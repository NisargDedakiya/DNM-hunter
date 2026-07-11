"""
Terraform static misconfiguration rules.

Operates on the dict produced by python-hcl2 for a single .tf file.
hcl2 represents each top-level block type (resource, provider, ...) as a list
of single-key dicts; a `resource` entry looks like:
    {"resource": [{"<type>": {"<name>": { ...body... }}}]}
"""
import re

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

_SECRET_ATTR = re.compile(r"(password|secret|api_key|access_key|private_key|token)$", re.IGNORECASE)
_LITERAL = re.compile(r"^[A-Za-z0-9+/_\-=]{8,}$")
_OPEN_CIDR = {"0.0.0.0/0", "::/0"}
_SENSITIVE_PORTS = {22, 3389, 5432, 3306, 6379, 27017, 9200, 2375}


def _finding(rule_id, severity, title, message, file_path, resource):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "message": message,
        "file_path": file_path,
        "line": None,
        "resource": resource,
    }


def _strip_quotes(s):
    """python-hcl2 sometimes leaves literal quote characters around string
    labels/values (e.g. '"aws_s3_bucket"' instead of 'aws_s3_bucket'). Normalize."""
    if isinstance(s, str) and len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


def _iter_resources(doc: dict):
    for block in doc.get("resource", []) or []:
        for rtype, named in block.items():
            for rname, body in named.items():
                if isinstance(body, list):
                    body = body[0] if body else {}
                yield _strip_quotes(rtype), _strip_quotes(rname), body or {}


def _val(v):
    """hcl2 wraps single scalars in lists sometimes and may leave literal
    quote characters around string values; unwrap and normalize conservatively."""
    if isinstance(v, list) and len(v) == 1:
        v = v[0]
    return _strip_quotes(v)


def check_terraform_doc(doc: dict, file_path: str) -> list[dict]:
    findings = []
    if not isinstance(doc, dict):
        return findings

    for rtype, rname, body in _iter_resources(doc):
        resource = f"{rtype}.{rname}"

        if rtype in ("aws_s3_bucket_acl", "aws_s3_bucket"):
            acl = _val(body.get("acl"))
            if acl in ("public-read", "public-read-write"):
                findings.append(_finding("TF-001", SEVERITY_CRITICAL, "Publicly readable/writable S3 bucket ACL",
                                          f"{resource} sets acl = {acl!r}, exposing bucket contents to anyone.",
                                          file_path, resource))

        if rtype == "aws_s3_bucket_public_access_block":
            for attr in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
                if _val(body.get(attr)) is False:
                    findings.append(_finding("TF-002", SEVERITY_HIGH, "S3 public access block disabled",
                                              f"{resource} sets {attr} = false, weakening the account-level guard against accidental public exposure.",
                                              file_path, resource))

        if rtype in ("aws_s3_bucket_server_side_encryption_configuration",):
            pass  # presence alone is fine; absence is checked via aws_s3_bucket below

        if rtype == "aws_s3_bucket" and "server_side_encryption_configuration" not in body:
            findings.append(_finding("TF-003", SEVERITY_MEDIUM, "S3 bucket without server-side encryption configured inline",
                                      f"{resource} has no server_side_encryption_configuration block; data at rest may be unencrypted.",
                                      file_path, resource))

        if rtype == "aws_security_group" or rtype == "aws_security_group_rule":
            ingress_blocks = body.get("ingress")
            rules = []
            if rtype == "aws_security_group_rule" and _val(body.get("type")) == "ingress":
                rules = [body]
            elif isinstance(ingress_blocks, list):
                rules = ingress_blocks

            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                cidrs = rule.get("cidr_blocks") or []
                if isinstance(cidrs, dict):
                    cidrs = [cidrs]
                flat_cidrs = []
                for c in cidrs:
                    if isinstance(c, list):
                        flat_cidrs.extend(c)
                    else:
                        flat_cidrs.append(c)
                flat_cidrs = [_strip_quotes(c) for c in flat_cidrs]
                if any(c in _OPEN_CIDR for c in flat_cidrs):
                    from_port = _val(rule.get("from_port"))
                    to_port = _val(rule.get("to_port"))
                    port_desc = f"{from_port}-{to_port}"
                    is_sensitive = False
                    try:
                        is_sensitive = any(int(from_port) <= p <= int(to_port) for p in _SENSITIVE_PORTS)
                    except (TypeError, ValueError):
                        pass
                    findings.append(_finding(
                        "TF-004", SEVERITY_CRITICAL if is_sensitive else SEVERITY_HIGH,
                        "Security group open to the internet",
                        f"{resource} allows ingress from 0.0.0.0/0 on port(s) {port_desc}" + (" — includes a sensitive administrative/database port." if is_sensitive else "."),
                        file_path, resource,
                    ))

        if rtype in ("aws_db_instance", "aws_rds_cluster"):
            if _val(body.get("publicly_accessible")) is True:
                findings.append(_finding("TF-005", SEVERITY_CRITICAL, "Database instance publicly accessible",
                                          f"{resource} sets publicly_accessible = true.",
                                          file_path, resource))
            if _val(body.get("storage_encrypted")) is not True:
                findings.append(_finding("TF-006", SEVERITY_MEDIUM, "Database storage not encrypted",
                                          f"{resource} does not set storage_encrypted = true.",
                                          file_path, resource))

        if rtype in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"):
            policy_raw = body.get("policy")
            policy_str = str(_val(policy_raw)) if policy_raw else ""
            has_wild_action = bool(re.search(r'"?Action"?\s*[:=]\s*"\*"', policy_str))
            has_wild_resource = bool(re.search(r'"?Resource"?\s*[:=]\s*"\*"', policy_str))
            if has_wild_action and has_wild_resource:
                findings.append(_finding("TF-007", SEVERITY_CRITICAL, "IAM policy grants Action:* on Resource:*",
                                          f"{resource} defines a policy with unrestricted Action and Resource (full-admin equivalent).",
                                          file_path, resource))

        for attr_name, attr_val in body.items():
            if _SECRET_ATTR.search(attr_name):
                v = _val(attr_val)
                if isinstance(v, str) and _LITERAL.match(v) and not v.startswith("${"):
                    findings.append(_finding("TF-008", SEVERITY_CRITICAL, f"Hardcoded credential in {attr_name}",
                                              f"{resource} sets {attr_name} to a literal string instead of a variable/secret reference.",
                                              file_path, resource))

    return findings
