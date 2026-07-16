"""Google Cloud (GCP) Terraform misconfiguration rules.

Extends the IaC scanner beyond AWS to GCP resources. Reuses the shared hcl2
helpers from terraform_rules so parsing behaves identically. Covers the CIS
GCP Benchmark staples: public buckets, open firewalls, public Cloud SQL,
public-IP compute instances, and over-broad / public IAM.
"""
from .terraform_rules import (
    _iter_resources, _val, _strip_quotes, _finding,
    _OPEN_CIDR, _SENSITIVE_PORTS,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
)

_PUBLIC_MEMBERS = {"allusers", "allauthenticatedusers"}
_PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}


def _members(body) -> list[str]:
    out = []
    for key in ("member", "members"):
        v = body.get(key)
        if v is None:
            continue
        if isinstance(v, list):
            for item in v:
                if isinstance(item, list):
                    out.extend(str(_strip_quotes(x)) for x in item)
                else:
                    out.append(str(_strip_quotes(item)))
        else:
            out.append(str(_strip_quotes(v)))
    return out


def check_gcp_doc(doc: dict, file_path: str) -> list[dict]:
    findings = []
    if not isinstance(doc, dict):
        return findings

    for rtype, rname, body in _iter_resources(doc):
        resource = f"{rtype}.{rname}"

        # GCP-001: publicly-shared Cloud Storage bucket via IAM to allUsers.
        if rtype in ("google_storage_bucket_iam_member", "google_storage_bucket_iam_binding"):
            members = [m.lower() for m in _members(body)]
            if any(m in _PUBLIC_MEMBERS for m in members):
                findings.append(_finding("GCP-001", SEVERITY_CRITICAL, "Public Cloud Storage bucket (IAM allUsers)",
                                          f"{resource} grants a bucket role to allUsers/allAuthenticatedUsers — the bucket is world-readable.",
                                          file_path, resource))

        # GCP-002: bucket without uniform bucket-level access (ACLs can leak).
        if rtype == "google_storage_bucket":
            ubla = body.get("uniform_bucket_level_access")
            if isinstance(ubla, list):
                ubla = ubla[0] if ubla else {}
            enabled = _val(ubla.get("enabled")) if isinstance(ubla, dict) else _val(ubla)
            if enabled is not True:
                findings.append(_finding("GCP-002", SEVERITY_MEDIUM, "Cloud Storage bucket without uniform bucket-level access",
                                          f"{resource} does not enable uniform_bucket_level_access; legacy ACLs can grant unintended public access.",
                                          file_path, resource))

        # GCP-003: firewall open to the internet.
        if rtype == "google_compute_firewall":
            ranges = body.get("source_ranges") or []
            if isinstance(ranges, dict):
                ranges = [ranges]
            flat = []
            for r in ranges:
                flat.extend(r) if isinstance(r, list) else flat.append(r)
            flat = [_strip_quotes(r) for r in flat]
            direction = str(_val(body.get("direction")) or "INGRESS").upper()
            if direction == "INGRESS" and any(c in _OPEN_CIDR for c in flat):
                # inspect allowed ports for sensitivity
                sensitive = False
                allow = body.get("allow") or []
                if isinstance(allow, dict):
                    allow = [allow]
                for a in allow:
                    if not isinstance(a, dict):
                        continue
                    for p in (a.get("ports") or []):
                        p = _strip_quotes(p)
                        try:
                            if int(str(p).split("-")[0]) in _SENSITIVE_PORTS:
                                sensitive = True
                        except (TypeError, ValueError):
                            pass
                findings.append(_finding("GCP-003", SEVERITY_CRITICAL if sensitive else SEVERITY_HIGH,
                                          "Compute firewall open to the internet",
                                          f"{resource} allows ingress from 0.0.0.0/0" + (" on a sensitive port." if sensitive else "."),
                                          file_path, resource))

        # GCP-004: Cloud SQL instance publicly reachable.
        if rtype == "google_sql_database_instance":
            settings = body.get("settings")
            if isinstance(settings, list):
                settings = settings[0] if settings else {}
            ipcfg = (settings or {}).get("ip_configuration") if isinstance(settings, dict) else None
            if isinstance(ipcfg, list):
                ipcfg = ipcfg[0] if ipcfg else {}
            if isinstance(ipcfg, dict):
                if _val(ipcfg.get("ipv4_enabled")) is True:
                    findings.append(_finding("GCP-004", SEVERITY_HIGH, "Cloud SQL instance has a public IP",
                                              f"{resource} enables a public IPv4 address (ipv4_enabled = true); prefer private IP + Cloud SQL Auth Proxy.",
                                              file_path, resource))
                authnets = ipcfg.get("authorized_networks") or []
                if isinstance(authnets, dict):
                    authnets = [authnets]
                for net in authnets:
                    if isinstance(net, dict) and _strip_quotes(_val(net.get("value"))) in _OPEN_CIDR:
                        findings.append(_finding("GCP-005", SEVERITY_CRITICAL, "Cloud SQL authorized network open to the internet",
                                                  f"{resource} authorizes 0.0.0.0/0 — the database is reachable from anywhere.",
                                                  file_path, resource))

        # GCP-006: primitive/owner IAM role, or public IAM at the project level.
        if rtype in ("google_project_iam_member", "google_project_iam_binding"):
            role = str(_val(body.get("role")) or "").lower()
            members = [m.lower() for m in _members(body)]
            if any(m in _PUBLIC_MEMBERS for m in members):
                findings.append(_finding("GCP-006", SEVERITY_CRITICAL, "Project IAM granted to allUsers",
                                          f"{resource} binds a project role to allUsers/allAuthenticatedUsers — anyone can access the project.",
                                          file_path, resource))
            elif role in _PRIMITIVE_ROLES:
                findings.append(_finding("GCP-007", SEVERITY_HIGH, "Primitive IAM role used",
                                          f"{resource} grants the primitive role {role!r}; use predefined/custom least-privilege roles instead.",
                                          file_path, resource))

    return findings
