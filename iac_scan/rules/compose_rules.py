"""docker-compose.yml static misconfiguration rules."""
import re

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"

# Letter-boundary (not \b) so underscore-joined names — the near-universal env
# var convention: DB_PASSWORD, MYSQL_ROOT_PASSWORD, SECRET_KEY, ACCESS_TOKEN —
# still match. \b treats '_' as a word char, so \bPASSWORD\b misses FOO_PASSWORD.
# The lookarounds count only letters as "inside a word", so '_', digits, and
# string edges act as separators while PASSWORDLESS / TOKENIZED do not match.
_SECRET_KEY = re.compile(r"(?<![A-Za-z])(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY)(?![A-Za-z])", re.IGNORECASE)
_LITERAL = re.compile(r"^[A-Za-z0-9+/_\-=]{8,}$")


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


def _env_pairs(env) -> dict:
    if isinstance(env, dict):
        return {k: str(v) for k, v in env.items()}
    if isinstance(env, list):
        out = {}
        for item in env:
            if isinstance(item, str) and "=" in item:
                k, _, v = item.partition("=")
                out[k] = v
        return out
    return {}


def check_compose_doc(doc: dict, file_path: str) -> list[dict]:
    findings = []
    if not isinstance(doc, dict):
        return findings

    services = doc.get("services") or {}
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        resource = f"service/{svc_name}"

        if svc.get("privileged") is True:
            findings.append(_finding("COMPOSE-001", SEVERITY_CRITICAL, "Privileged container",
                                      f"{resource} runs with privileged: true — full host device access.",
                                      file_path, resource))

        if svc.get("network_mode") == "host":
            findings.append(_finding("COMPOSE-002", SEVERITY_HIGH, "Host network mode",
                                      f"{resource} uses network_mode: host, bypassing container network isolation.",
                                      file_path, resource))

        for vol in svc.get("volumes") or []:
            vol_str = vol if isinstance(vol, str) else (vol.get("source", "") if isinstance(vol, dict) else "")
            if "docker.sock" in str(vol_str):
                findings.append(_finding("COMPOSE-003", SEVERITY_CRITICAL, "Docker socket mounted into container",
                                          f"{resource} mounts the Docker socket ({vol_str}) — equivalent to root on the host via the Docker API.",
                                          file_path, resource))

        env_pairs = _env_pairs(svc.get("environment"))
        for key, val in env_pairs.items():
            if _SECRET_KEY.search(key) and val and _LITERAL.match(val.strip('"\'')) and not val.startswith("${"):
                findings.append(_finding("COMPOSE-004", SEVERITY_HIGH, "Hardcoded secret in environment",
                                          f"{resource} sets {key} to a literal value in the compose file instead of an env-file/secret reference.",
                                          file_path, resource))

        ports = svc.get("ports") or []
        for p in ports:
            p_str = str(p)
            host_part = p_str.split(":")[0] if ":" in p_str else p_str
            if host_part.strip() in ("22", "2375", "3389") or (isinstance(p, dict) and str(p.get("published")) in ("22", "2375", "3389")):
                findings.append(_finding("COMPOSE-005", SEVERITY_MEDIUM, "Sensitive port published to host",
                                          f"{resource} publishes a sensitive port ({p_str}).",
                                          file_path, resource))

    return findings
