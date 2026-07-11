"""
Dockerfile static misconfiguration rules.

Each rule receives the parsed instruction list (list of (lineno, instruction, args_str))
for a single Dockerfile and yields Finding dicts.
"""
import re

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

_SECRET_ENV_NAME = re.compile(
    r"\b(PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|AWS_SECRET)\b",
    re.IGNORECASE,
)
_SECRET_VALUE_LOOKS_LITERAL = re.compile(r"^[\"']?[A-Za-z0-9+/_\-=]{8,}[\"']?$")


def parse_dockerfile(text: str) -> list[tuple[int, str, str]]:
    """Parse a Dockerfile into (lineno, INSTRUCTION, args) tuples, joining line continuations."""
    instructions = []
    pending = ""
    pending_start = None
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if pending:
            pending += " " + stripped.rstrip("\\").strip()
        else:
            pending_start = lineno
            pending = stripped.rstrip("\\").strip()
        if raw_line.rstrip().endswith("\\"):
            continue
        parts = pending.split(None, 1)
        instruction = parts[0].upper() if parts else ""
        args = parts[1] if len(parts) > 1 else ""
        if instruction:
            instructions.append((pending_start, instruction, args))
        pending = ""
        pending_start = None
    return instructions


def check_dockerfile(text: str, file_path: str) -> list[dict]:
    findings = []
    instructions = parse_dockerfile(text)

    has_user = False
    last_from_line = 1
    has_healthcheck = False

    for lineno, instruction, args in instructions:
        if instruction == "FROM":
            last_from_line = lineno
            image = args.split()[0] if args else ""
            if ":latest" in image or (":" not in image and "@" not in image and image not in ("scratch",)):
                findings.append({
                    "rule_id": "DOCKER-001",
                    "severity": SEVERITY_MEDIUM,
                    "title": "Base image not pinned to a specific version",
                    "message": f"FROM uses an unpinned/`latest` tag ({image!r}); builds are non-reproducible and can silently pull a compromised image.",
                    "file_path": file_path,
                    "line": lineno,
                    "resource": image,
                })

        elif instruction == "USER":
            if args.strip() not in ("root", "0"):
                has_user = True

        elif instruction == "HEALTHCHECK":
            has_healthcheck = True

        elif instruction == "ADD":
            first_arg = args.split()[0] if args else ""
            if first_arg.startswith("http://") or first_arg.startswith("https://"):
                findings.append({
                    "rule_id": "DOCKER-002",
                    "severity": SEVERITY_MEDIUM,
                    "title": "ADD used to fetch a remote URL",
                    "message": "ADD <url> fetches and extracts remote content with no integrity check; prefer COPY + explicit checksum verification.",
                    "file_path": file_path,
                    "line": lineno,
                    "resource": first_arg,
                })

        elif instruction == "ENV" or instruction == "ARG":
            for token in re.split(r"\s+(?=[A-Za-z_][A-Za-z0-9_]*=)", args):
                if "=" not in token:
                    continue
                name, _, value = token.partition("=")
                name = name.strip()
                value = value.strip()
                if _SECRET_ENV_NAME.search(name) and value and _SECRET_VALUE_LOOKS_LITERAL.match(value):
                    findings.append({
                        "rule_id": "DOCKER-003",
                        "severity": SEVERITY_CRITICAL,
                        "title": f"Hardcoded secret in {instruction}",
                        "message": f"{instruction} {name}=... looks like a literal credential baked into the image layer history.",
                        "file_path": file_path,
                        "line": lineno,
                        "resource": name,
                    })

        elif instruction == "RUN":
            if re.search(r"\bcurl\b.*\|\s*(sh|bash)\b", args) or re.search(r"\bwget\b.*\|\s*(sh|bash)\b", args):
                findings.append({
                    "rule_id": "DOCKER-004",
                    "severity": SEVERITY_HIGH,
                    "title": "Piping a remote download directly into a shell",
                    "message": "curl|bash (or wget|sh) executes unverified remote code during the build with no integrity check.",
                    "file_path": file_path,
                    "line": lineno,
                    "resource": args[:120],
                })
            if re.search(r"\bchmod\s+(-R\s+)?777\b", args):
                findings.append({
                    "rule_id": "DOCKER-005",
                    "severity": SEVERITY_MEDIUM,
                    "title": "World-writable permissions granted",
                    "message": "chmod 777 grants world write access to files in the image.",
                    "file_path": file_path,
                    "line": lineno,
                    "resource": args[:120],
                })

        elif instruction == "EXPOSE":
            for port_tok in args.split():
                port = port_tok.split("/")[0]
                if port.isdigit() and port in ("22", "23", "2375", "3389"):
                    findings.append({
                        "rule_id": "DOCKER-006",
                        "severity": SEVERITY_HIGH,
                        "title": f"Sensitive port {port} exposed",
                        "message": f"EXPOSE {port} publishes a management/administrative port (SSH/Telnet/unauthenticated Docker daemon/RDP) from the container.",
                        "file_path": file_path,
                        "line": lineno,
                        "resource": port,
                    })

    if not has_user:
        findings.append({
            "rule_id": "DOCKER-007",
            "severity": SEVERITY_HIGH,
            "title": "Container runs as root",
            "message": "No non-root USER instruction found; the container's default process runs as root, widening the blast radius of a container-escape or RCE.",
            "file_path": file_path,
            "line": last_from_line,
            "resource": None,
        })

    return findings
