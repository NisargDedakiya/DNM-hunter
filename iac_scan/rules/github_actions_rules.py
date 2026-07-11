"""
GitHub Actions workflow static misconfiguration rules.

Focuses on the classic Actions supply-chain and script-injection issue classes:
pull_request_target + checkout of PR head, unpinned third-party actions,
overly broad permissions, and untrusted-input script injection.
"""
import re

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

_UNTRUSTED_EXPR = re.compile(
    r"\$\{\{\s*(github\.event\.(issue\.title|issue\.body|pull_request\.title|"
    r"pull_request\.body|pull_request\.head\.ref|comment\.body|review\.body|head_commit\.message)"
    r"|github\.head_ref)\s*\}\}"
)
_SHA_PIN = re.compile(r"@[0-9a-f]{40}$")


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


def check_workflow(doc: dict, file_path: str) -> list[dict]:
    if not isinstance(doc, dict):
        return []
    findings = []

    triggers = doc.get(True, doc.get("on"))  # PyYAML parses bare `on:` key as boolean True
    trigger_names = set()
    if isinstance(triggers, str):
        trigger_names = {triggers}
    elif isinstance(triggers, list):
        trigger_names = set(triggers)
    elif isinstance(triggers, dict):
        trigger_names = set(triggers.keys())

    is_pr_target = "pull_request_target" in trigger_names
    top_permissions = doc.get("permissions")

    if isinstance(top_permissions, str) and top_permissions == "write-all":
        findings.append(_finding("GHA-001", SEVERITY_HIGH, "write-all permissions granted",
                                  "Workflow grants `permissions: write-all` to the GITHUB_TOKEN — broader than almost any job needs.",
                                  file_path, "(workflow)"))

    jobs = doc.get("jobs") or {}
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        job_perms = job.get("permissions")
        runs_on = job.get("runs-on", "")
        self_hosted = isinstance(runs_on, str) and "self-hosted" in runs_on

        if is_pr_target and self_hosted:
            findings.append(_finding("GHA-002", SEVERITY_CRITICAL, "pull_request_target on a self-hosted runner",
                                      f"Job {job_name!r} runs on a self-hosted runner while triggered by pull_request_target — a fork PR can execute arbitrary code with repo secrets on infrastructure you control.",
                                      file_path, job_name))

        steps = job.get("steps") or []
        checked_out_pr_head = False
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses", "")
            run = step.get("run", "")

            if uses.startswith("actions/checkout") and is_pr_target:
                with_block = step.get("with") or {}
                ref = str(with_block.get("ref", ""))
                if "head" in ref or "pull_request.head" in ref or "github.event.pull_request.head.sha" in ref:
                    checked_out_pr_head = True

            if uses and "@" in uses and not uses.startswith("./") and not uses.startswith("docker://"):
                if not _SHA_PIN.search(uses):
                    findings.append(_finding("GHA-003", SEVERITY_MEDIUM, "Third-party action not pinned to a commit SHA",
                                              f"Step in job {job_name!r} uses {uses!r}, pinned to a mutable tag/branch instead of a full commit SHA — a compromised upstream action can silently change behavior (supply-chain risk).",
                                              file_path, uses))

            if run and _UNTRUSTED_EXPR.search(run):
                match = _UNTRUSTED_EXPR.search(run)
                findings.append(_finding("GHA-004", SEVERITY_CRITICAL, "Script injection via untrusted workflow expression",
                                          f"Job {job_name!r} interpolates {match.group(0)} directly into a `run:` shell step — attacker-controlled text (PR title/body/branch name) is executed as shell code.",
                                          file_path, job_name))

        if is_pr_target and checked_out_pr_head:
            has_secret_use = any(
                isinstance(s, dict) and ("secrets." in str(s.get("with", "")) or "secrets." in str(s.get("env", "")) or "secrets." in str(s.get("run", "")))
                for s in steps
            )
            findings.append(_finding(
                "GHA-005", SEVERITY_CRITICAL if has_secret_use else SEVERITY_HIGH,
                "pull_request_target checks out untrusted PR head",
                f"Job {job_name!r} is triggered by pull_request_target (which runs with base-repo secrets/token) and checks out the fork's PR head — subsequent build/test steps execute attacker-controlled code with elevated privileges.",
                file_path, job_name,
            ))

        if isinstance(job_perms, dict) and job_perms.get("contents") == "write" and is_pr_target:
            findings.append(_finding("GHA-006", SEVERITY_MEDIUM, "Write permissions on a pull_request_target job",
                                      f"Job {job_name!r} runs on pull_request_target with contents: write; combined with untrusted checkout this can be used to push malicious commits/tags.",
                                      file_path, job_name))

    return findings
