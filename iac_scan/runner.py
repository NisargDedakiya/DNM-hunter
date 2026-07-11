"""
IaC/DevOps configuration scanner.

Walks a target directory (a cloned repo checkout) and runs offline static
analysis against Dockerfiles, docker-compose files, Kubernetes manifests,
GitHub Actions workflows, and Terraform — no network calls, no credentials
required. This mirrors the class of checks tools like hadolint/kube-linter/
checkov/tfsec perform, hand-rolled and scoped to the highest-signal rules.
"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import yaml

try:
    import hcl2
except ImportError:
    hcl2 = None

from iac_scan.rules.dockerfile_rules import check_dockerfile
from iac_scan.rules.compose_rules import check_compose_doc
from iac_scan.rules.kubernetes_rules import check_kubernetes_doc
from iac_scan.rules.github_actions_rules import check_workflow
from iac_scan.rules.terraform_rules import check_terraform_doc

logger = logging.getLogger(__name__)

_IGNORE_DIRS = {".git", "node_modules", "vendor", ".terraform", "__pycache__", "dist", "build"}

_K8S_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}


class IacScanRunner:
    def __init__(self, target_dir: str, project_id: str, output_dir: str | None = None):
        self.target_dir = Path(target_dir)
        self.project_id = project_id
        self.output_dir = Path(output_dir) if output_dir else Path(__file__).parent / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.output_file: Path | None = None
        self.stats = {
            "files_scanned": 0,
            "total_findings": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_category": {"dockerfile": 0, "compose": 0, "kubernetes": 0, "github_actions": 0, "terraform": 0},
            "errors": [],
        }

    def _iter_files(self):
        if not self.target_dir.exists():
            return
        for path in self.target_dir.rglob("*"):
            if not path.is_file():
                continue
            if any(part in _IGNORE_DIRS for part in path.parts):
                continue
            yield path

    def _rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.target_dir))
        except ValueError:
            return str(path)

    def _record(self, findings: list[dict], category: str):
        self.stats["files_scanned"] += 1
        for f in findings:
            self.stats["total_findings"] += 1
            self.stats["by_severity"][f["severity"]] = self.stats["by_severity"].get(f["severity"], 0) + 1
            self.stats["by_category"][category] = self.stats["by_category"].get(category, 0) + 1
            f["category"] = category

    def run(self) -> list[dict]:
        all_findings: list[dict] = []

        for path in self._iter_files():
            name = path.name
            rel = self._rel(path)
            try:
                if name == "Dockerfile" or name.startswith("Dockerfile."):
                    text = path.read_text(errors="replace")
                    findings = check_dockerfile(text, rel)
                    self._record(findings, "dockerfile")
                    all_findings.extend(findings)

                elif name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
                    doc = yaml.safe_load(path.read_text(errors="replace"))
                    findings = check_compose_doc(doc, rel)
                    self._record(findings, "compose")
                    all_findings.extend(findings)

                elif name.endswith((".yml", ".yaml")) and self._looks_like_k8s_or_workflow(path):
                    self._scan_yaml_multi(path, rel, all_findings)

                elif name.endswith(".tf") and hcl2 is not None:
                    with path.open() as fh:
                        doc = hcl2.load(fh)
                    findings = check_terraform_doc(doc, rel)
                    self._record(findings, "terraform")
                    all_findings.extend(findings)

            except Exception as e:
                logger.warning(f"Failed to scan {rel}: {e}")
                self.stats["errors"].append(f"{rel}: {e}")

        result = {
            "scan_metadata": {
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "target_dir": str(self.target_dir),
                "project_id": self.project_id,
            },
            "findings": all_findings,
            "statistics": self.stats,
        }
        self.output_file = self.output_dir / f"iac_scan_{self.project_id}.json"
        self.output_file.write_text(json.dumps(result, indent=2))
        return all_findings

    def _looks_like_k8s_or_workflow(self, path: Path) -> bool:
        return ".github/workflows" in str(path).replace("\\", "/") or True  # cheap gate; real dispatch happens per-doc below

    def _scan_yaml_multi(self, path: Path, rel: str, all_findings: list[dict]):
        is_workflow = ".github/workflows/" in str(path).replace("\\", "/")
        try:
            docs = list(yaml.safe_load_all(path.read_text(errors="replace")))
        except yaml.YAMLError as e:
            self.stats["errors"].append(f"{rel}: YAML parse error: {e}")
            return

        for idx, doc in enumerate(docs):
            if not isinstance(doc, dict):
                continue
            if is_workflow or "jobs" in doc:
                findings = check_workflow(doc, rel)
                self._record(findings, "github_actions")
                all_findings.extend(findings)
            elif doc.get("kind") in _K8S_KINDS:
                findings = check_kubernetes_doc(doc, rel, idx)
                self._record(findings, "kubernetes")
                all_findings.extend(findings)
