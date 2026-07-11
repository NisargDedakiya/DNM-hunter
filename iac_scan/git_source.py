"""Shallow-clone GitHub repositories for offline IaC static analysis."""
import logging
import subprocess
import tempfile
from pathlib import Path

import requests

logger = logging.getLogger(__name__)


def list_org_repos(org: str, token: str) -> list[str]:
    """List non-archived repo full_names for a GitHub org via the REST API."""
    repos: list[str] = []
    page = 1
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    while True:
        resp = requests.get(
            f"https://api.github.com/orgs/{org}/repos",
            params={"per_page": 100, "page": page, "type": "sources"},
            headers=headers,
            timeout=30,
        )
        if resp.status_code != 200:
            logger.warning(f"Failed to list repos for org {org}: HTTP {resp.status_code}")
            break
        batch = resp.json()
        if not batch:
            break
        repos.extend(r["full_name"] for r in batch if not r.get("archived"))
        if len(batch) < 100:
            break
        page += 1
    return repos


def clone_repo(repo: str, token: str, dest_root: Path) -> Path | None:
    """Shallow-clone a single repo (owner/name or full URL) into dest_root. Returns the checkout path or None on failure."""
    if repo.startswith("http"):
        url = repo
        slug = repo.rstrip("/").split("/")[-1].replace(".git", "")
    else:
        url = f"https://github.com/{repo}.git"
        slug = repo.split("/")[-1]

    if token:
        auth_url = url.replace("https://", f"https://x-access-token:{token}@")
    else:
        auth_url = url

    dest = dest_root / slug
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", auth_url, str(dest)],
            check=True,
            capture_output=True,
            timeout=180,
        )
        return dest
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode(errors="replace") if e.stderr else ""
        logger.warning(f"Failed to clone {repo}: {stderr[:300]}")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"Clone of {repo} timed out")
        return None


class ClonedRepos:
    """Context manager yielding (repo_name, checkout_path) pairs for cleanup-on-exit."""

    def __init__(self, repos: list[str], token: str):
        self.repos = repos
        self.token = token
        self._tmp: tempfile.TemporaryDirectory | None = None

    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="iac_scan_")
        root = Path(self._tmp.name)
        results = []
        for repo in self.repos:
            path = clone_repo(repo, self.token, root)
            if path is not None:
                name = repo.rstrip("/").split("/")[-1].replace(".git", "")
                results.append((name, path))
        return results

    def __exit__(self, exc_type, exc, tb):
        if self._tmp is not None:
            self._tmp.cleanup()
