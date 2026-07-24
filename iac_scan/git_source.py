"""Shallow-clone GitHub repositories for offline IaC static analysis."""
import json
import logging
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)


def list_org_repos(org: str, token: str) -> list[str]:
    """List non-archived repo full_names for a GitHub org via the REST API.

    Uses the stdlib urllib so the scanner suite stays dependency-free (it ships
    with `dependencies = []` and runs inside the webapp's dependency-light image).
    """
    repos: list[str] = []
    page = 1
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "dnm-hunter-iac-scan",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    while True:
        query = urllib.parse.urlencode({"per_page": 100, "page": page, "type": "sources"})
        req = urllib.request.Request(
            f"https://api.github.com/orgs/{org}/repos?{query}",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                batch = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            logger.warning(f"Failed to list repos for org {org}: HTTP {e.code}")
            break
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            logger.warning(f"Failed to list repos for org {org}: {e}")
            break
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
