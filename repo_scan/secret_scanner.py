"""Value-pattern secret scanning over a source tree.

Reuses the platform's existing 100+ compiled secret regexes
(recon/helpers/js_recon/patterns.py :: JS_SECRET_PATTERNS) and applies them to
every text file in a repository, not just JavaScript — so a leaked AWS key,
GitHub token, Stripe key, or private key is caught wherever it lives (.env,
config.yaml, source, docs). Matches are redacted before they leave this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


def _load_secret_patterns() -> list:
    """Load the canonical JS secret pattern set.

    ``patterns.py`` is itself stdlib-only, but importing it through the package
    path (``recon.helpers.js_recon.patterns``) first executes
    ``recon/helpers/__init__.py``, which eagerly pulls in the Docker / nuclei /
    CVE helpers and their third-party dependencies. In a minimal install (e.g.
    CI, or the standalone scanner container) those deps are absent, so the
    package import raises and secret scanning silently degrades to zero patterns.

    Load the module file directly instead — bypassing the heavy package
    ``__init__`` — to honour the scanner's zero-dependency contract. Fall back to
    the normal package import, then to an empty set.
    """
    patterns_file = (
        Path(__file__).resolve().parents[1] / "recon" / "helpers" / "js_recon" / "patterns.py"
    )
    if patterns_file.is_file():
        try:
            import importlib.util

            spec = importlib.util.spec_from_file_location("_nh_js_secret_patterns", patterns_file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore[union-attr]
            return list(getattr(module, "JS_SECRET_PATTERNS", []))
        except Exception:  # pragma: no cover - fall through to the package import
            pass
    try:
        from recon.helpers.js_recon.patterns import JS_SECRET_PATTERNS as _pkg_patterns

        return list(_pkg_patterns)
    except Exception:  # pragma: no cover - keeps the scanner usable in isolation
        return []


# Reuse the canonical pattern set (loaded without triggering recon's heavy __init__).
JS_SECRET_PATTERNS = _load_secret_patterns()

# Directories that are noise or not the target's own code.
_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".next",
              "__pycache__", ".venv", "venv", "site-packages", ".terraform"}
# Binary / non-source extensions we never scan for secrets.
_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".zip",
             ".gz", ".tar", ".jar", ".war", ".class", ".woff", ".woff2", ".ttf",
             ".eot", ".mp4", ".mp3", ".mov", ".pyc", ".so", ".dll", ".exe",
             ".lock", ".min.js", ".map"}
_MAX_FILE_BYTES = 2_000_000   # skip files larger than 2 MB
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# Obvious placeholders that shouldn't be reported as live secrets.
_PLACEHOLDER = re.compile(r"(?i)(example|placeholder|your[_-]?key|xxxx+|<[^>]+>|changeme|dummy|sample|redacted)")


@dataclass
class SecretFinding:
    kind: str            # "secret"
    name: str            # e.g. "AWS Access Key ID"
    severity: str
    confidence: str
    category: str
    file: str            # repo-relative path
    line: int
    redacted: str        # masked match, safe to display/store


def redact(value: str) -> str:
    """Mask a secret so it's safe to store/display: first 4 + last 2 chars,
    middle replaced with a fixed-width mask."""
    v = value.strip().strip("'\"")
    if len(v) <= 8:
        return v[0] + "***" if v else "***"
    return f"{v[:4]}…{v[-2:]} ({len(v)} chars)"


def _iter_text_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in _SKIP_EXT or path.name.endswith(".min.js"):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def scan_secrets(root: str | Path) -> list[SecretFinding]:
    """Scan every text file under `root` for known secret patterns. Never
    raises on an unreadable file — it's skipped."""
    root = Path(root)
    # Collapse overlapping patterns that match the SAME secret value at the same
    # location (e.g. several providers share the sk_live_ prefix) to one finding,
    # keeping the highest severity — one leaked secret is one finding, not N.
    best: dict[tuple, SecretFinding] = {}

    for path in _iter_text_files(root):
        try:
            text = path.read_text(errors="replace")
        except Exception:
            continue
        rel = str(path.relative_to(root))
        for pat in JS_SECRET_PATTERNS:
            for m in pat["regex"].finditer(text):
                matched = m.group(0)
                if _PLACEHOLDER.search(matched):
                    continue
                line = text.count("\n", 0, m.start()) + 1
                loc = (rel, line, matched)
                finding = SecretFinding(
                    kind="secret", name=pat["name"], severity=pat["severity"],
                    confidence=pat["confidence"], category=pat["category"],
                    file=rel, line=line, redacted=redact(matched),
                )
                existing = best.get(loc)
                if existing is None or _SEV_RANK.get(finding.severity, 9) < _SEV_RANK.get(existing.severity, 9):
                    best[loc] = finding
    return list(best.values())
