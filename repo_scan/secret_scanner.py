"""Value-pattern secret scanning over a source tree.

Reuses the platform's existing 100+ compiled secret regexes
(recon/helpers/js_recon/patterns.py :: JS_SECRET_PATTERNS) and applies them to
every text file in a repository, not just JavaScript — so a leaked AWS key,
GitHub token, Stripe key, or private key is caught wherever it lives (.env,
config.yaml, source, docs). Matches are redacted before they leave this module.

False-positive controls (so the count reflects real secrets, not noise):
  * dependency lockfiles and generated/build output are skipped by default;
  * matching is line-scoped, so a pattern can't span lines and grab a log
    message (e.g. `console.error('… password:', err)`);
  * the recon path's own filters are reused — placeholder text, whitelisted
    doc/CDN hosts, false-positive email domains, low Shannon entropy, base64
    blobs, font/binary context, repetitive filler;
  * findings in documentation / example / demo / test files are downgraded to
    informational, since a "secret" there is almost always illustrative.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


def _load_patterns_module():
    """Load recon/helpers/js_recon/patterns.py directly (bypassing recon's heavy
    package __init__, which pulls optional third-party deps) so the scanner keeps
    its zero-dependency contract. Returns the module, or None."""
    patterns_file = (
        Path(__file__).resolve().parents[1] / "recon" / "helpers" / "js_recon" / "patterns.py"
    )
    if patterns_file.is_file():
        try:
            import importlib.util

            spec = importlib.util.spec_from_file_location("_nh_js_secret_patterns", patterns_file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore[union-attr]
            return module
        except Exception:  # pragma: no cover - fall through to the package import
            pass
    try:
        from recon.helpers.js_recon import patterns as module

        return module
    except Exception:  # pragma: no cover - keeps the scanner usable in isolation
        return None


_PAT_MOD = _load_patterns_module()
JS_SECRET_PATTERNS = list(getattr(_PAT_MOD, "JS_SECRET_PATTERNS", [])) if _PAT_MOD else []


def _helper(name, default):
    fn = getattr(_PAT_MOD, name, None) if _PAT_MOD else None
    return fn if callable(fn) else default


# Reuse the exact false-positive filters the recon scan path already applies, so
# a repo scan suppresses the same noise instead of re-flagging it.
_is_fp_email = _helper("_is_false_positive_email", lambda e: False)
_is_wl_staging = _helper("_is_whitelisted_staging_url", lambda u: False)
_shannon_entropy = _helper("_shannon_entropy", lambda t: 4.0)
_is_inside_base64_blob = _helper("_is_inside_base64_blob", lambda ln, s, e: False)
_has_binary_context = _helper("_has_binary_context", lambda c: False)
_has_repetitive_pattern = _helper("_has_repetitive_pattern", lambda t: False)
# Categories that carry real secrets (so the entropy/binary filters apply); the
# infrastructure/info categories (URLs, emails) are handled by their own filters.
_FP_FILTER_CATEGORIES = {"auth", "cloud", "payment", "secret", "js_service", "ai_llm"}
_SKIP_ENTROPY_KEYWORDS = ("Private Key", "URL", "URI", "DSN", "Header")

# Directories that are noise or not the target's own code.
_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".next", "out",
              "__pycache__", ".venv", "venv", "site-packages", ".terraform",
              "coverage", ".cache", ".nuxt", ".svelte-kit", "__snapshots__"}
# Dependency lockfiles / generated manifests — machine-written, full of hashes
# that look like secrets. Enterprise scanners skip these by default (the reviewer's
# Priority 2); a hash in package-lock.json is not a leaked key.
_SKIP_FILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
               "pnpm-lock.yaml", "composer.lock", "gemfile.lock", "poetry.lock",
               "cargo.lock", "go.sum", "pipfile.lock", "packages.lock.json",
               "flake.lock", "bun.lockb"}
# Binary / non-source extensions we never scan for secrets.
_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".zip",
             ".gz", ".tar", ".jar", ".war", ".class", ".woff", ".woff2", ".ttf",
             ".eot", ".mp4", ".mp3", ".mov", ".pyc", ".so", ".dll", ".exe",
             ".lock", ".min.js", ".map"}
_MAX_FILE_BYTES = 2_000_000   # skip files larger than 2 MB
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# Obvious placeholders that shouldn't be reported as live secrets.
_PLACEHOLDER = re.compile(r"(?i)(example|placeholder|your[_-]?key|xxxx+|<[^>]+>|changeme|dummy|sample|redacted)")

# Documentation extensions and example/test/demo path markers → downgrade to info.
_DOC_EXT = {".md", ".markdown", ".mdx", ".rst", ".txt", ".adoc"}
_LOW_VALUE_PATH = re.compile(
    # a whole path segment …
    r"(^|/)(examples?|samples?|demos?|mocks?|__mocks__|fixtures?|__tests__|stories|storybook)(/|$)"
    # … or a filename token bounded by . _ - (demo.service.js, user.mock.ts, seed-data.js)
    r"|(^|/|[._-])(example|sample|demo|mock|fixture|seed)s?([._-])"
    r"|\.(test|spec|stories|e2e|cy)\.|(^|/)tests?/|(^|/)e2e/",
    re.IGNORECASE)


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
    note: str = ""       # e.g. "in a documentation/example file — likely illustrative"


def redact(value: str) -> str:
    """Mask a secret so it's safe to store/display: first 4 + last 2 chars,
    middle replaced with a fixed-width mask."""
    v = value.strip().strip("'\"")
    if len(v) <= 8:
        return v[0] + "***" if v else "***"
    return f"{v[:4]}…{v[-2:]} ({len(v)} chars)"


def _low_value_context(rel: str) -> str:
    """A note if `rel` is a doc/example/test/demo file (finding → informational),
    else empty string."""
    norm = rel.replace("\\", "/").lower()
    if Path(rel).suffix.lower() in _DOC_EXT:
        return "in a documentation file — likely illustrative, not a live secret"
    if _LOW_VALUE_PATH.search(norm):
        return "in an example/test/demo file — likely not a live secret"
    return ""


def _iter_text_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        name = path.name.lower()
        if name in _SKIP_FILES or ".min." in name:
            continue
        if path.suffix.lower() in _SKIP_EXT:
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def _is_filtered(name: str, category: str, matched: str, line: str, start: int, end: int) -> bool:
    """Reproduce the recon path's false-positive filters for one match."""
    if _PLACEHOLDER.search(matched):
        return True
    if name == "Email Address" and _is_fp_email(matched):
        return True
    if name == "Internal/Staging URL" and _is_wl_staging(matched):
        return True
    if category in _FP_FILTER_CATEGORIES:
        skip_entropy = any(kw in name for kw in _SKIP_ENTROPY_KEYWORDS)
        if not skip_entropy and len(matched) >= 16 and _shannon_entropy(matched) < 3.0:
            return True
        if _is_inside_base64_blob(line, start, end):
            return True
        if _has_binary_context(line):
            return True
        if _has_repetitive_pattern(matched):
            return True
    return False


def scan_secrets(root: str | Path) -> list[SecretFinding]:
    """Scan every text file under `root` for known secret patterns. Never
    raises on an unreadable file — it's skipped. Matching is line-scoped and
    the recon path's false-positive filters are applied, so lockfile hashes,
    doc URLs, placeholder text and log messages don't inflate the count."""
    root = Path(root)
    # Collapse overlapping patterns that match the SAME secret value at the same
    # location to one finding, keeping the highest severity — one leaked secret
    # is one finding, not N.
    best: dict[tuple, SecretFinding] = {}

    for path in _iter_text_files(root):
        try:
            text = path.read_text(errors="replace")
        except Exception:
            continue
        rel = str(path.relative_to(root))
        downgrade = _low_value_context(rel)
        for lineno, line in enumerate(text.split("\n"), 1):
            if len(line) > 100_000:  # pathological minified line — skip (perf + noise)
                continue
            for pat in JS_SECRET_PATTERNS:
                for m in pat["regex"].finditer(line):
                    matched = m.group(0)
                    if _is_filtered(pat["name"], pat["category"], matched, line, m.start(), m.end()):
                        continue
                    severity = "info" if downgrade else pat["severity"]
                    loc = (rel, lineno, matched)
                    finding = SecretFinding(
                        kind="secret", name=pat["name"], severity=severity,
                        confidence=pat["confidence"], category=pat["category"],
                        file=rel, line=lineno, redacted=redact(matched), note=downgrade,
                    )
                    existing = best.get(loc)
                    if existing is None or _SEV_RANK.get(finding.severity, 9) < _SEV_RANK.get(existing.severity, 9):
                        best[loc] = finding
    return list(best.values())
