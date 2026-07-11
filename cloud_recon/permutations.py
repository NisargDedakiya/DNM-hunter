"""Candidate cloud storage bucket/container name generation.

Given seed words (company name, product name, domain labels), produces a
deduplicated list of plausible bucket names by combining seeds with common
separators and suffix/prefix wordlists — the same permutation strategy tools
like s3scanner/GCPBucketBrute use.
"""
import re

_SEPARATORS = ("-", "_", ".")
_SUFFIX_WORDS = (
    "prod", "production", "dev", "development", "staging", "stage",
    "test", "backup", "backups", "assets", "static", "media", "uploads",
    "data", "logs", "public", "private", "internal", "files", "cdn",
    "www", "web", "app", "images", "storage", "archive",
)
_PREFIX_WORDS = ("www", "cdn", "static", "assets", "backup")

_MAX_CANDIDATES = 400


def _normalize(seed: str) -> str:
    s = seed.strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = re.sub(r"\.(com|net|org|io|co|app|dev)$", "", s)
    s = re.sub(r"[^a-z0-9.\-]", "", s)
    return s


def generate_candidates(seeds: list[str]) -> list[str]:
    normalized = sorted({_normalize(s) for s in seeds if _normalize(s)})
    candidates: set[str] = set()

    def _add(name: str):
        name = name.strip("-_.")
        if 3 <= len(name) <= 63 and re.match(r"^[a-z0-9][a-z0-9.\-]*[a-z0-9]$", name):
            candidates.add(name)

    for seed in normalized:
        _add(seed)
        for sep in _SEPARATORS:
            for suffix in _SUFFIX_WORDS:
                _add(f"{seed}{sep}{suffix}")
            for prefix in _PREFIX_WORDS:
                _add(f"{prefix}{sep}{seed}")
        if len(candidates) >= _MAX_CANDIDATES:
            break

    return sorted(candidates)[:_MAX_CANDIDATES]
