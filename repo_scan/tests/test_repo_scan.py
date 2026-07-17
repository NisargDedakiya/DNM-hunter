"""Tests for the GitHub-repo vulnerability scanner.

Runs against a planted local tree (no network) so it's fully deterministic.
Run: python -m unittest repo_scan.tests.test_repo_scan -v
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from repo_scan import scan_tree  # noqa: E402
from repo_scan.secret_scanner import redact, scan_secrets  # noqa: E402

# Build secret-shaped test values at RUNTIME from split parts. The assembled
# string matches the detector regex, but no contiguous token literal exists in
# this file — so GitHub push protection (and our own scanner) don't flag the
# test fixture itself. Values are synthetic, not real credentials.
_AWS_KEY = "AKIA" + "5T7RQ2VN4KJ" + "W9XZC"                       # AKIA[0-9A-Z]{16}
_STRIPE_KEY = "sk_" + "live_" + "0Synthetic0Test0Key0abcdEFGH"    # sk_live_[0-9a-zA-Z]{24,}
_GH_TOKEN = "ghp_" + "0synthetic0test0token0" + "abcdefghijklmn"  # ghp_[0-9a-zA-Z]{36}
_AWS_PLACEHOLDER = "AKIA" + "EXAMPLE" + "EXAMPLE12"               # contains EXAMPLE -> ignored


def _planted_repo(root: Path):
    (root / "infra").mkdir(parents=True, exist_ok=True)
    (root / "Dockerfile").write_text("FROM ubuntu:latest\nRUN curl -sL https://x/i.sh | bash\n")
    (root / "infra" / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" { bucket = "x" acl = "public-read" }\n'
        'resource "aws_instance" "web" { ami = "ami-1" instance_type = "t3.micro" }\n'
    )
    (root / ".env").write_text(
        f"AWS_ACCESS_KEY_ID={_AWS_KEY}\n"
        f"STRIPE_KEY={_STRIPE_KEY}\n"
    )
    (root / "config.yaml").write_text(f"github_token: {_GH_TOKEN}\n")
    # noise that must be skipped / not flagged
    (root / "node_modules").mkdir(exist_ok=True)
    (root / "node_modules" / "leak.env").write_text(f"AWS_ACCESS_KEY_ID={_AWS_KEY}\n")
    (root / "README.md").write_text(f"Set your key like AWS_ACCESS_KEY_ID={_AWS_PLACEHOLDER}\n")


class TestSecretScanner(unittest.TestCase):
    def test_finds_real_secrets_and_redacts(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); _planted_repo(root)
            found = scan_secrets(root)
            names = {f.name for f in found}
            self.assertIn("AWS Access Key ID", names)
            self.assertIn("GitHub Token Classic", names)
            # every reported secret is redacted (no raw value leaks)
            for f in found:
                self.assertNotIn(_AWS_KEY, f.redacted)
                self.assertNotIn(_GH_TOKEN, f.redacted)

    def test_skips_vendored_dirs(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); _planted_repo(root)
            found = scan_secrets(root)
            self.assertFalse(any("node_modules" in f.file for f in found), "must not scan node_modules")

    def test_placeholder_values_are_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); _planted_repo(root)
            found = scan_secrets(root)
            self.assertFalse(any("README" in f.file for f in found), "EXAMPLE placeholder must be ignored")

    def test_overlapping_patterns_collapse_to_one(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / ".env").write_text(f"KEY={_STRIPE_KEY}\n")
            found = [f for f in scan_secrets(root) if f.line == 1]
            self.assertEqual(len(found), 1, "one secret value -> one finding, not N overlapping patterns")

    def test_redact_never_returns_full_value(self):
        self.assertNotEqual(redact(_AWS_KEY), _AWS_KEY)


class TestRepoScanIntegration(unittest.TestCase):
    def test_scan_tree_returns_misconfig_and_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); _planted_repo(root)
            res = scan_tree(root, repo_label="test/repo")
            kinds = {f.kind for f in res.findings}
            self.assertIn("misconfig", kinds)
            self.assertIn("secret", kinds)
            self.assertIsNone(res.error)
            self.assertEqual(res.summary["highestSeverity"], "critical")
            self.assertGreater(res.summary["total"], 5)

    def test_findings_sorted_by_severity(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); _planted_repo(root)
            res = scan_tree(root)
            rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            seq = [rank[f.severity] for f in res.findings]
            self.assertEqual(seq, sorted(seq))

    def test_scan_repo_on_local_dir_skips_clone(self):
        from repo_scan import scan_repo
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); _planted_repo(root)
            res = scan_repo(str(root))
            self.assertIsNone(res.error)
            self.assertGreater(res.summary["total"], 0)


if __name__ == "__main__":
    unittest.main()
