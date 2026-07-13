"""Regression tests for hardcoded-secret detection in IaC rules.

Guards the fix for a false-negative where \b word boundaries let underscore-
joined env var names (DB_PASSWORD, MYSQL_ROOT_PASSWORD, SECRET_KEY, ...) — the
near-universal convention — slip past both the Dockerfile and Compose rules.

Run: python -m unittest iac_scan.tests.test_secret_name_detection -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rules.dockerfile_rules import check_dockerfile
from rules.compose_rules import check_compose_doc


def _secret_titles(findings):
    return [f["title"] for f in findings if "secret" in f["title"].lower()]


class TestDockerfileSecretNames(unittest.TestCase):
    def test_underscore_joined_names_are_detected(self):
        for name in ("DB_PASSWORD", "MYSQL_ROOT_PASSWORD", "SECRET_KEY", "ACCESS_TOKEN", "PRIVATE_KEY"):
            df = f"FROM ubuntu:22.04\nENV {name}=SuperSecret12345\nUSER app\n"
            self.assertTrue(_secret_titles(check_dockerfile(df, "Dockerfile")),
                            f"{name} should be flagged as a hardcoded secret")

    def test_non_secret_names_are_not_flagged(self):
        for name in ("USERNAME", "HOSTNAME", "PASSWORDLESS_MODE", "TOKENIZER_PATH"):
            df = f"FROM ubuntu:22.04\nENV {name}=SomeLongValue123\nUSER app\n"
            self.assertEqual(_secret_titles(check_dockerfile(df, "Dockerfile")), [],
                             f"{name} should NOT be flagged")


class TestComposeSecretNames(unittest.TestCase):
    def _doc(self, key):
        return {"services": {"web": {"image": "x", "environment": [f"{key}=SuperSecret12345"]}}}

    def test_underscore_joined_names_are_detected(self):
        for name in ("DB_PASSWORD", "MYSQL_ROOT_PASSWORD", "SECRET_KEY", "ACCESS_TOKEN"):
            self.assertTrue(_secret_titles(check_compose_doc(self._doc(name), "docker-compose.yml")),
                            f"{name} should be flagged in compose env")

    def test_env_var_reference_is_not_flagged(self):
        # A ${VAR} reference is not a hardcoded literal.
        doc = {"services": {"web": {"image": "x", "environment": ["DB_PASSWORD=${DB_PASSWORD}"]}}}
        self.assertEqual(_secret_titles(check_compose_doc(doc, "docker-compose.yml")), [])


if __name__ == "__main__":
    unittest.main()
