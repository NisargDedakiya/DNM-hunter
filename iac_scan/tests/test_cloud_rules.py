"""Regression tests for the multi-cloud IaC rules (GCP + Azure).

Extends cloud misconfiguration detection beyond AWS. Run:
  python -m unittest iac_scan.tests.test_cloud_rules -v
"""
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hcl2  # noqa: E402
from rules.terraform_rules import check_terraform_doc  # noqa: E402


def ids(tf: str):
    return {f["rule_id"] for f in check_terraform_doc(hcl2.load(io.StringIO(tf)), "main.tf")}


class TestGcp(unittest.TestCase):
    def test_public_bucket_iam(self):
        tf = 'resource "google_storage_bucket_iam_member" "p" { bucket="b" role="roles/storage.objectViewer" member="allUsers" }'
        self.assertIn("GCP-001", ids(tf))

    def test_open_firewall_sensitive_port_is_critical(self):
        tf = 'resource "google_compute_firewall" "f" { direction="INGRESS" source_ranges=["0.0.0.0/0"] allow { protocol="tcp" ports=["22"] } }'
        self.assertIn("GCP-003", ids(tf))

    def test_public_cloud_sql(self):
        tf = 'resource "google_sql_database_instance" "d" { settings { ip_configuration { ipv4_enabled = true } } }'
        self.assertIn("GCP-004", ids(tf))

    def test_primitive_owner_role(self):
        tf = 'resource "google_project_iam_member" "o" { role="roles/owner" member="user:x@y.com" }'
        self.assertIn("GCP-007", ids(tf))

    def test_secure_bucket_is_clean(self):
        tf = 'resource "google_storage_bucket" "b" { uniform_bucket_level_access { enabled = true } }'
        self.assertEqual(ids(tf), set())


class TestAzure(unittest.TestCase):
    def test_public_blob_storage(self):
        tf = 'resource "azurerm_storage_account" "s" { allow_nested_items_to_be_public = true }'
        self.assertIn("AZURE-001", ids(tf))

    def test_plaintext_http(self):
        tf = 'resource "azurerm_storage_account" "s" { enable_https_traffic_only = false }'
        self.assertIn("AZURE-002", ids(tf))

    def test_open_nsg_rule(self):
        tf = 'resource "azurerm_network_security_rule" "r" { access="Allow" direction="Inbound" source_address_prefix="*" destination_port_range="3389" }'
        self.assertIn("AZURE-004", ids(tf))

    def test_open_sql_firewall(self):
        tf = 'resource "azurerm_sql_firewall_rule" "f" { start_ip_address="0.0.0.0" end_ip_address="255.255.255.255" }'
        self.assertIn("AZURE-005", ids(tf))

    def test_secure_storage_is_clean(self):
        tf = 'resource "azurerm_storage_account" "s" { enable_https_traffic_only = true min_tls_version = "TLS1_2" }'
        self.assertEqual(ids(tf), set())


class TestMultiCloudInOneFile(unittest.TestCase):
    def test_aws_gcp_azure_in_one_scan(self):
        tf = '''
        resource "aws_s3_bucket" "a" { bucket = "x" acl = "public-read" }
        resource "google_storage_bucket_iam_member" "g" { bucket="b" role="r" member="allUsers" }
        resource "azurerm_storage_account" "z" { allow_nested_items_to_be_public = true }
        '''
        got = ids(tf)
        self.assertIn("TF-001", got)     # AWS
        self.assertIn("GCP-001", got)    # GCP
        self.assertIn("AZURE-001", got)  # Azure


if __name__ == "__main__":
    unittest.main()
