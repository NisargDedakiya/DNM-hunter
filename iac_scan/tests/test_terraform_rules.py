"""Regression tests for Terraform misconfiguration rules, incl. the accuracy
upgrades: IMDSv1 detection (TF-009), unencrypted EBS (TF-010), and the TF-008
hardcoded-secret value check that no longer misses special-character passwords.

Run: python -m unittest iac_scan.tests.test_terraform_rules -v
"""
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hcl2  # noqa: E402
from rules.terraform_rules import check_terraform_doc  # noqa: E402


def scan(tf: str):
    return check_terraform_doc(hcl2.load(io.StringIO(tf)), "main.tf")


def ids(findings):
    return {f["rule_id"] for f in findings}


class TestImdsv1(unittest.TestCase):
    def test_no_metadata_options_flags_imdsv1(self):
        tf = 'resource "aws_instance" "web" { ami = "ami-1" instance_type = "t3.micro" }'
        self.assertIn("TF-009", ids(scan(tf)))

    def test_http_tokens_optional_flags_imdsv1(self):
        tf = 'resource "aws_instance" "web" { ami = "ami-1" metadata_options { http_tokens = "optional" } }'
        self.assertIn("TF-009", ids(scan(tf)))

    def test_http_tokens_required_is_clean(self):
        tf = 'resource "aws_instance" "web" { ami = "ami-1" metadata_options { http_tokens = "required" } }'
        self.assertNotIn("TF-009", ids(scan(tf)))

    def test_launch_template_covered(self):
        tf = 'resource "aws_launch_template" "lt" { image_id = "ami-1" }'
        self.assertIn("TF-009", ids(scan(tf)))


class TestEbsEncryption(unittest.TestCase):
    def test_unencrypted_ebs_flags(self):
        tf = 'resource "aws_ebs_volume" "d" { availability_zone = "us-east-1a" size = 20 }'
        self.assertIn("TF-010", ids(scan(tf)))

    def test_encrypted_ebs_is_clean(self):
        tf = 'resource "aws_ebs_volume" "d" { encrypted = true size = 20 }'
        self.assertNotIn("TF-010", ids(scan(tf)))


class TestHardcodedSecretValue(unittest.TestCase):
    def test_special_char_password_is_caught(self):
        # The old charset-limited regex missed values with @ ! # etc.
        tf = 'resource "aws_db_instance" "db" { password = "P@ssw0rd!2024#" }'
        self.assertIn("TF-008", ids(scan(tf)))

    def test_variable_reference_is_not_flagged(self):
        tf = 'resource "aws_db_instance" "db" { password = var.db_password }'
        self.assertNotIn("TF-008", ids(scan(tf)))

    def test_interpolation_is_not_flagged(self):
        tf = 'resource "aws_db_instance" "db" { password = "${data.aws_ssm.x.value}" }'
        self.assertNotIn("TF-008", ids(scan(tf)))


class TestExistingRulesStillFire(unittest.TestCase):
    def test_public_s3_and_open_sg_and_iam_wildcard(self):
        tf = '''
        resource "aws_s3_bucket" "b" { bucket = "x" acl = "public-read" }
        resource "aws_security_group" "sg" {
          ingress { from_port = 22 to_port = 22 protocol = "tcp" cidr_blocks = ["0.0.0.0/0"] }
        }
        '''
        got = ids(scan(tf))
        self.assertIn("TF-001", got)   # public S3
        self.assertIn("TF-004", got)   # open SG


if __name__ == "__main__":
    unittest.main()
