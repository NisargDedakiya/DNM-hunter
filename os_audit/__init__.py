"""OS / low-level system vulnerability detection.

Two static detectors, no root and no live host required:
  - host_config: CIS-style OS hardening audit of system config files
    (sshd_config, sudoers, sysctl, /etc/passwd + /etc/shadow, fstab).
  - native_code: classic low-level source vulnerabilities in C/C++
    (buffer-overflow-prone functions, command injection, format-string bugs).
"""
from .runner import OsAuditResult, audit_tree

__all__ = ["audit_tree", "OsAuditResult"]
