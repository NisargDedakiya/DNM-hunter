"""Web-application source SAST — VRT-mapped static detection of the
server-side/web vulnerability classes (injection, crypto weakness, insecure
deserialization, XSS/SSRF/redirect sinks, misconfig) that are visible in code.
"""
from .scanner import CodeFinding, scan_code, scan_tree

__all__ = ["CodeFinding", "scan_code", "scan_tree"]
