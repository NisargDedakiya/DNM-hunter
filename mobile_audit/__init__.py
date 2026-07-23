"""mobile_audit — static source SAST for mobile apps (Android + iOS), mapped to
the OWASP Mobile Top 10 (2024).

    from mobile_audit import scan_tree, scan_code
    for f in scan_tree("path/to/app"):
        print(f.owasp, f.severity, f.platform, f.file, f.title)
"""

from .scanner import MobileFinding, scan_code, scan_tree

__all__ = ["MobileFinding", "scan_code", "scan_tree"]
