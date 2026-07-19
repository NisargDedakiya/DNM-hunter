"""CLI entry point so `python -m web_probe <url> [--json]` works.

Usage:  python -m web_probe https://target.example [--json]
"""
import sys

from .scanner import _main

if __name__ == "__main__":
    sys.exit(_main())
