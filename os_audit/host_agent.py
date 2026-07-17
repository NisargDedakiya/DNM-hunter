"""Live-host collector agent.

Unlike host_config.py (which parses config *files* you give it), this runs ON a
host and collects from the *live* system: it reads the real /etc config, the
live kernel hardening state from /proc/sys, and walks the filesystem to inventory
SUID/SGID binaries and world-writable paths — the checks that are only possible
against a running machine.

It reuses the static rule functions for config content and adds the live-only
checks. Read-only; needs no writes and degrades gracefully when a path is
unreadable (e.g. /etc/shadow without root).

CLI:  python -m os_audit.host_agent [--root /] [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .host_config import (
    _SYSCTL_RULES,
    CRIT,
    MED,
    audit_fstab,
    audit_passwd,
    audit_shadow,
    audit_sshd_config,
    audit_sudoers,
)

# Standard setuid-root binaries shipped by the distro — expected, not flagged.
_STANDARD_SUID = {
    "sudo", "sudoedit", "su", "passwd", "chsh", "chfn", "newgrp", "gpasswd",
    "mount", "umount", "ping", "ping6", "pkexec", "fusermount", "fusermount3",
    "ssh-keysign", "unix_chkpwd", "expiry", "chage", "at", "crontab",
    "dbus-daemon-launch-helper", "polkit-agent-helper-1", "vmware-user-suid-wrapper",
    "Xorg.wrap", "mount.nfs", "write", "wall",
}
# SUID on any of these is an immediate privilege-escalation primitive (GTFOBins).
_GTFO_SUID = {
    "bash", "sh", "dash", "zsh", "find", "vim", "vi", "nano", "less", "more",
    "man", "awk", "gawk", "perl", "python", "python3", "ruby", "lua", "node",
    "cp", "mv", "tar", "zip", "nmap", "env", "ionice", "nice", "docker",
    "gdb", "make", "ftp", "socat", "tee", "dd", "emacs", "ed", "expect",
}


@dataclass
class AgentFinding:
    rule_id: str
    severity: str
    title: str
    detail: str
    path: str


@dataclass
class HostAgentResult:
    host_root: str
    findings: list[AgentFinding] = field(default_factory=list)
    collected: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"hostRoot": self.host_root, "collected": self.collected,
                "findings": [asdict(f) for f in self.findings]}


def _read(path: Path) -> str | None:
    try:
        return path.read_text(errors="replace")
    except Exception:
        return None


def _audit_live_configs(root: Path) -> list[AgentFinding]:
    out: list[AgentFinding] = []
    jobs = [
        ("etc/ssh/sshd_config", audit_sshd_config),
        ("etc/sudoers", audit_sudoers),
        ("etc/passwd", audit_passwd),
        ("etc/shadow", audit_shadow),
        ("etc/fstab", audit_fstab),
    ]
    for rel, fn in jobs:
        text = _read(root / rel)
        if text is None:
            continue
        for h in fn(text, "/" + rel):
            out.append(AgentFinding(h.rule_id, h.severity, h.title, h.detail, "/" + rel))
    return out


def _audit_live_sysctl(root: Path) -> list[AgentFinding]:
    """Read the *running* kernel's hardening state from /proc/sys."""
    out: list[AgentFinding] = []
    proc_sys = root / "proc/sys"
    for key, (bad_val, sev, title, detail) in _SYSCTL_RULES.items():
        p = proc_sys / key.replace(".", "/")
        val = _read(p)
        if val is None:
            continue
        if val.strip() == bad_val:
            out.append(AgentFinding(f"LIVE-SYSCTL:{key}", sev, f"{title} (live)", detail, "/" + str(p.relative_to(root))))
    return out


def _inventory_suid(root: Path, scan_dirs: list[str], max_files: int = 20000) -> tuple[list[AgentFinding], int]:
    """Walk the filesystem for setuid/setgid files; flag unexpected ones."""
    out: list[AgentFinding] = []
    count = 0
    for d in scan_dirs:
        base = root / d.lstrip("/")
        if not base.exists():
            continue
        for dirpath, _dirnames, filenames in os.walk(base, followlinks=False):
            for name in filenames:
                count += 1
                if count > max_files:
                    return out, count
                fp = Path(dirpath) / name
                try:
                    mode = fp.lstat().st_mode
                except OSError:
                    continue
                if not (mode & (stat.S_ISUID | stat.S_ISGID)):
                    continue
                suid = bool(mode & stat.S_ISUID)
                shown = "/" + str(fp.relative_to(root))
                if name in _GTFO_SUID and suid:
                    out.append(AgentFinding("LIVE-SUID-GTFO", CRIT, f"SUID on a shell-capable binary: {name}",
                                            f"{shown} is setuid-root and is a known GTFOBins privilege-escalation primitive.", shown))
                elif suid and name not in _STANDARD_SUID:
                    out.append(AgentFinding("LIVE-SUID-UNKNOWN", MED, f"Unexpected SUID binary: {name}",
                                            f"{shown} is setuid-root and is not a standard distro binary — review why it needs root.", shown))
    return out, count


def _world_writable(root: Path, scan_dirs: list[str], max_files: int = 20000) -> list[AgentFinding]:
    out: list[AgentFinding] = []
    count = 0
    for d in scan_dirs:
        base = root / d.lstrip("/")
        if not base.exists():
            continue
        for dirpath, _dirnames, filenames in os.walk(base, followlinks=False):
            for name in filenames:
                count += 1
                if count > max_files:
                    return out
                fp = Path(dirpath) / name
                try:
                    mode = fp.lstat().st_mode
                except OSError:
                    continue
                # world-writable regular file that is NOT a symlink
                if stat.S_ISREG(mode) and (mode & stat.S_IWOTH):
                    shown = "/" + str(fp.relative_to(root))
                    out.append(AgentFinding("LIVE-WWRITE", MED, f"World-writable file: {name}",
                                            f"{shown} is writable by any local user — a tampering/backdoor surface.", shown))
    return out


def collect_and_audit(root: str | Path = "/", suid_dirs: list[str] | None = None,
                      ww_dirs: list[str] | None = None) -> HostAgentResult:
    root = Path(root)
    suid_dirs = suid_dirs or ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/opt"]
    ww_dirs = ww_dirs or ["/etc", "/usr/local/bin", "/opt"]

    findings: list[AgentFinding] = []
    findings += _audit_live_configs(root)
    findings += _audit_live_sysctl(root)
    suid_findings, scanned = _inventory_suid(root, suid_dirs)
    findings += suid_findings
    findings += _world_writable(root, ww_dirs)

    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (rank.get(f.severity, 9), f.path))
    res = HostAgentResult(host_root=str(root), findings=findings)
    res.collected = {"suid_files_scanned": scanned, "total_findings": len(findings)}
    return res


def _main() -> int:
    ap = argparse.ArgumentParser(description="Live-host security posture collector.")
    ap.add_argument("--root", default="/", help="filesystem root to treat as the host (default /)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    res = collect_and_audit(args.root)
    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
        return 0
    print(f"Host agent — root={res.host_root}  ({res.collected})")
    for f in res.findings:
        print(f"  [{f.severity:8}] {f.rule_id:20} {f.path}  — {f.title}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
