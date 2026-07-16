"""OS host-hardening audit — CIS-style checks over system configuration files.

Analyses the *content* of common Linux system config files for dangerous
low-level settings, entirely statically (no root, no live host). Finds bugs
like root SSH login, ASLR disabled, passwordless sudo, UID-0 backdoor accounts,
and world-exec temp mounts — the OS-level misconfigurations attackers rely on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class HostFinding:
    rule_id: str
    severity: str      # critical | high | medium | low
    title: str
    detail: str
    file: str
    line: int | None = None


CRIT, HIGH, MED, LOW = "critical", "high", "medium", "low"


def _lines(text: str):
    """Yield (line_number, stripped_non_comment_line)."""
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        yield i, s


# --------------------------------------------------------------------------- #
# sshd_config
# --------------------------------------------------------------------------- #
def audit_sshd_config(text: str, file: str) -> list[HostFinding]:
    f: list[HostFinding] = []
    for ln, s in _lines(text):
        low = s.lower()
        key = low.split()[0] if low.split() else ""
        val = low.split()[1] if len(low.split()) > 1 else ""
        if key == "permitrootlogin" and val in ("yes", "prohibit-password"):
            sev = CRIT if val == "yes" else MED
            f.append(HostFinding("OS-SSH-001", sev, "SSH permits root login",
                                 f"PermitRootLogin {val} — disable direct root SSH (set to 'no').", file, ln))
        if key == "permitemptypasswords" and val == "yes":
            f.append(HostFinding("OS-SSH-002", CRIT, "SSH permits empty passwords",
                                 "PermitEmptyPasswords yes — accounts with no password can log in.", file, ln))
        if key == "passwordauthentication" and val == "yes":
            f.append(HostFinding("OS-SSH-003", MED, "SSH password authentication enabled",
                                 "PasswordAuthentication yes — prefer key-based auth to resist brute force.", file, ln))
        if key == "protocol" and "1" in val.split(","):
            f.append(HostFinding("OS-SSH-004", HIGH, "SSH protocol 1 enabled",
                                 "Protocol 1 is cryptographically broken; use protocol 2 only.", file, ln))
        if key in ("ciphers", "macs") and re.search(r"\b(3des|arcfour|cbc|md5|hmac-sha1\b)", low):
            f.append(HostFinding("OS-SSH-005", MED, "Weak SSH ciphers/MACs configured",
                                 f"{s} — includes weak/deprecated algorithms.", file, ln))
    return f


# --------------------------------------------------------------------------- #
# sudoers
# --------------------------------------------------------------------------- #
def audit_sudoers(text: str, file: str) -> list[HostFinding]:
    f: list[HostFinding] = []
    for ln, s in _lines(text):
        if "NOPASSWD" in s.upper():
            f.append(HostFinding("OS-SUDO-001", HIGH, "Passwordless sudo (NOPASSWD)",
                                 f"{s} — a compromised account escalates to root without a password.", file, ln))
        if re.search(r"!\s*authenticate", s, re.IGNORECASE):
            f.append(HostFinding("OS-SUDO-002", HIGH, "sudo authentication disabled (!authenticate)",
                                 f"{s} — sudo will not prompt for a password.", file, ln))
        # ALL=(ALL) ALL granted to a non-root, non-%wheel/%sudo principal
        m = re.match(r"^(\S+)\s+ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL\s*$", s, re.IGNORECASE)
        if m and m.group(1).lower() not in ("root", "%wheel", "%sudo", "%admin"):
            f.append(HostFinding("OS-SUDO-003", MED, "Full sudo granted to a non-standard principal",
                                 f"{s} — grants unrestricted root to {m.group(1)}.", file, ln))
    return f


# --------------------------------------------------------------------------- #
# sysctl (kernel hardening)
# --------------------------------------------------------------------------- #
_SYSCTL_RULES = {
    "kernel.randomize_va_space": ("0", CRIT, "ASLR disabled",
                                  "kernel.randomize_va_space=0 turns off address-space layout randomization, making memory-corruption exploits reliable."),
    "kernel.yama.ptrace_scope": ("0", MED, "ptrace not restricted",
                                 "kernel.yama.ptrace_scope=0 lets any process trace another — aids credential theft from memory."),
    "fs.suid_dumpable": ("1", MED, "SUID core dumps enabled",
                         "fs.suid_dumpable=1 lets setuid programs dump core, leaking secrets."),
    "kernel.dmesg_restrict": ("0", LOW, "dmesg not restricted",
                              "kernel.dmesg_restrict=0 exposes kernel pointers/log to unprivileged users (KASLR bypass aid)."),
    "kernel.unprivileged_bpf_disabled": ("0", HIGH, "Unprivileged BPF enabled",
                                         "kernel.unprivileged_bpf_disabled=0 exposes the eBPF verifier to unprivileged users — a recurring LPE surface."),
    "net.ipv4.conf.all.rp_filter": ("0", LOW, "Reverse-path filtering disabled",
                                    "net.ipv4.conf.all.rp_filter=0 allows source-spoofed packets."),
}


def audit_sysctl(text: str, file: str) -> list[HostFinding]:
    f: list[HostFinding] = []
    for ln, s in _lines(text):
        if "=" not in s:
            continue
        key, _, val = s.partition("=")
        key, val = key.strip(), val.strip()
        rule = _SYSCTL_RULES.get(key)
        if rule and val == rule[0]:
            _, sev, title, detail = rule
            f.append(HostFinding("OS-SYSCTL", sev, title, detail, file, ln))
        # ip_forward on a non-router host turns it into a pivot
        if key in ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding") and val == "1":
            f.append(HostFinding("OS-SYSCTL-FWD", LOW, "IP forwarding enabled",
                                 f"{s} — the host will route packets; unexpected on a non-gateway system.", file, ln))
    return f


# --------------------------------------------------------------------------- #
# /etc/passwd + /etc/shadow
# --------------------------------------------------------------------------- #
def audit_passwd(text: str, file: str) -> list[HostFinding]:
    f: list[HostFinding] = []
    for ln, s in _lines(text):
        parts = s.split(":")
        if len(parts) < 7:
            continue
        name, pw, uid = parts[0], parts[1], parts[2]
        if uid == "0" and name != "root":
            f.append(HostFinding("OS-PASSWD-001", CRIT, "Non-root account with UID 0",
                                 f"Account {name!r} has UID 0 — an equivalent-to-root backdoor.", file, ln))
        if pw == "":
            f.append(HostFinding("OS-PASSWD-002", HIGH, "Account with empty password field",
                                 f"Account {name!r} has an empty password field in passwd.", file, ln))
    return f


def audit_shadow(text: str, file: str) -> list[HostFinding]:
    f: list[HostFinding] = []
    for ln, s in _lines(text):
        parts = s.split(":")
        if len(parts) < 2:
            continue
        name, pwhash = parts[0], parts[1]
        if pwhash == "":
            f.append(HostFinding("OS-SHADOW-001", CRIT, "Account with no password hash",
                                 f"Account {name!r} has an empty password hash — it can log in with no password.", file, ln))
        elif pwhash.startswith("$1$"):
            f.append(HostFinding("OS-SHADOW-002", MED, "Weak MD5 password hash",
                                 f"Account {name!r} uses an MD5 ($1$) password hash; use yescrypt/sha512.", file, ln))
    return f


# --------------------------------------------------------------------------- #
# fstab (mount hardening)
# --------------------------------------------------------------------------- #
def audit_fstab(text: str, file: str) -> list[HostFinding]:
    f: list[HostFinding] = []
    for ln, s in _lines(text):
        cols = s.split()
        if len(cols) < 4:
            continue
        mount, opts = cols[1], cols[3]
        optset = set(opts.split(","))
        if mount in ("/tmp", "/dev/shm", "/var/tmp"):
            missing = [o for o in ("nosuid", "noexec", "nodev") if o not in optset]
            if missing:
                f.append(HostFinding("OS-FSTAB-001", MED, f"{mount} missing hardening mount options",
                                     f"{mount} does not set {', '.join(missing)} — allows exec/setuid from a world-writable area.", file, ln))
    return f


# --------------------------------------------------------------------------- #
# dispatcher
# --------------------------------------------------------------------------- #
def audit_config_file(name: str, path_str: str, text: str) -> list[HostFinding]:
    """Route a file to the right audit based on its name/path."""
    n = name.lower()
    p = path_str.lower()
    if n == "sshd_config":
        return audit_sshd_config(text, path_str)
    if n == "sudoers" or "/sudoers.d/" in p:
        return audit_sudoers(text, path_str)
    if n.endswith(".conf") and ("sysctl" in p or n == "sysctl.conf"):
        return audit_sysctl(text, path_str)
    if n == "passwd":
        return audit_passwd(text, path_str)
    if n == "shadow":
        return audit_shadow(text, path_str)
    if n == "fstab":
        return audit_fstab(text, path_str)
    return []
