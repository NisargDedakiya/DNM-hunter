# OS & Low-Level Auditor (`os_audit`)

Finds bugs at the **operating-system and native-code level** — the layer below
the web app — entirely statically (no root, no live host, no compiler).

Two detectors:

## 1. Host-hardening config audit (`host_config.py`)
CIS-benchmark-style checks over the *content* of system config files:

| File | Detects |
|---|---|
| `sshd_config` | root SSH login, empty passwords, password auth, protocol 1, weak ciphers/MACs |
| `sudoers` / `sudoers.d/*` | `NOPASSWD`, `!authenticate`, full sudo to non-standard principals |
| `sysctl.conf` / `sysctl.d/*` | ASLR off (`randomize_va_space=0`), unprivileged BPF, ptrace unrestricted, SUID core dumps, IP forwarding |
| `/etc/passwd` | UID-0 backdoor accounts, empty password field |
| `/etc/shadow` | empty password hash, weak MD5 (`$1$`) hashes |
| `/etc/fstab` | `/tmp`, `/dev/shm`, `/var/tmp` missing `nosuid`/`noexec`/`nodev` |

## 2. Native-code (C/C++) vulnerability scan (`native_code.py`)
The classic memory-safety / binary-level bugs:

- **Buffer overflow** — `gets()` (critical), `strcpy`/`strcat`/`sprintf`/`scanf("%s")`, `alloca()`
- **OS command injection** — `system`/`popen`/`exec*` with a **variable** argument (a literal argument is only low-severity)
- **Format-string** — `printf(var)` / `fprintf(f, var)` where the format is not a literal
- **World-writable modes** — `chmod/open(..., 0777)`

High-signal patterns only, so precision stays usable — e.g. `snprintf(b, sizeof b, "%s", s)` and `printf("%s", s)` are correctly **not** flagged.

## Usage

```bash
python -m os_audit /path/to/checkout            # or a mounted host /etc
python -m os_audit ./repo --json

from os_audit import audit_tree
res = audit_tree("/path")
print(res.summary)                              # totals + bySeverity + byKind
```

## Integration

- Shipped as a plugin: `plugins/scanner/os-audit.json` (Marketplace, `fs:read` only).
- The **GitHub repo scanner** (`repo_scan`) runs it automatically, so a scanned
  repo is checked for OS/native bugs alongside IaC misconfig + secrets.

## Scope note

This is **static** analysis of config files and source. It is not a running-host
agent (that would read a live `/etc`, enumerate SUID binaries on disk, and query
the kernel) and not a binary/decompiler analysis (Ghidra/angr-class). Point it at
a repo, a config bundle, or a mounted host filesystem.

## Tests

```bash
python -m unittest os_audit.tests.test_os_audit -v   # 14 tests
```
