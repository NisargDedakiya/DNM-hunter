# Binary / ELF Analyzer (`binary_audit`)

checksec-style low-level analysis of compiled **ELF** binaries — the exploit
mitigations a binary is *missing*, its dangerous imports, and insecure library
paths. Uses standard binutils (`readelf`, `nm`); it inspects the binary, it does
**not** execute it.

## What it reports

| Check | Finding when… |
|---|---|
| **NX / executable stack** | `GNU_STACK` is RWE — stack shellcode can run |
| **PIE** | `Type: EXEC` — fixed addresses, ASLR doesn't apply to the image |
| **RELRO** | none (writable GOT → GOT-overwrite) or partial |
| **Stack canary** | no `__stack_chk_fail` — built without `-fstack-protector` |
| **FORTIFY_SOURCE** | reported as a property (`*_chk` symbols present) |
| **Dangerous imports** | links `gets` (critical), `strcpy`/`system`/`popen`/`mktemp`, … |
| **Insecure RPATH/RUNPATH** | relative / `$ORIGIN` / writable search path → library hijacking |

## Usage

```bash
python -m binary_audit ./a.out
python -m binary_audit /path/to/dir --json     # analyzes every ELF under the dir

from binary_audit import analyze_elf
r = analyze_elf("./a.out")
print(r.properties)   # {'nx':False,'pie':False,'relro':'none','canary':False,...}
for f in r.findings: print(f.severity, f.rule_id, f.title)
```

## Validated

Against real `gcc` output: an insecure build (`-fno-stack-protector -no-pie
-z execstack -z norelro`) flags NX/PIE/RELRO/canary + `gets`/`strcpy`/`system`;
a hardened build (`-fstack-protector-all -pie -Wl,-z,relro,-z,now
-D_FORTIFY_SOURCE=2`) reports all protections present and only the inherent
dangerous imports.

## Scope

This is the fast, deterministic first pass (hardening + imports + strings-level
signals). It is **not** full decompilation / symbolic execution (Ghidra / angr /
IDA) — that's a heavier, separate capability. Point this at any native binary,
a firmware extraction, or committed binaries in a repo.

## Tests

```bash
python -m unittest binary_audit.tests.test_elf -v   # compiles real binaries; skips if no gcc
```
