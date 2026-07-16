"""ELF binary hardening + dangerous-import analysis (checksec-style).

Uses standard binutils (readelf, nm) to inspect a compiled ELF and report the
low-level protections it is MISSING — the weaknesses that turn a memory bug into
a reliable exploit — plus dangerous imported libc functions and insecure
RPATH/RUNPATH. No decompilation; this is the fast, deterministic layer that a
pentester runs first on any native binary.

CLI:  python -m binary_audit <path-to-elf-or-dir> [--json]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

CRIT, HIGH, MED, LOW, INFO = "critical", "high", "medium", "low", "info"

# Imported libc functions that are inherently dangerous at the binary level.
_DANGEROUS_IMPORTS = {
    "gets": (CRIT, "unbounded read — guaranteed stack overflow"),
    "strcpy": (MED, "unbounded copy — overflow-prone"),
    "strcat": (MED, "unbounded concat — overflow-prone"),
    "sprintf": (MED, "unbounded format write — overflow-prone"),
    "vsprintf": (MED, "unbounded format write — overflow-prone"),
    "scanf": (LOW, "unbounded %s reads possible"),
    "system": (MED, "spawns a shell — command-injection surface"),
    "popen": (MED, "spawns a shell — command-injection surface"),
    "mktemp": (MED, "insecure temp file (race) — use mkstemp"),
    "tmpnam": (MED, "insecure temp file (race)"),
    "strncpy": (LOW, "may leave the destination unterminated"),
}


@dataclass
class BinFinding:
    rule_id: str
    severity: str
    title: str
    detail: str


@dataclass
class ElfAnalysis:
    path: str
    is_elf: bool = False
    properties: dict = field(default_factory=dict)   # nx, pie, relro, canary, fortify, stripped
    findings: list[BinFinding] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return {"path": self.path, "isElf": self.is_elf, "properties": self.properties,
                "error": self.error, "findings": [asdict(f) for f in self.findings]}


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False).stdout
    except Exception:
        return ""


def _is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except Exception:
        return False


def analyze_elf(path: str | Path) -> ElfAnalysis:
    path = Path(path)
    res = ElfAnalysis(path=str(path))
    if not path.is_file() or not _is_elf(path):
        res.error = "not an ELF file"
        return res
    res.is_elf = True

    header = _run(["readelf", "-h", str(path)])
    segments = _run(["readelf", "-lW", str(path)])
    dyn = _run(["readelf", "-dW", str(path)])
    syms = _run(["readelf", "-sW", str(path)]) or _run(["nm", "-D", str(path)])

    props = res.properties

    # ── NX / executable stack ──
    nx = True
    for line in segments.splitlines():
        if "GNU_STACK" in line:
            # flags column contains R W E; E on the stack == executable stack
            flags = line.split("GNU_STACK", 1)[1]
            if "E" in flags.split()[-1] if flags.split() else False:
                nx = False
            elif "RWE" in flags:
                nx = False
    props["nx"] = nx
    if not nx:
        res.findings.append(BinFinding("BIN-NX", HIGH, "Executable stack (NX disabled)",
                                       "The stack is executable (GNU_STACK RWE) — injected shellcode on the stack can run."))

    # ── PIE / ASLR for the image ──
    etype = ""
    for line in header.splitlines():
        if line.strip().startswith("Type:"):
            etype = line.split("Type:", 1)[1].strip()
    is_dyn = etype.startswith("DYN")
    has_interp = "INTERP" in segments
    pie = is_dyn and has_interp
    props["pie"] = pie
    if etype.startswith("EXEC"):
        res.findings.append(BinFinding("BIN-PIE", MED, "No PIE (position-dependent executable)",
                                       "The executable is not position-independent, so its code/data are at fixed addresses — ASLR does not apply to the image, aiding ROP."))

    # ── RELRO ──
    has_relro_seg = "GNU_RELRO" in segments
    bind_now = "BIND_NOW" in dyn or "(FLAGS)" in dyn and "NOW" in dyn
    if has_relro_seg and bind_now:
        props["relro"] = "full"
    elif has_relro_seg:
        props["relro"] = "partial"
        res.findings.append(BinFinding("BIN-RELRO", LOW, "Partial RELRO",
                                       "The GOT is only partially protected; full RELRO (-z relro -z now) prevents GOT-overwrite attacks."))
    else:
        props["relro"] = "none"
        res.findings.append(BinFinding("BIN-RELRO", MED, "No RELRO",
                                       "The relocation table / GOT is writable — a memory write can hijack control flow via GOT overwrite."))

    # ── Stack canary ──
    canary = ("__stack_chk_fail" in syms) or ("__stack_chk_guard" in syms)
    props["canary"] = canary
    if not canary:
        res.findings.append(BinFinding("BIN-CANARY", MED, "No stack canary",
                                       "No __stack_chk_fail reference — the binary was built without stack-smashing protection (-fstack-protector)."))

    # ── FORTIFY_SOURCE ──
    props["fortify"] = "_chk" in syms
    props["stripped"] = "no symbols" in _run(["nm", str(path)]).lower() or not _run(["nm", str(path)]).strip()

    # ── Dangerous imported symbols ──
    imported = set()
    for line in syms.splitlines():
        parts = line.split()
        # readelf -s: last column is the symbol name; keep undefined (UND) imports
        if not parts:
            continue
        name = parts[-1].split("@")[0]
        if name in _DANGEROUS_IMPORTS and ("UND" in line or "U " in line or True):
            imported.add(name)
    for name in sorted(imported):
        sev, why = _DANGEROUS_IMPORTS[name]
        res.findings.append(BinFinding(f"BIN-IMPORT-{name}", sev, f"Imports dangerous function {name}()",
                                       f"The binary links {name}() — {why}."))

    # ── Insecure RPATH / RUNPATH ──
    for line in dyn.splitlines():
        if "RPATH" in line or "RUNPATH" in line:
            val = line.split("[", 1)[1].rstrip("]") if "[" in line else line
            if any(tok in val for tok in ("$ORIGIN", "./", "/tmp", "..")) or (":" not in val and "/" not in val):
                res.findings.append(BinFinding("BIN-RPATH", MED, "Insecure RPATH/RUNPATH",
                                               f"Runtime library search path {val!r} is relative/writable — a planted .so can be loaded (library hijacking)."))

    return res


def analyze_path(path: str | Path) -> list[ElfAnalysis]:
    """Analyze a single ELF, or every ELF under a directory."""
    path = Path(path)
    if path.is_file():
        return [analyze_elf(path)]
    out = []
    for p in path.rglob("*"):
        if p.is_file() and _is_elf(p):
            out.append(analyze_elf(p))
    return out


def _main() -> int:
    ap = argparse.ArgumentParser(description="Analyze an ELF binary's low-level hardening + dangerous imports.")
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    results = analyze_path(args.path)
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
        return 0
    for r in results:
        if not r.is_elf:
            continue
        print(f"{r.path}  {r.properties}")
        for f in r.findings:
            print(f"  [{f.severity:8}] {f.rule_id:18} {f.title}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
