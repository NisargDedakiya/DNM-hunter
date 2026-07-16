"""Low-level native-code (C/C++) vulnerability scanning.

Static source scan for the classic memory-safety and command-execution bugs
that live at the OS/binary level: buffer overflows from unbounded string
functions, OS command injection, and format-string vulnerabilities. High-signal
patterns only, to keep precision usable without a full compiler front-end.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

CRIT, HIGH, MED, LOW = "critical", "high", "medium", "low"

_C_EXT = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}


@dataclass
class NativeFinding:
    rule_id: str
    severity: str
    title: str
    detail: str
    file: str
    line: int


# Always-unsafe libc functions (no bounds). gets() is unconditionally exploitable.
_UNSAFE = [
    (re.compile(r"\bgets\s*\("), "NATIVE-001", CRIT, "Use of gets()",
     "gets() performs an unbounded read into a fixed buffer — a guaranteed stack buffer overflow. Use fgets()."),
    (re.compile(r"\bstrcpy\s*\("), "NATIVE-002", HIGH, "Use of strcpy()",
     "strcpy() copies without a length bound; a longer source overflows the destination. Use strncpy()/strlcpy()."),
    (re.compile(r"\bstrcat\s*\("), "NATIVE-003", HIGH, "Use of strcat()",
     "strcat() concatenates without a bound and can overflow the destination. Use strncat()/strlcat()."),
    (re.compile(r"\b(sprintf|vsprintf)\s*\("), "NATIVE-004", HIGH, "Use of sprintf()/vsprintf()",
     "sprintf() writes without a size limit and can overflow the buffer. Use snprintf()."),
    (re.compile(r"\bscanf\s*\(\s*\"[^\"]*%s"), "NATIVE-005", HIGH, "scanf(\"%s\") without a width",
     "scanf %s with no field width reads unbounded input into a fixed buffer. Add a width, e.g. %63s."),
    (re.compile(r"\b(alloca|_alloca)\s*\("), "NATIVE-006", MED, "Use of alloca()",
     "alloca() allocates on the stack; an attacker-influenced size can smash the stack. Prefer heap allocation."),
]

# Command execution — variable argument => likely OS command injection.
_CMD_EXEC = re.compile(r"\b(system|popen|execlp|execvp|execl|execv)\s*\(\s*([^)]*)")
_STRING_LITERAL_ARG = re.compile(r'^\s*"[^"]*"\s*[,)]?')

# Format string — first format arg is a bare identifier, not a string literal.
_FMT_VAR = re.compile(r"\b(printf|syslog)\s*\(\s*([A-Za-z_]\w*)\s*\)")
_FMT_VAR2 = re.compile(r"\b(fprintf|sprintf|snprintf|dprintf)\s*\([^,]+,\s*([A-Za-z_]\w*)\s*\)")

# Overly-permissive file modes at the syscall level.
_MODE_777 = re.compile(r"\b(chmod|fchmod|open|creat|mkdir)\s*\([^;]*0777")


def _strip_line_comment(line: str) -> str:
    idx = line.find("//")
    return line[:idx] if idx >= 0 else line


def scan_c_source(text: str, file: str) -> list[NativeFinding]:
    findings: list[NativeFinding] = []
    for ln, raw in enumerate(text.splitlines(), 1):
        line = _strip_line_comment(raw)
        stripped = line.strip()
        if not stripped or stripped.startswith(("*", "/*")):
            continue

        for rx, rid, sev, title, detail in _UNSAFE:
            if rx.search(line):
                findings.append(NativeFinding(rid, sev, title, detail, file, ln))

        m = _CMD_EXEC.search(line)
        if m:
            arg = m.group(2).strip()
            if not _STRING_LITERAL_ARG.match(arg):
                findings.append(NativeFinding("NATIVE-007", HIGH, f"Command execution via {m.group(1)}() with a variable argument",
                                              f"{m.group(1)}() is called with a non-literal argument ({arg[:40]}…); if any part is attacker-controlled this is OS command injection.",
                                              file, ln))
            else:
                findings.append(NativeFinding("NATIVE-008", LOW, f"Command execution via {m.group(1)}()",
                                              f"{m.group(1)}() spawns a shell/process; confirm the command is fully static.",
                                              file, ln))

        fm = _FMT_VAR.search(line) or _FMT_VAR2.search(line)
        if fm:
            findings.append(NativeFinding("NATIVE-009", HIGH, "Format-string vulnerability",
                                          f"{fm.group(1)}() is called with a variable format argument ({fm.group(2)}); attacker-controlled format specifiers can read/write memory. Use a literal format, e.g. \"%s\".",
                                          file, ln))

        if _MODE_777.search(line):
            findings.append(NativeFinding("NATIVE-010", MED, "World-writable file mode (0777)",
                                          "A file/dir is created world-writable (0777) — any local user can modify it.", file, ln))
    return findings


def is_c_source(path: Path) -> bool:
    return path.suffix.lower() in _C_EXT
