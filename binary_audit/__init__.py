"""Binary / low-level (ELF) security analysis.

A checksec-style hardening analyzer for compiled ELF binaries, plus detection of
dangerous imported symbols and insecure RPATH/RUNPATH — using standard binutils
(readelf, nm). Finds the binary-level weaknesses that make memory-corruption
bugs exploitable: no NX, no PIE, no stack canary, no RELRO, and unsafe imports.
"""
from .elf import ElfAnalysis, analyze_elf, analyze_path

__all__ = ["analyze_elf", "analyze_path", "ElfAnalysis"]
