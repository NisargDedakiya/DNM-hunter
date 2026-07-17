"""Solidity smart-contract static scanner — the Smart Contract Misconfiguration
and Decentralized Application VRT rows.

Detects the classic on-chain bug classes from source: reentrancy (state written
after an external call), authorization via tx.origin, unchecked low-level call
return values, arbitrary/user-controlled delegatecall, selfdestruct reachable
without an owner guard, unprotected ownership/critical setters, integer
overflow exposure (pre-0.8 pragma without SafeMath), uninitialized storage
pointers, block-timestamp/blockhash used as randomness, and a public/absent
constructor owner takeover shape.

This is line/heuristic analysis over Solidity source — it does not compile or
symbolically execute — so it finds the recognisable anti-patterns a reviewer
triages first. Every finding carries a VRT id.

CLI:  python -m contract_audit <path-or-dir> [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

CRIT, HIGH, MED, LOW = "critical", "high", "medium", "low"
_SKIP_DIRS = {".git", "node_modules", "lib", "out", "artifacts", "cache", "build"}


@dataclass
class ContractFinding:
    vrt: str
    rule_id: str
    severity: str
    title: str
    file: str
    line: int
    detail: str
    swc: str = ""      # SWC registry id where applicable

    def to_dict(self) -> dict:
        return asdict(self)


# external-call patterns that move value / hand control to another contract
_EXTERNAL_CALL = re.compile(r"\.(call|delegatecall|callcode)\s*[\{（(]|\.(send|transfer)\s*\(|\.call\.value\s*\(")
_STATE_WRITE = re.compile(r"^\s*[A-Za-z_]\w*(\[[^\]]*\])?\s*(=|[-+]=)\s*")
_LOWLEVEL_CALL = re.compile(r"\.(call|delegatecall|callcode|send)\s*[\{（(]")


def _strip_comments(text: str) -> list[str]:
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.DOTALL)
    out = []
    for raw in text.splitlines():
        out.append(raw.split("//", 1)[0])
    return out


def _pragma_major_minor(text: str):
    m = re.search(r"pragma\s+solidity\s+[^\d]*?(\d+)\.(\d+)", text)
    return (int(m.group(1)), int(m.group(2))) if m else None


def scan_contract(text: str, file: str) -> list[ContractFinding]:
    findings: list[ContractFinding] = []
    lines = _strip_comments(text)

    def add(vrt, rule, sev, title, i, detail, swc=""):
        findings.append(ContractFinding(vrt, rule, sev, title, file, i, detail, swc))

    has_safemath = bool(re.search(r"\b(SafeMath|using\s+SafeMath)\b", text))
    has_reentrancy_guard = bool(re.search(r"(nonReentrant|ReentrancyGuard)", text))
    pragma = _pragma_major_minor(text)

    # ── file-level: integer overflow exposure (pre-0.8 without SafeMath) ──
    if pragma and (pragma[0], pragma[1]) < (0, 8) and not has_safemath:
        if re.search(r"[+\-*]\s*=|\b\w+\s*[+\-*]\s*\w+", text):
            ln = next((i for i, pl in enumerate(lines, 1) if "pragma" in pl), 1)
            add("smart_contract.integer_overflow", "SC-OVERFLOW", HIGH,
                "Arithmetic without SafeMath on Solidity <0.8 (integer overflow/underflow)",
                ln, "Compiler <0.8 does not check arithmetic; unchecked math can overflow/underflow. "
                "Use Solidity >=0.8 or SafeMath.", "SWC-101")

    for i, line in enumerate(lines, 1):
        s = line.strip()
        if not s:
            continue

        # ── reentrancy: external value call followed by a state write, no guard ──
        if _EXTERNAL_CALL.search(line) and not has_reentrancy_guard:
            for j in range(i, min(i + 6, len(lines))):
                if _STATE_WRITE.match(lines[j]) and "require" not in lines[j]:
                    add("smart_contract.reentrancy", "SC-REENTRANCY", CRIT,
                        "State updated after an external call (reentrancy)", i,
                        "An external call is made before contract state is finalised and no reentrancy "
                        "guard is present — follow checks-effects-interactions or add nonReentrant.",
                        "SWC-107")
                    break

        # ── tx.origin used for authorization ──
        if re.search(r"require\s*\(\s*tx\.origin\s*==|tx\.origin\s*==\s*owner|if\s*\(\s*tx\.origin", line):
            add("smart_contract.owner_takeover", "SC-TXORIGIN", HIGH,
                "Authorization via tx.origin (phishing-based takeover)", i,
                "tx.origin authenticates the transaction origin, not the caller — a malicious "
                "intermediate contract bypasses it. Use msg.sender.", "SWC-115")

        # ── unchecked low-level call return value ──
        if _LOWLEVEL_CALL.search(line):
            ctx = " ".join(lines[max(0, i - 2):i + 1])
            assigned = bool(re.search(r"\(\s*bool\s+\w+|\bsuccess\b|=\s*[A-Za-z_]\w*\.call|require\s*\(", ctx))
            if not assigned:
                add("smart_contract.unauthorized_transfer", "SC-UNCHECKED-CALL", MED,
                    "Return value of a low-level call is ignored", i,
                    "A failed .call/.send is silently ignored — check the boolean return or use a "
                    "checked transfer to avoid funds/logic desync.", "SWC-104")

        # ── arbitrary delegatecall to a user-controlled target ──
        dm = re.search(r"(\w+)\.delegatecall\s*[\{（(]", line)
        if dm:
            receiver = dm.group(1)
            controllable = bool(re.search(r"(target|^to$|addr|impl|dest|proxy|dst)", receiver, re.IGNORECASE)) \
                or bool(re.search(r"delegatecall\s*\(\s*(msg\.data|_?data\b)", line))
            if controllable:
                add("smart_contract.owner_takeover", "SC-DELEGATECALL", CRIT,
                    "delegatecall to a caller-influenced address (arbitrary code execution / storage takeover)", i,
                    "delegatecall runs external code in this contract's storage context; a controllable "
                    "target lets an attacker rewrite storage (including ownership).", "SWC-112")

        # ── selfdestruct without an owner/modifier guard on the same function ──
        if re.search(r"\bselfdestruct\s*\(|\bsuicide\s*\(", line):
            # look back for a function signature with an access modifier
            guarded = False
            for j in range(i - 1, max(0, i - 25), -1):
                lj = lines[j - 1]
                if re.search(r"\bfunction\b", lj):
                    guarded = bool(re.search(r"\b(onlyOwner|onlyAdmin|onlyGovernance|auth|restricted)\b", lj)) \
                        or any(re.search(r"require\s*\(\s*msg\.sender\s*==", lines[k]) for k in range(j, i))
                    break
            if not guarded:
                add("smart_contract.owner_takeover", "SC-SELFDESTRUCT", CRIT,
                    "selfdestruct reachable without an access-control guard", i,
                    "An unguarded selfdestruct lets anyone destroy the contract and sweep its balance. "
                    "Gate it behind onlyOwner / access control.", "SWC-106")

        # ── unprotected ownership / critical state setter ──
        if re.search(r"\bfunction\b.*\b(setOwner|transferOwnership|changeOwner|setAdmin|initialize|mint|withdraw|setImplementation|upgradeTo)\b", line, re.IGNORECASE):
            if re.search(r"\bpublic\b|\bexternal\b", line) and not re.search(r"\b(onlyOwner|onlyAdmin|onlyGovernance|auth|restricted|internal|private)\b", line):
                # confirm no in-body msg.sender check in the next few lines
                body = " ".join(lines[i:i + 6])
                if "msg.sender" not in body and "require" not in body:
                    add("smart_contract.owner_takeover", "SC-UNPROTECTED-OWNER", HIGH,
                        "Critical/ownership function is externally callable without access control", i,
                        "A privileged setter (ownership/mint/withdraw/upgrade) is public/external with no "
                        "owner guard — anyone can invoke it (contract owner takeover).", "SWC-105")

        # ── uninitialized storage pointer (pre-0.5 footgun) ──
        if re.search(r"\b(struct\s+\w+|[A-Z]\w*)\s+storage\s+\w+\s*;", line):
            add("smart_contract.uninitialized_variables", "SC-UNINIT-STORAGE", MED,
                "Uninitialized storage pointer", i,
                "A storage reference declared without initialisation can alias slot 0 and corrupt "
                "state. Initialise it or use memory.", "SWC-109")

        # ── block values used as randomness ──
        if re.search(r"\b(block\.(timestamp|number|difficulty|prevrandao)|now|blockhash\s*\()", line) and \
           re.search(r"\b(random|rand|winner|seed|lottery|draw|dice|roll)\b", line, re.IGNORECASE):
            add("smart_contract.malicious_superuser_risk", "SC-WEAK-RANDOM", MED,
                "Block properties used as a randomness source (miner-manipulable)", i,
                "block.timestamp/blockhash are influenceable by validators — do not use them for "
                "randomness in value-bearing logic; use a VRF/commit-reveal.", "SWC-120")

    return findings


def scan_tree(root: str | Path) -> list[ContractFinding]:
    root = Path(root)
    out: list[ContractFinding] = []
    if root.is_file():
        return scan_contract(root.read_text(errors="replace"), str(root))
    for path in root.rglob("*.sol"):
        if any(p in _SKIP_DIRS for p in path.parts):
            continue
        try:
            text = path.read_text(errors="replace")
        except Exception:
            continue
        out.extend(scan_contract(text, str(path.relative_to(root))))
    return out


def _main() -> int:
    ap = argparse.ArgumentParser(description="Solidity smart-contract static scanner (VRT-mapped).")
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    findings = scan_tree(args.path)
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return 0
    for f in sorted(findings, key=lambda x: x.severity):
        print(f"  [{f.severity:8}] {f.rule_id:20} {f.file}:{f.line}  {f.title}")
    print(f"\n{len(findings)} findings")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
