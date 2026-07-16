# contract_audit — Solidity Smart-Contract Scanner

Static detection of the **Smart Contract Misconfiguration** VRT rows from
Solidity source. Each finding carries its VRT id and the matching
[SWC registry](https://swcregistry.io) id.

## What it detects

| Rule | VRT | SWC | Sev | Class |
|------|-----|-----|-----|-------|
| SC-REENTRANCY | `smart_contract.reentrancy` | SWC-107 | critical | State write after an external value call, no guard |
| SC-DELEGATECALL | `smart_contract.owner_takeover` | SWC-112 | critical | `delegatecall` to a caller-influenced target |
| SC-SELFDESTRUCT | `smart_contract.owner_takeover` | SWC-106 | critical | `selfdestruct` with no access-control guard |
| SC-TXORIGIN | `smart_contract.owner_takeover` | SWC-115 | high | Authorization via `tx.origin` |
| SC-UNPROTECTED-OWNER | `smart_contract.owner_takeover` | SWC-105 | high | Public ownership/mint/withdraw/upgrade setter, no guard |
| SC-OVERFLOW | `smart_contract.integer_overflow` | SWC-101 | high | Arithmetic on pre-0.8 pragma without SafeMath |
| SC-UNCHECKED-CALL | `smart_contract.unauthorized_transfer` | SWC-104 | medium | Ignored low-level `.call`/`.send` return |
| SC-UNINIT-STORAGE | `smart_contract.uninitialized_variables` | SWC-109 | medium | Uninitialized storage pointer |
| SC-WEAK-RANDOM | `smart_contract.malicious_superuser_risk` | SWC-120 | medium | Block properties used as randomness |

## Precision

- **Reentrancy** requires an external value-moving call *followed by* a state
  write within a short window **and** the absence of a `nonReentrant` /
  `ReentrancyGuard`. A contract that uses OpenZeppelin's guard, or follows
  checks-effects-interactions, is not flagged.
- **selfdestruct / ownership setters** look back to the enclosing function for an
  access modifier (`onlyOwner`, …) or an inline `require(msg.sender == …)` and
  only fire when none is present.
- **Integer overflow** only fires on a `pragma solidity <0.8` that lacks
  SafeMath — 0.8+ has checked arithmetic built in.
- Comments and block comments are stripped before analysis.

## Honest scope

This is heuristic source analysis — it does **not** compile the contract or run
symbolic execution, so it will not find economic-logic bugs (price/oracle
manipulation, flash-loan accounting, governance flaws), cross-contract
invariants, or proxy-storage-collision issues. Those DeFi/marketplace VRT rows
are marked `manual` in the platform's VRT coverage map. What this catches is the
well-known structural anti-patterns that dominate real audit findings.

## Usage

```bash
python -m contract_audit path/to/contracts --json
```

Also runs automatically inside `repo_scan` (kind `smart-contract`).
