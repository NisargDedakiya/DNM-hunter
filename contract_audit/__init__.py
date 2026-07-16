"""Solidity smart-contract static scanner — VRT-mapped detection of the
Smart Contract Misconfiguration classes (reentrancy, owner takeover, unchecked
calls, delegatecall, selfdestruct, integer overflow, uninitialized storage,
weak randomness).
"""
from .scanner import ContractFinding, scan_contract, scan_tree

__all__ = ["ContractFinding", "scan_contract", "scan_tree"]
