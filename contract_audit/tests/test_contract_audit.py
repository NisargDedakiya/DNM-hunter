"""Tests for the Solidity smart-contract scanner (contract_audit).

Run: python -m unittest contract_audit.tests.test_contract_audit -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from contract_audit import scan_contract


def rules(f):
    return {x.rule_id for x in f}


_VULN = '''
pragma solidity ^0.7.0;
contract Bank {
    address owner;
    mapping(address => uint) balances;

    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;          // state write AFTER external call
    }

    function login(address who) public {
        require(tx.origin == owner);             // tx.origin auth
    }

    function kill() public {
        selfdestruct(payable(msg.sender));       // unguarded selfdestruct
    }

    function setOwner(address n) public {        // unprotected owner setter
        owner = n;
    }

    function proxy(address target, bytes memory data) public {
        target.delegatecall(data);               // arbitrary delegatecall
    }

    function pay(address to) public {
        to.call{value: 1 ether}("");             // unchecked low-level call
    }
}
'''

_SAFE = '''
pragma solidity ^0.8.19;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract Safe is ReentrancyGuard {
    address owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }

    function withdraw(uint amount) public nonReentrant {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
    function setOwner(address n) public onlyOwner { owner = n; }
    function kill() public onlyOwner { selfdestruct(payable(owner)); }
}
'''


class TestDetection(unittest.TestCase):
    def test_detects_core_classes(self):
        got = rules(scan_contract(_VULN, "Bank.sol"))
        for r in ("SC-REENTRANCY", "SC-TXORIGIN", "SC-SELFDESTRUCT",
                  "SC-UNPROTECTED-OWNER", "SC-DELEGATECALL", "SC-OVERFLOW"):
            self.assertIn(r, got, f"{r} should be detected")

    def test_reentrancy_is_critical_with_vrt(self):
        f = [x for x in scan_contract(_VULN, "Bank.sol") if x.rule_id == "SC-REENTRANCY"][0]
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.vrt, "smart_contract.reentrancy")
        self.assertEqual(f.swc, "SWC-107")


class TestPrecision(unittest.TestCase):
    def test_guarded_contract_is_quiet(self):
        got = rules(scan_contract(_SAFE, "Safe.sol"))
        self.assertNotIn("SC-REENTRANCY", got)      # has nonReentrant
        self.assertNotIn("SC-SELFDESTRUCT", got)    # onlyOwner
        self.assertNotIn("SC-UNPROTECTED-OWNER", got)  # onlyOwner
        self.assertNotIn("SC-OVERFLOW", got)        # 0.8 pragma

    def test_comment_reentrancy_not_flagged(self):
        code = "pragma solidity ^0.8.0;\ncontract C { // msg.sender.call then balances -= x\n uint x; }"
        self.assertNotIn("SC-REENTRANCY", rules(scan_contract(code, "C.sol")))


if __name__ == "__main__":
    unittest.main()
