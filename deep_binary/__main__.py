"""CLI: python -m deep_binary <binary> [--reach SYMBOL_OR_ADDR] [--hijack] [--json]"""
import argparse
import json
import sys

from . import HAVE_ANGR, reach_target, find_control_hijack


def main() -> int:
    ap = argparse.ArgumentParser(description="Deep binary analysis (symbolic execution via angr).")
    ap.add_argument("binary")
    ap.add_argument("--reach", help="symbol name or 0xADDR to solve an input for")
    ap.add_argument("--hijack", action="store_true", help="search for a control-flow-hijack (memory corruption)")
    ap.add_argument("--timeout", type=float, default=45.0)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not HAVE_ANGR:
        print("angr is not installed — run: pip install angr", file=sys.stderr)
        return 2

    out = {}
    if args.reach:
        target = int(args.reach, 16) if args.reach.lower().startswith("0x") else args.reach
        out["reach"] = reach_target(args.binary, target, timeout_s=args.timeout).to_dict()
    if args.hijack:
        out["hijack"] = find_control_hijack(args.binary, timeout_s=args.timeout).to_dict()
    if not out:
        ap.error("specify --reach and/or --hijack")

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        for k, v in out.items():
            print(f"{k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
