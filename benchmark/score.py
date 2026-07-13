#!/usr/bin/env python3
"""Score a real NisargHunter AI scan against the guinea-pig ground truth.

Turns "can it find P3+ vulnerabilities?" into a measured number: given the
findings a real end-to-end scan produced, this reports recall overall, per
Bugcrowd P-tier, and per target, plus the exact list of misses.

Usage
-----
    # after a real scan, export the tool's findings to JSON (see README), then:
    python benchmark/score.py --findings findings.json
    python benchmark/score.py --findings findings.json --target dvws-node
    python benchmark/score.py --self-test          # verify the scorer itself

Findings JSON contract
----------------------
A JSON array of finding objects. Field names are matched leniently; these are
recognized (first present wins):
    target:   target | targetName | project
    category: category | type | vulnClass
    title:    title | name | rule | ruleId
    severity: severity
    endpoint: endpoint | url | path | affectedUrl
A finding matches a ground-truth item when its category equals the item's
category OR any of the item's keywords appears in the finding's title/category,
AND (when both the item and the finding carry an endpoint) the item's endpoint
substring appears in the finding's endpoint.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pyyaml is required: pip install pyyaml")

_GT_PATH = Path(__file__).parent / "ground_truth.yaml"
_P_ORDER = ["P1", "P2", "P3", "P4", "P5"]


def load_ground_truth(path: Path = _GT_PATH) -> dict:
    return yaml.safe_load(path.read_text())


def _field(obj: dict, *names: str) -> str:
    for n in names:
        v = obj.get(n)
        if v:
            return str(v)
    return ""


def _finding_matches(item: dict, finding: dict) -> bool:
    f_cat = _field(finding, "category", "type", "vulnClass").lower()
    f_title = _field(finding, "title", "name", "rule", "ruleId").lower()
    f_endpoint = _field(finding, "endpoint", "url", "path", "affectedUrl").lower()

    # 1) category or keyword signal
    signal = False
    if f_cat and f_cat == str(item.get("category", "")).lower():
        signal = True
    if not signal:
        hay = f"{f_title} {f_cat}"
        for kw in item.get("keywords", []):
            if kw.lower() in hay:
                signal = True
                break
    if not signal:
        return False

    # 2) endpoint constraint (only when both sides carry one)
    want_ep = str(item.get("endpoint", "")).lower()
    if want_ep and f_endpoint:
        return want_ep in f_endpoint
    return True


def score(ground_truth: dict, findings: list[dict], only_target: str | None = None) -> dict:
    targets = ground_truth["targets"]
    hits, misses = [], []
    matched_finding_ids = set()

    for tname, tdata in targets.items():
        if only_target and tname != only_target:
            continue
        for item in tdata["items"]:
            found = False
            for i, f in enumerate(findings):
                # honor an explicit target field when present
                f_target = _field(f, "target", "targetName", "project").lower()
                if f_target and tname.replace("_", "-") not in f_target and tname not in f_target:
                    continue
                if _finding_matches(item, f):
                    found = True
                    matched_finding_ids.add(i)
            (hits if found else misses).append({**item, "target": tname})

    additional = [f for i, f in enumerate(findings) if i not in matched_finding_ids]

    def by_tier(rows):
        out = {p: 0 for p in _P_ORDER}
        for r in rows:
            out[r.get("p_tier", "P5")] = out.get(r.get("p_tier", "P5"), 0) + 1
        return out

    return {
        "hits": hits,
        "misses": misses,
        "additional": additional,
        "hit_tiers": by_tier(hits),
        "total_tiers": by_tier(hits + misses),
    }


def render(result: dict, ground_truth: dict) -> str:
    labels = ground_truth.get("p_tier_labels", {})
    total = len(result["hits"]) + len(result["misses"])
    found = len(result["hits"])
    lines = []
    lines.append("=" * 64)
    lines.append("  NisargHunter AI — guinea-pig vulnerability recall")
    lines.append("=" * 64)
    lines.append(f"  Overall recall: {found}/{total} "
                 f"({(100 * found / total if total else 0):.0f}%)")
    lines.append("")
    lines.append("  By severity (Bugcrowd P-tier):")
    p3plus_found = p3plus_total = 0
    for p in _P_ORDER:
        t = result["total_tiers"].get(p, 0)
        h = result["hit_tiers"].get(p, 0)
        if t == 0:
            continue
        if p in ("P1", "P2", "P3"):
            p3plus_found += h
            p3plus_total += t
        pct = f"{(100 * h / t):.0f}%" if t else "—"
        lines.append(f"    {p} ({labels.get(p, p):13}) {h}/{t}  {pct}")
    lines.append("")
    lines.append(f"  >>> P3+ (medium and up) recall: {p3plus_found}/{p3plus_total} "
                 f"({(100 * p3plus_found / p3plus_total if p3plus_total else 0):.0f}%)")
    lines.append("")
    if result["misses"]:
        lines.append(f"  Missed ({len(result['misses'])}):")
        for m in result["misses"]:
            lines.append(f"    - [{m['p_tier']}] {m['target']}: {m['name']}")
    else:
        lines.append("  Missed: none 🎉")
    lines.append("")
    lines.append(f"  Additional findings not in the catalog: {len(result['additional'])} "
                 f"(review manually — could be extra true positives or FPs)")
    lines.append("=" * 64)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# self-test: prove the scorer logic without a live scan
# --------------------------------------------------------------------------- #
def _self_test() -> int:
    gt = load_ground_truth()
    all_items = [it for t in gt["targets"].values() for it in t["items"]]

    # A "perfect" scanner: emit one finding per ground-truth item.
    perfect = [{"category": it["category"], "title": it["name"], "endpoint": it.get("endpoint", "")}
               for it in all_items]
    r = score(gt, perfect)
    assert len(r["misses"]) == 0, f"perfect run should miss nothing, missed {len(r['misses'])}"

    # A "partial" scanner: only the P1s.
    p1 = [f for f, it in zip(perfect, all_items) if it["p_tier"] == "P1"]
    r2 = score(gt, p1)
    assert r2["hit_tiers"]["P1"] > 0
    assert r2["hit_tiers"]["P4"] == 0, "partial run should not hit P4s"

    # An empty scanner: zero recall.
    r3 = score(gt, [])
    assert len(r3["hits"]) == 0 and len(r3["misses"]) == len(all_items)

    print("self-test OK:")
    print(f"  perfect run  -> {len(r['hits'])}/{len(all_items)} recall (expected full)")
    print(f"  P1-only run  -> P1 {r2['hit_tiers']['P1']} hits, P4 {r2['hit_tiers']['P4']} hits (expected P4=0)")
    print(f"  empty run    -> {len(r3['hits'])} hits (expected 0)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", help="path to the scan findings JSON")
    ap.add_argument("--target", help="score only this target (e.g. dvws-node)")
    ap.add_argument("--self-test", action="store_true", help="verify the scorer itself and exit")
    ap.add_argument("--min-p3-recall", type=float, default=None,
                    help="exit non-zero if P3+ recall is below this percent (for CI)")
    args = ap.parse_args()

    if args.self_test:
        return _self_test()
    if not args.findings:
        ap.error("--findings is required (or use --self-test)")

    gt = load_ground_truth()
    findings = json.loads(Path(args.findings).read_text())
    if isinstance(findings, dict):  # tolerate {"findings": [...]}
        findings = findings.get("findings", findings.get("remediations", []))
    result = score(gt, findings, only_target=args.target)
    print(render(result, gt))

    if args.min_p3_recall is not None:
        p3f = sum(result["hit_tiers"][p] for p in ("P1", "P2", "P3"))
        p3t = sum(result["total_tiers"][p] for p in ("P1", "P2", "P3"))
        pct = 100 * p3f / p3t if p3t else 0
        if pct < args.min_p3_recall:
            print(f"\nFAIL: P3+ recall {pct:.0f}% < required {args.min_p3_recall:.0f}%")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
