"""Console summary and JSON report writer (local output directory only)."""
import json
import os
from datetime import datetime

from .rules import SEVERITY_ORDER


def print_summary(findings):
    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER[f["severity"]])
    print("\n{:<8} {:<7} {:<34} {}".format("SEV", "ID", "FILE", "FINDING"))
    print("-" * 90)
    for f in ordered:
        print("{:<8} {:<7} {:<34} {}".format(
            f["severity"], f["rule_id"], f["file"][-34:], f["title"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    print("-" * 90)
    print("Totals: " + "  ".join(f"{s}={n}" for s, n in counts.items()))
    return counts


def write_report(target, findings, stats, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"apkscan_report_{datetime.now():%Y%m%d_%H%M%S}.json")
    report = {
        "tool": "KeyHound",
        "note": "Local report. Secret values are masked. Handle per README disclosure guidance.",
        "target": target,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "stats": stats,
        "findings": findings,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    return path
