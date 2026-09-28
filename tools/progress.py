#!/usr/bin/env python3

###
# Prints a progress summary from an objdiff report.
#
# Usage:
#   python3 tools/progress.py build/report.json
###

import json
import sys


def pct(measures: dict, key: str) -> float:
    return float(measures.get(key, 0) or 0)


def line(name: str, m: dict) -> str:
    total_code = int(m.get("total_code", 0) or 0)
    matched_code = int(m.get("matched_code", 0) or 0)
    total_funcs = int(m.get("total_functions", 0) or 0)
    matched_funcs = int(m.get("matched_functions", 0) or 0)
    return (
        f"{name:<10} code {pct(m, 'matched_code_percent'):6.2f}% ({matched_code}/{total_code} bytes)"
        f"  fuzzy {pct(m, 'fuzzy_match_percent'):6.2f}%"
        f"  functions {matched_funcs}/{total_funcs}"
        f"  data {pct(m, 'matched_data_percent'):6.2f}%"
    )


def main() -> None:
    with open(sys.argv[1], encoding="utf-8") as f:
        report = json.load(f)

    print(line("all", report.get("measures", {})))
    for cat in report.get("categories", []):
        print(line(cat.get("id", "?"), cat.get("measures", {})))


if __name__ == "__main__":
    main()
