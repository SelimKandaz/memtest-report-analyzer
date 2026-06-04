#!/usr/bin/env python3
import argparse
import csv
import re
from pathlib import Path
from datetime import datetime

DIMM_RE = re.compile(r"^(DIMM_[A-Z]\d+)\s+(\S+)\s+(\S+)\s+(PASS|FAIL)\s+errors=(\d+)", re.IGNORECASE)

def parse_log(path: Path):
    dimms = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = DIMM_RE.match(line.strip())
        if not m:
            continue
        slot, capacity, mem_type, status, errors = m.groups()
        dimms.append({
            "slot": slot,
            "capacity": capacity,
            "memory_type": mem_type,
            "status": status.upper(),
            "errors": int(errors),
        })
    return dimms

def write_csv(rows, out_path: Path):
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["slot", "capacity", "memory_type", "status", "errors"])
        writer.writeheader()
        writer.writerows(rows)

def write_markdown(rows, out_path: Path, source: Path):
    passed = sum(1 for r in rows if r["status"] == "PASS")
    failed = sum(1 for r in rows if r["status"] == "FAIL")
    lines = [
        "# MemTest Analysis Report",
        "",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"Source: {source.name}",
        "",
        "## Summary",
        "",
        f"- Total DIMMs: {len(rows)}",
        f"- Passed: {passed}",
        f"- Failed: {failed}",
        "",
        "## DIMM Results",
        "",
        "| Slot | Capacity | Type | Status | Errors |",
        "|---|---:|---|---|---:|",
    ]
    for r in rows:
        lines.append(f"| {r['slot']} | {r['capacity']} | {r['memory_type']} | {r['status']} | {r['errors']} |")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

def main():
    parser = argparse.ArgumentParser(description="Parse sanitized MemTest logs and generate reports.")
    parser.add_argument("log_file", type=Path)
    parser.add_argument("--out", type=Path, default=Path("reports"))
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    rows = parse_log(args.log_file)
    if not rows:
        raise SystemExit("No DIMM result lines found.")

    write_csv(rows, args.out / "memtest-summary.csv")
    write_markdown(rows, args.out / "memtest-report.md", args.log_file)
    print(f"Generated reports in {args.out}")

if __name__ == "__main__":
    main()
