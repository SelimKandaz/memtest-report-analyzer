# MemTest Report Analyzer

A Python-based reporting tool for parsing memory validation logs and generating clean technician-friendly reports.

This repository is a sanitized portfolio version focused on server memory validation workflows. It uses fake sample logs and does not include customer data, real serial numbers or company-specific output.

## Features

- Parse sanitized memory test logs
- Extract DIMM slots, capacity, type, status and error counts
- Generate Markdown reports
- Generate CSV summaries
- Keep generated reports out of public Git history by default
- Provide fake sample data for safe public demonstration

## Quick start

```bash
python src/memtest_analyzer.py examples/sample-memtest.log --out reports
```

Generated files:

```text
reports/
  memtest-summary.csv
  memtest-report.md
```

## Test

```bash
python -m pytest
```

The tool itself uses only the Python standard library. `pytest` is only needed for tests.

## Technology focus

Python, log parsing, CSV/Markdown report generation, hardware validation workflows and server operations automation.
