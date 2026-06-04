# MemTest Report Analyzer

A Python-based reporting tool concept for parsing memory validation logs and generating clean technician-friendly reports.

This repository is a sanitized portfolio version focused on server memory validation workflows. It uses fake sample logs and does not include customer data, real serial numbers or company-specific output.

## Why this project exists

Memory validation work can produce logs that are difficult to review quickly. A repeatable analyzer helps convert raw test output into structured pass/fail summaries, CSV exports and clean reports.

## Features

- Parse sanitized memory test logs
- Extract DIMM slots, status and error counts
- Generate Markdown reports
- Generate CSV summaries
- Keep reports out of public Git history by default
- Provide fake sample data for safe public demonstration

## Quick start

```bash
python src/memtest_analyzer.py examples/sample-memtest.log --out reports
```

## Technology focus

- Python
- Log parsing
- CSV and Markdown report generation
- Hardware validation workflows
- Server operations automation

## Portfolio note

This project demonstrates how repetitive hardware validation evidence can be turned into clean operational reports.
