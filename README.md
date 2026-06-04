# MemTest Report Analyzer

A Python toolset for parsing memory validation logs and generating technician-friendly reports.

This repository now includes two layers:

1. `src/memtest_analyzer.py`  
   A small CLI parser for sanitized demo logs.

2. `src/memtest_analyzer_pro.py`  
   The original full desktop GUI MemTest Analyzer Pro application, sanitized for public open-source use.

## Full GUI application

Run the desktop analyzer:

```bash
pip install -r requirements.txt
python src/memtest_analyzer_pro.py
```

The GUI supports:

- Loading MemTest-style log files
- Parsing system information
- Parsing DIMM population details
- Detecting pass/fail/error summary
- Exporting CSV
- Exporting JSON
- Exporting PDF reports when ReportLab is installed
- Optional watermark logo when Pillow is installed and a local image is selected

## CLI demo analyzer

```bash
python src/memtest_analyzer.py examples/sample-memtest.log --out reports
```

Generated files:

```text
reports/
  memtest-summary.csv
  memtest-report.md
```

## Requirements

```bash
pip install -r requirements.txt
```

## Test

```bash
python -m pytest
```

## Open-source note

This project is published as a sanitized open-source memory-reporting utility. It contains fake sample data only. Do not commit real customer logs, real server serial numbers, internal validation reports or private screenshots.

## License

MIT
