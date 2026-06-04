# Customization Guide

This project can be adapted to different memory validation log formats.

## Common customization points

- Parser patterns
- DIMM slot naming
- Pass/fail rules
- Report title
- PDF layout
- Export filename format
- Optional logo/watermark

## Start here

- `src/memtest_analyzer.py` for the lightweight CLI parser
- `src/memtest_analyzer_pro.py` for the full GUI analyzer
- `examples/sample-memtest.log` for a simple sample

## Keep local

Keep private validation logs and generated reports outside the repository.
