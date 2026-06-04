from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from memtest_analyzer import parse_log

def test_parse_sample_log():
    rows = parse_log(ROOT / "examples" / "sample-memtest.log")
    assert len(rows) == 4
    assert rows[0]["slot"] == "DIMM_A1"
    assert rows[-1]["status"] == "FAIL"
    assert rows[-1]["errors"] == 12
