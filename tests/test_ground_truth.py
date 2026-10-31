import json
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]

@pytest.mark.xfail(reason="Integration is not implemented; golden benchmark remains a stub")
def test_ground_truth_five_cases_and_metrics():
    scan = json.loads((ROOT / "fixtures/golden/scan_result.json").read_text(encoding="utf-8"))
    reach = {finding["cve_id"]: finding for finding in scan["reach"]["findings"]}
    assert sum(f["reach_status"] == "reachable" for f in reach.values()) >= 1
    assert sum(f["reach_status"] == "unreachable" and f["confidence"] == 1.0 for f in reach.values()) >= 1
    assert any(f["reach_status"] == "unknown_dynamic_execution" for f in reach.values())
    assert any(flag["package"] == "reqeusts" for flag in scan["inspect"]["typo_flags"])
    assert any(report["package"] == "private-source-package" and report["has_source_repo"] is None for report in scan["inspect"]["provenance"])
    assert scan["vex"]["metrics"]["noise_reduction_pct"] >= 50.0
    assert scan["vex"]["metrics"]["actionable_rate_pct"] == 100.0
