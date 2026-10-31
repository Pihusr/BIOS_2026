import json
from pathlib import Path
from typing import NoReturn

import pytest
import requests

import osv_client
import typo_inspector
from pipeline import run_scan

ROOT = Path(__file__).resolve().parents[1]


def test_ground_truth_five_cases_and_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache_path = tmp_path / "osv_cache.db"
    monkeypatch.setattr(osv_client, "CACHE_DB_PATH", cache_path)
    monkeypatch.setattr(typo_inspector, "CACHE_DB", cache_path)

    def offline(*args: object, **kwargs: object) -> NoReturn:
        raise requests.ConnectionError("offline test")

    monkeypatch.setattr(osv_client.requests, "post", offline)
    monkeypatch.setattr(typo_inspector.requests, "get", offline)

    scan = run_scan(str(ROOT / "fixtures" / "ground_truth_repo"))
    oracle = json.loads(
        (ROOT / "fixtures" / "golden" / "scan_result.json").read_text(encoding="utf-8")
    )
    reach = {finding["cve_id"]: finding for finding in scan["reach"]["findings"]}
    assert sum(f["reach_status"] == "reachable" for f in reach.values()) >= 1
    assert sum(
        f["reach_status"] == "unreachable" and f["confidence"] == 1.0
        for f in reach.values()
    ) >= 1
    assert any(f["reach_status"] == "unknown_dynamic_execution" for f in reach.values())
    assert any(flag["package"] == "reqeusts" for flag in scan["inspect"]["typo_flags"])
    assert any(
        report["package"] == "private-source-package"
        and report["has_source_repo"] is None
        for report in scan["inspect"]["provenance"]
    )
    assert scan["vex"]["ok"]
    assert scan["vex"]["metrics"]["noise_reduction_pct"] >= 50.0
    assert scan["vex"]["metrics"]["actionable_rate_pct"] == 100.0

    expected = {
        (finding["id"], finding["package"], finding["status"])
        for finding in oracle["vex"]["findings"]
    }
    findings = scan["vex"]["findings"]
    precision = (
        sum(
            (finding["id"], finding["package"], finding["status"]) in expected
            for finding in findings
        )
        / len(findings)
        if findings
        else 0.0
    )
    assert precision >= 0.90
