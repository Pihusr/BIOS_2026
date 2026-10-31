import hashlib
import json
import sqlite3
import time
from pathlib import Path

import pytest

import typo_inspector
from contracts import Package


def _package(name: str, ecosystem: str = "PyPI") -> Package:
    return {
        "name": name,
        "version": "1.0.0",
        "ecosystem": ecosystem,
        "purl": f"pkg:{ecosystem.lower()}/{name}@1.0.0",
        "scope": "direct",
        "depends_on": [],
    }


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("reqeusts", True),
        ("requets", True),
        ("requestss", True),
        ("requestx", True),
        ("flaskk", True),
        ("flaks", True),
        ("flas", True),
        ("djnago", True),
        ("djago", True),
        ("numppy", True),
        ("numpys", True),
        ("pandasx", True),
        ("pandass", True),
        ("scipyy", True),
        ("pytests", True),
        ("pytes", True),
        ("packagingg", True),
        ("packagng", True),
        ("certiffi", True),
        ("urllib4", True),
        ("f1ask", True),
        ("flаsk", True),
        ("flαsk", True),
        ("flaѕk", True),
        ("nυmpy", True),
        ("numpу", True),
        ("pаndas", True),
        ("rnarkdown-it-py", True),
        ("d0jango", True),
        ("requests", False),
        ("flask", False),
        ("numpy", False),
        ("pandas", False),
        ("django", False),
        ("scipy", False),
        ("pytest", False),
        ("packaging", False),
        ("certifi", False),
        ("urllib3", False),
        ("idna", False),
        ("typing-extensions", False),
    ],
)
def test_synthetic_typosquat_matrix(monkeypatch: pytest.MonkeyPatch, name: str, expected: bool) -> None:
    monkeypatch.setattr(typo_inspector, "_cached_get", lambda url: (None, f"offline test: {url}"))
    result = typo_inspector.inspect([_package(name)])
    assert result["ok"] is True
    flags = [flag for flag in result["typo_flags"] if flag["package"] == name]
    assert bool(flags) is expected


def test_homoglyph_flag_and_risk_scores(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(typo_inspector, "_cached_get", lambda url: (None, f"offline test: {url}"))
    result = typo_inspector.inspect([_package("f1ask"), _package("flаsk"), _package("flaks")])
    by_name = {flag["package"]: flag for flag in result["typo_flags"]}
    assert by_name["f1ask"]["matched"] == "flask"
    assert by_name["flаsk"]["matched"] == "flask"
    assert by_name["flаsk"]["homoglyph"] is True
    assert by_name["f1ask"]["homoglyph"] is True
    assert by_name["flаsk"]["risk_score"] > by_name["flaks"]["risk_score"]
    assert all(0.0 <= flag["risk_score"] <= 1.0 for flag in by_name.values())


@pytest.mark.parametrize(("ecosystem", "name"), [("PyPI", "reqeusts"), ("npm", "--can-you-instal")])
def test_10k_name_scan_finishes_under_one_second(
    monkeypatch: pytest.MonkeyPatch, ecosystem: str, name: str
) -> None:
    monkeypatch.setattr(typo_inspector, "_cached_get", lambda url: (None, f"offline test: {url}"))
    typo_inspector._top_index.cache_clear()
    started = time.perf_counter()
    result = typo_inspector.inspect([_package(name, ecosystem)])
    assert result["ok"] is True
    assert result["typo_flags"]
    assert time.perf_counter() - started < 1.0


def test_npm_top_list_flags_typos_but_not_exact_names(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(typo_inspector, "_cached_get", lambda url: (None, f"offline test: {url}"))
    result = typo_inspector.inspect(
        [_package("--can-you-instal", "npm"), _package("--can-you-install", "npm")]
    )
    assert len(result["typo_flags"]) == 1
    assert result["typo_flags"][0]["matched"] == "--can-you-install"
    assert result["typo_flags"][0]["distance"] == 1


def test_provenance_uses_cached_recorded_pypi_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cache_db = tmp_path / "osv_cache.db"
    monkeypatch.setattr(typo_inspector, "CACHE_DB", cache_db)
    recorded_json = {
        "info": {
            "project_urls": {"Source": "https://github.com/example/demo"},
            "home_page": "https://example.com/demo",
        },
        "urls": [
            {"attestations": [{"predicateType": "https://slsa.dev/provenance/v1"}]}
        ],
    }
    calls: list[str] = []

    class RecordedResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return recorded_json

    def recorded_get(url: str, timeout: int) -> RecordedResponse:
        assert timeout == 8
        calls.append(url)
        return RecordedResponse()

    monkeypatch.setattr(typo_inspector.requests, "get", recorded_get)
    package = _package("demo-package")
    first = typo_inspector.inspect([package])
    report = first["provenance"][0]
    assert report["has_source_repo"] is True
    assert report["signature_verified"] is True
    assert report["slsa_attested"] is True
    assert report["violations"] == []
    assert calls == ["https://pypi.org/pypi/demo-package/1.0.0/json"]

    def unexpected_get(url: str, timeout: int) -> RecordedResponse:
        raise AssertionError(f"fresh cache should avoid HTTP for {url} (timeout={timeout})")

    monkeypatch.setattr(typo_inspector.requests, "get", unexpected_get)
    second = typo_inspector.inspect([package])
    assert second["provenance"][0] == report

    key = hashlib.sha256(f"GET{calls[0]}".encode("utf-8")).hexdigest()
    with sqlite3.connect(cache_db) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(http_cache)")]
        cached = connection.execute(
            "SELECT body, fetched_at FROM http_cache WHERE key = ?", (key,)
        ).fetchone()
    assert columns == ["key", "body", "fetched_at"]
    assert cached is not None
    assert json.loads(cached[0]) == recorded_json


def test_missing_provenance_is_reported_as_false(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(typo_inspector, "CACHE_DB", tmp_path / "osv_cache.db")
    recorded_json = {"info": {"project_urls": {"Homepage": "https://example.com"}}, "urls": []}

    class RecordedResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return recorded_json

    def recorded_get(url: str, timeout: int) -> RecordedResponse:
        assert url == "https://pypi.org/pypi/no-source-project/1.0.0/json"
        assert timeout == 8
        return RecordedResponse()

    monkeypatch.setattr(typo_inspector.requests, "get", recorded_get)
    report = typo_inspector.inspect([_package("no-source-project")])["provenance"][0]
    assert report["has_source_repo"] is False
    assert report["signature_verified"] is False
    assert report["slsa_attested"] is False
    assert {"missing_source_repo", "no_attestation", "no_slsa_provenance"} == set(report["violations"])


def test_unavailable_registry_metadata_stays_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(typo_inspector, "_cached_get", lambda url: (None, f"offline test: {url}"))
    result = typo_inspector.inspect([_package("offline-project")])
    report = result["provenance"][0]
    assert result["ok"] is True
    assert report["has_source_repo"] is None
    assert report["signature_verified"] is None
    assert report["slsa_attested"] is None
    assert report["violations"] == []
    assert result["warnings"]


def test_invalid_input_returns_safe_inspect_result() -> None:
    result = typo_inspector.inspect([{"name": "missing-fields"}])  # type: ignore[list-item]
    assert result["ok"] is False
    assert result["error"]
    assert result["typo_flags"] == []
    assert result["provenance"] == []
