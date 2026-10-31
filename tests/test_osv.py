import json
import sqlite3
import time
from pathlib import Path

import pytest
import requests

import osv_client

PAYLOAD = {
    "vulns": [
        {
            "id": "GHSA-abcd-efgh-ijkl",
            "aliases": ["GHSA-abcd-efgh-ijkl", "CVE-2024-11111"],
            "summary": "Recorded test advisory",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            ],
            "database_specific": {"severity": "MEDIUM"},
            "affected": [
                {
                    "package": {"name": "demo-package", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                        }
                    ],
                }
            ],
        }
    ]
}


@pytest.fixture
def cache_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "osv_cache.db"
    monkeypatch.setattr(osv_client, "CACHE_DB_PATH", path)
    return path


def _seed_cache(
    path: Path,
    payload: object,
    name: str = "demo-package",
    version: str = "1.0.0",
    fetched_at: float | None = None,
) -> None:
    request_body = json.dumps(
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": version},
        sort_keys=True,
        separators=(",", ":"),
    )
    key = osv_client._cache_key("POST", osv_client.OSV_QUERY_URL, request_body)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE http_cache (key TEXT PRIMARY KEY, body TEXT, fetched_at REAL)"
        )
        connection.execute(
            "INSERT INTO http_cache (key, body, fetched_at) VALUES (?, ?, ?)",
            (key, json.dumps(payload), fetched_at if fetched_at is not None else time.time()),
        )


def test_query_osv_cache_hit_parses_advisory(cache_db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_cache(cache_db, PAYLOAD)

    def fail_if_requested(*args: object, **kwargs: object) -> None:
        pytest.fail("cache hit unexpectedly made an HTTP request")

    monkeypatch.setattr(osv_client.requests, "post", fail_if_requested)
    result = osv_client.query_osv("demo-package", "1.0.0")

    assert result["ok"] is True
    assert result["advisories"] == [
        {
            "cve_id": "CVE-2024-11111",
            "osv_id": "GHSA-abcd-efgh-ijkl",
            "package": "demo-package",
            "version": "1.0.0",
            "summary": "Recorded test advisory",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "fixed_in": ["2.0.0"],
        }
    ]


def test_query_osv_empty_object_is_successful_no_advisories(
    cache_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class EmptyResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> object:
            return {}

    monkeypatch.setattr(
        osv_client.requests, "post", lambda *args, **kwargs: EmptyResponse()
    )
    result = osv_client.query_osv("demo-package", "1.0.0")

    assert result["ok"] is True
    assert result["error"] is None
    assert result["advisories"] == []


def test_query_osv_rejects_json_that_is_not_an_object(
    cache_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class NonObjectResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> object:
            return []

    monkeypatch.setattr(
        osv_client.requests, "post", lambda *args, **kwargs: NonObjectResponse()
    )
    result = osv_client.query_osv("demo-package", "1.0.0")

    assert result["ok"] is False
    assert "must be an object" in (result["error"] or "")
    assert result["advisories"] == []


def test_parse_advisories_deduplicates_overlapping_osv_aliases() -> None:
    payload = {
        "vulns": [
            {
                "id": "GHSA-abcd-efgh-ijkl",
                "aliases": ["CVE-2024-11111", "PYSEC-2024-1"],
            },
            {
                "id": "PYSEC-2024-1",
                "aliases": ["CVE-2024-11111", "GHSA-abcd-efgh-ijkl"],
            },
        ]
    }

    advisories = osv_client._parse_advisories(payload, "demo-package", "1.0.0")

    assert len(advisories) == 1
    assert advisories[0]["cve_id"] == "CVE-2024-11111"


def test_dedupe_advisories_uses_shared_aliases() -> None:
    advisories = [
        {"cve_id": "CVE-2024-11111", "osv_id": "GHSA-abcd-efgh-ijkl",
         "aliases": ["PYSEC-2024-1"]},
        {"cve_id": "PYSEC-2024-1", "osv_id": "PYSEC-2024-1"},
        {"cve_id": "CVE-2024-22222", "osv_id": "GHSA-wxyz-efgh-ijkl"},
    ]

    assert osv_client.dedupe_advisories(advisories) == [
        advisories[0],
        advisories[2],
    ]


def test_query_osv_network_failure_returns_error_and_warning(
    cache_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = 0

    def fail_request(*args: object, **kwargs: object) -> None:
        nonlocal attempts
        attempts += 1
        raise requests.ConnectionError("offline")

    monkeypatch.setattr(osv_client.requests, "post", fail_request)
    result = osv_client.query_osv("demo-package", "1.0.0")

    assert result["ok"] is False
    assert result["error"] and "offline" in result["error"]
    assert result["warnings"]
    assert attempts == 3


def test_query_osv_rejects_malformed_json(
    cache_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class MalformedResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> object:
            raise json.JSONDecodeError("invalid JSON", "{", 0)

    monkeypatch.setattr(
        osv_client.requests, "post", lambda *args, **kwargs: MalformedResponse()
    )
    result = osv_client.query_osv("demo-package", "1.0.0")

    assert result["ok"] is False
    assert "failed after 3 attempts" in (result["error"] or "")
    assert result["advisories"] == []


def test_query_osv_uses_expired_cache_if_network_fails(
    cache_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_cache(cache_db, PAYLOAD, fetched_at=time.time() - osv_client.CACHE_TTL_SECONDS - 1)
    monkeypatch.setattr(
        osv_client.requests,
        "post",
        lambda *args, **kwargs: (_ for _ in ()).throw(requests.ConnectionError("offline")),
    )

    result = osv_client.query_osv("demo-package", "1.0.0")

    assert result["ok"] is True
    assert result["advisories"][0]["cve_id"] == "CVE-2024-11111"
    assert any("expired cached response" in warning for warning in result["warnings"])


def test_query_osv_uses_matching_golden_fixture_when_offline(
    cache_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        osv_client.requests,
        "post",
        lambda *args, **kwargs: (_ for _ in ()).throw(requests.ConnectionError("offline")),
    )

    result = osv_client.query_osv("Flask", "2.2.2")

    assert result["ok"] is True
    assert result["advisories"][0]["cve_id"] == "CVE-2023-30861"
    assert any("golden fixture" in warning for warning in result["warnings"])


def test_map_symbols_uses_package_level_for_unknown_cve(caplog: pytest.LogCaptureFixture) -> None:
    targets = osv_client.map_symbols(
        [
            {
                "cve_id": "CVE-2099-00001",
                "osv_id": "OSV-2099-00001",
                "package": "demo-package",
                "version": "1.0.0",
                "summary": "Unknown test advisory",
                "severity": "LOW",
                "cvss": None,
                "fixed_in": [],
            }
        ]
    )

    assert targets[0]["symbols"] == []
    assert "package-level only" in caplog.text


def test_query_osv_uses_database_severity_when_vector_is_unsupported(
    cache_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = {
        "vulns": [
            {
                "id": "OSV-2099-00002",
                "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}],
                "database_specific": {"severity": "high"},
            }
        ]
    }

    class CachedResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> object:
            return payload

    calls = 0

    def cached_response(url: str, json: dict, timeout: int) -> CachedResponse:
        nonlocal calls
        calls += 1
        assert url == osv_client.OSV_QUERY_URL
        assert json == {
            "package": {"name": "demo-package", "ecosystem": "PyPI"},
            "version": "1.0.0",
        }
        assert timeout == 8
        return CachedResponse()

    monkeypatch.setattr(osv_client.requests, "post", cached_response)
    result = osv_client.query_osv("demo-package", "1.0.0")
    repeated = osv_client.query_osv("demo-package", "1.0.0")

    assert result["ok"] is True
    assert result["advisories"][0]["cve_id"] == "OSV-2099-00002"
    assert result["advisories"][0]["severity"] == "HIGH"
    assert result["advisories"][0]["cvss"] is None
    assert repeated["ok"] is True
    assert calls == 1


def test_map_symbols_uses_curated_mapping() -> None:
    target = osv_client.map_symbols(
        [
            {
                "cve_id": "CVE-2023-32681",
                "osv_id": "PYSEC-2023-74",
                "package": "requests",
                "version": "2.25.1",
                "summary": "Recorded test advisory",
                "severity": "MEDIUM",
                "cvss": 6.1,
                "fixed_in": ["2.31.0"],
            }
        ]
    )[0]

    assert target["symbols"] == ["requests.sessions.Session.send"]


def test_warm_cli_reads_pinned_and_unpinned_requirements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo-package==1.0.0\nother-package>=2.0\n", encoding="utf-8")
    queries: list[tuple[str, str]] = []

    def successful_query(name: str, version: str, ecosystem: str = "PyPI") -> dict:
        queries.append((name, version))
        return {"ok": True, "error": None, "warnings": [], "advisories": []}

    monkeypatch.setattr(osv_client, "query_osv", successful_query)

    assert osv_client.main(["--warm", str(requirements)]) == 0
    assert queries == [("demo-package", "1.0.0"), ("other-package", "")]
