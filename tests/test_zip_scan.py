from __future__ import annotations

from io import BytesIO
from pathlib import Path
import zipfile
from typing import NoReturn

import pytest
import requests

import osv_client
import pipeline
import typo_inspector


ROOT = Path(__file__).resolve().parents[1]
MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def _offline(*args: object, **kwargs: object) -> NoReturn:
    raise requests.ConnectionError("offline test")


def _fixture_zip() -> bytes:
    fixture_root = ROOT / "fixtures" / "ground_truth_repo"
    output = BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in fixture_root.rglob("*"):
            if path.is_file():
                archive.write(
                    path,
                    (Path("ground_truth_repo") / path.relative_to(fixture_root)).as_posix(),
                )
    return output.getvalue()


def test_run_scan_zip_rejects_oversize_bytes() -> None:
    result = pipeline.run_scan_zip(b"x" * (MAX_UPLOAD_BYTES + 1))

    assert result["ok"] is False
    assert "10 MB" in result["error"]


def test_run_scan_zip_rejects_non_zip_bytes() -> None:
    result = pipeline.run_scan_zip(b"not a zip file")

    assert result["ok"] is False
    assert "valid ZIP archive" in result["error"]


def test_run_scan_zip_rejects_path_traversal() -> None:
    output = BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("../outside.py", "print('not executed')")

    result = pipeline.run_scan_zip(output.getvalue())

    assert result["ok"] is False
    assert "unsafe path" in result["error"]


def test_run_scan_zip_scans_valid_fixture_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache_path = tmp_path / "osv_cache.db"
    monkeypatch.setattr(osv_client, "CACHE_DB_PATH", cache_path)
    monkeypatch.setattr(typo_inspector, "CACHE_DB", cache_path)
    monkeypatch.setattr(osv_client.requests, "post", _offline)
    monkeypatch.setattr(typo_inspector.requests, "get", _offline)

    result = pipeline.run_scan_zip(_fixture_zip())

    assert result.get("ok", True) is True
    assert result["sbom"]["ok"] is True
    assert result["target"] == "uploaded ZIP"
