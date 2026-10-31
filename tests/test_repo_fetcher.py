from __future__ import annotations

from io import BytesIO
import os
from pathlib import Path
import runpy
import stat
import sys
import tempfile
import types
from typing import Any
import zipfile

import pytest

import pipeline
import repo_fetcher


ROOT = Path(__file__).resolve().parents[1]


def _zip_bytes(files: dict[str, bytes | str]) -> bytes:
    output = BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(
                name, content.encode() if isinstance(content, str) else content
            )
    return output.getvalue()


class _Response:
    def __init__(
        self,
        content: bytes = b"",
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        chunks: list[bytes] | None = None,
    ) -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self._content = content
        self._chunks = chunks
        self.closed = False

    def iter_content(self, chunk_size: int) -> object:
        if self._chunks is not None:
            yield from self._chunks
        else:
            for offset in range(0, len(self._content), chunk_size):
                yield self._content[offset : offset + chunk_size]

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/owner/repo", ("owner", "repo", None)),
        ("https://github.com/owner/repo/", ("owner", "repo", None)),
        ("https://github.com/owner/repo.git", ("owner", "repo", None)),
        (
            "https://github.com/owner/repo.git/",
            ("owner", "repo", None),
        ),
        (
            "https://github.com/owner/repo/tree/release/2026",
            ("owner", "repo", "release/2026"),
        ),
    ],
)
def test_parse_github_url_accepts_supported_urls(
    url: str, expected: tuple[str, str, str | None]
) -> None:
    assert repo_fetcher.parse_github_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/owner/repo",
        "http://github.com/owner/repo",
        "https://github.com@evil.example/owner/repo",
        "https://github.com:443/owner/repo",
        "https://127.0.0.1/owner/repo",
        "https://github.com.evil.example/owner/repo",
        "https://gіthub.com/owner/repo",
        "https://github.com/owner/../repo",
        "https://github.com/-owner/repo",
        "https://github.com/owner/-repo",
        "https://github.com/owner/repo?download=1",
        "https://github.com/owner/repo#readme",
        "https://github.com/owner/repo/issues",
        "https://github.com/owner/repo/tree/",
        "https://github.com/owner/repo/tree//main",
        "https://github.com/owner/repo/tree/a/../b",
        "https://github.com/owner/repo/tree/%2Dbranch",
        "https://github.com/owner/invalid%2Frepo",
        "https://github.com/" + "a" * 101 + "/repo",
        "-https://github.com/owner/repo",
    ],
)
def test_parse_github_url_rejects_unsupported_urls(url: str) -> None:
    with pytest.raises(ValueError):
        repo_fetcher.parse_github_url(url)


def test_parse_github_url_rejects_unicode_repository_names() -> None:
    with pytest.raises(ValueError, match="owner and repository"):
        repo_fetcher.parse_github_url("https://github.com/ownér/repo")


def test_fetch_extracts_only_whitelisted_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _zip_bytes(
        {
            "repo-main/app.py": "print('safe')",
            "repo-main/requirements-prod.txt": "requests==2.31",
            "repo-main/pyproject.toml": "[project]",
            "repo-main/Pipfile": "",
            "repo-main/Pipfile.lock": "{}",
            "repo-main/package.json": "{}",
            "repo-main/package-lock.json": "{}",
            "repo-main/poetry.lock": "",
            "repo-main/README.md": "not included",
            "repo-main/.git/config": "not included",
            "repo-main/.venv/ignored.py": "not included",
            "repo-main/venv/ignored.py": "not included",
            "repo-main/node_modules/ignored.py": "not included",
            "repo-main/site-packages/ignored.py": "not included",
        }
    )
    response = _Response(payload)
    calls: list[tuple[str, dict[str, object]]] = []

    def fake_get(url: str, **kwargs: object) -> _Response:
        calls.append((url, kwargs))
        return response

    monkeypatch.setattr(repo_fetcher.requests, "get", fake_get)
    extracted = Path(repo_fetcher.fetch("https://github.com/owner/repo", tmp_path))
    assert extracted == tmp_path / "repo"
    assert sorted(str(path.relative_to(extracted)) for path in extracted.rglob("*") if path.is_file()) == [
        "Pipfile",
        "Pipfile.lock",
        "app.py",
        "package-lock.json",
        "package.json",
        "poetry.lock",
        "pyproject.toml",
        "requirements-prod.txt",
    ]
    assert calls[0][0] == "https://github.com/owner/repo/archive/HEAD.zip"
    assert calls[0][1]["timeout"] == (10, 30)
    assert calls[0][1]["stream"] is True
    assert calls[0][1]["allow_redirects"] is False
    assert response.closed


def test_fetch_uses_branch_archive_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def fake_get(url: str, **kwargs: object) -> _Response:
        calls.append(url)
        return _Response(_zip_bytes({"repo-branch/app.py": "pass"}))

    monkeypatch.setattr(repo_fetcher.requests, "get", fake_get)
    repo_fetcher.fetch("https://github.com/owner/repo/tree/feature/new", tmp_path)
    assert calls == [
        "https://github.com/owner/repo/archive/refs/heads/feature/new.zip"
    ]


@pytest.mark.parametrize(
    "archive_path",
    [
        "repo-main/../../outside.py",
        "/absolute/app.py",
        "C:/outside.py",
        "C:outside.py",
    ],
)
def test_fetch_rejects_unsafe_archive_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, archive_path: str
) -> None:
    monkeypatch.setattr(
        repo_fetcher.requests,
        "get",
        lambda *args, **kwargs: _Response(_zip_bytes({archive_path: "unsafe"})),
    )
    with pytest.raises(ValueError, match="unsafe path|absolute or drive-letter"):
        repo_fetcher.fetch("https://github.com/owner/repo", tmp_path)
    assert not (tmp_path.parent / "outside.py").exists()


def test_fetch_rejects_symlink_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        entry = zipfile.ZipInfo("repo-main/link.py")
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(entry, "target.py")
    monkeypatch.setattr(
        repo_fetcher.requests, "get", lambda *args, **kwargs: _Response(output.getvalue())
    )
    with pytest.raises(ValueError, match="symbolic link"):
        repo_fetcher.fetch("https://github.com/owner/repo", tmp_path)


def test_fetch_allows_more_than_5000_non_whitelisted_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for index in range(6000):
            archive.writestr(f"repo-main/assets/file-{index}.dat", b"x")
        archive.writestr("repo-main/requirements.txt", "requests==2.31")
    monkeypatch.setattr(
        repo_fetcher.requests,
        "get",
        lambda *args, **kwargs: _Response(output.getvalue()),
    )

    extracted = Path(repo_fetcher.fetch("https://github.com/owner/repo", tmp_path))
    assert (extracted / "requirements.txt").read_text(encoding="utf-8") == "requests==2.31"
    assert len(list(extracted.rglob("*"))) == 1


def test_fetch_ignores_compression_ratio_for_non_whitelisted_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("repo-main/assets/zeros.dat", bytes(10 * 1024 * 1024))
        archive.writestr("repo-main/requirements.txt", "requests==2.31")
    monkeypatch.setattr(
        repo_fetcher.requests,
        "get",
        lambda *args, **kwargs: _Response(output.getvalue()),
    )

    extracted = Path(repo_fetcher.fetch("https://github.com/owner/repo", tmp_path))
    assert (extracted / "requirements.txt").is_file()
    assert not (extracted / "assets" / "zeros.dat").exists()


def test_fetch_rejects_compressible_whitelisted_python_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("repo-main/app.py", bytes(10 * 1024 * 1024))
    monkeypatch.setattr(
        repo_fetcher.requests,
        "get",
        lambda *args, **kwargs: _Response(output.getvalue()),
    )

    with pytest.raises(ValueError, match="compression ratio"):
        repo_fetcher.fetch("https://github.com/owner/repo", tmp_path)


def test_fetch_rejects_archive_over_entry_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = _zip_bytes(
        {f"repo-main/file-{index}.txt": "" for index in range(4)}
    )
    monkeypatch.setattr(repo_fetcher, "_MAX_ENTRIES", 3)
    monkeypatch.setattr(
        repo_fetcher.requests,
        "get",
        lambda *args, **kwargs: _Response(output),
    )

    with pytest.raises(ValueError, match="more than 3 entries"):
        repo_fetcher.fetch("https://github.com/owner/repo", tmp_path)


def test_fetch_rejects_slow_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    response = _Response(chunks=[b"zip-data"])
    monkeypatch.setattr(
        repo_fetcher.requests,
        "get",
        lambda *args, **kwargs: response,
    )
    clock_values = iter([0.0, 61.0])
    monkeypatch.setattr(repo_fetcher.time, "monotonic", lambda: next(clock_values))

    with pytest.raises(ValueError, match="^Download took too long\\.$"):
        repo_fetcher.fetch("https://github.com/owner/repo", tmp_path)
    assert response.closed


@pytest.mark.parametrize(
    ("archive_path", "is_symlink"),
    [
        ("repo-main/README.md", True),
        ("repo-main/../README.md", False),
    ],
)
def test_fetch_checks_unsafe_non_whitelisted_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    archive_path: str,
    is_symlink: bool,
) -> None:
    output = BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        if is_symlink:
            entry = zipfile.ZipInfo(archive_path)
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(entry, "target")
        else:
            archive.writestr(archive_path, "not whitelisted")
    monkeypatch.setattr(
        repo_fetcher.requests,
        "get",
        lambda *args, **kwargs: _Response(output.getvalue()),
    )

    message = "symbolic link" if is_symlink else "unsafe path"
    with pytest.raises(ValueError, match=message):
        repo_fetcher.fetch("https://github.com/owner/repo", tmp_path)


def test_fetch_rejects_streamed_download_over_50_mb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chunks = [b"x" * (1024 * 1024) for _ in range(50)] + [b"x"]
    monkeypatch.setattr(
        repo_fetcher.requests,
        "get",
        lambda *args, **kwargs: _Response(chunks=chunks),
    )
    with pytest.raises(ValueError, match="50 MB"):
        repo_fetcher.fetch("https://github.com/owner/repo", tmp_path)


def test_fetch_rejects_extracted_file_over_2_mb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _zip_bytes(
        {"repo-main/large.py": os.urandom(2 * 1024 * 1024 + 1)}
    )
    monkeypatch.setattr(
        repo_fetcher.requests, "get", lambda *args, **kwargs: _Response(payload)
    )
    with pytest.raises(ValueError, match="larger than 2 MB"):
        repo_fetcher.fetch("https://github.com/owner/repo", tmp_path)


def test_fetch_rejects_suspicious_compression_ratio(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _zip_bytes({"repo-main/repeated.py": "a" * 100_000})
    monkeypatch.setattr(
        repo_fetcher.requests, "get", lambda *args, **kwargs: _Response(payload)
    )
    with pytest.raises(ValueError, match="compression ratio"):
        repo_fetcher.fetch("https://github.com/owner/repo", tmp_path)


def test_fetch_rejects_disallowed_redirect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    redirect = _Response(
        status_code=302, headers={"Location": "https://evil.example/archive.zip"}
    )
    monkeypatch.setattr(repo_fetcher.requests, "get", lambda *args, **kwargs: redirect)
    with pytest.raises(ValueError, match="unsupported host"):
        repo_fetcher.fetch("https://github.com/owner/repo", tmp_path)
    assert redirect.closed


def test_fetch_allows_redirect_to_codeload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    redirect = _Response(
        status_code=302,
        headers={"Location": "https://codeload.github.com/owner/repo/legacy.zip/HEAD"},
    )
    archive = _Response(_zip_bytes({"repo-main/app.py": "pass"}))
    responses = iter([redirect, archive])
    urls: list[str] = []

    def fake_get(url: str, **kwargs: object) -> _Response:
        urls.append(url)
        return next(responses)

    monkeypatch.setattr(repo_fetcher.requests, "get", fake_get)
    repo_fetcher.fetch("https://github.com/owner/repo", tmp_path)
    assert urls == [
        "https://github.com/owner/repo/archive/HEAD.zip",
        "https://codeload.github.com/owner/repo/legacy.zip/HEAD",
    ]
    assert redirect.closed
    assert archive.closed


def test_fetch_404_has_public_repository_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        repo_fetcher.requests,
        "get",
        lambda *args, **kwargs: _Response(status_code=404),
    )
    with pytest.raises(
        ValueError,
        match="Repository not found or private. Only public GitHub repos are supported.",
    ):
        repo_fetcher.fetch("https://github.com/owner/repo", tmp_path)


def test_run_scan_url_sets_target_and_cleans_temp_dir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_temporary_directory = tempfile.TemporaryDirectory
    temporary_paths: list[Path] = []

    def tracking_temporary_directory(*args: Any, **kwargs: Any):
        directory = real_temporary_directory(*args, **kwargs)
        temporary_paths.append(Path(directory.name))
        return directory

    def fake_fetch(url: str, dest_dir: str) -> str:
        extracted = Path(dest_dir) / "repo"
        extracted.mkdir()
        (extracted / "main.py").write_text("pass", encoding="utf-8")
        return str(extracted)

    scan = {
        "target": "old path",
        "sbom": {"packages": [{"name": "unpinned-package", "version": ""}]},
        "osv": {},
        "reach": {},
        "inspect": {},
        "vex": {},
    }
    monkeypatch.setattr(pipeline.tempfile, "TemporaryDirectory", tracking_temporary_directory)
    monkeypatch.setattr(pipeline.repo_fetcher, "fetch", fake_fetch)
    monkeypatch.setattr(pipeline, "run_scan", lambda path: scan)

    url = "https://github.com/owner/repo"
    result = pipeline.run_scan_url(url)
    assert result["target"] == url
    assert any("unpinned-package" in item for item in result["warnings"])
    assert len(temporary_paths) == 1
    assert not temporary_paths[0].exists()


def test_run_scan_url_warns_when_no_python_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_fetch(url: str, dest_dir: str) -> str:
        extracted = Path(dest_dir) / "repo"
        extracted.mkdir()
        (extracted / "requirements.txt").write_text("sample", encoding="utf-8")
        return str(extracted)

    monkeypatch.setattr(pipeline.repo_fetcher, "fetch", fake_fetch)
    monkeypatch.setattr(
        pipeline,
        "run_scan",
        lambda path: {
            "target": path,
            "sbom": {"packages": []},
            "osv": {},
            "reach": {},
            "inspect": {},
            "vex": {},
        },
    )
    result = pipeline.run_scan_url("https://github.com/owner/repo")
    assert any("no Python files" in item for item in result["warnings"])


def test_run_scan_url_failure_cleans_temp_dir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_temporary_directory = tempfile.TemporaryDirectory
    temporary_paths: list[Path] = []

    def tracking_temporary_directory(*args: Any, **kwargs: Any):
        directory = real_temporary_directory(*args, **kwargs)
        temporary_paths.append(Path(directory.name))
        return directory

    monkeypatch.setattr(pipeline.tempfile, "TemporaryDirectory", tracking_temporary_directory)
    monkeypatch.setattr(
        pipeline.repo_fetcher,
        "fetch",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("download failed")),
    )
    result = pipeline.run_scan_url("https://github.com/owner/repo")
    assert result["ok"] is False
    assert result["error"] == "download failed"
    assert len(temporary_paths) == 1
    assert not temporary_paths[0].exists()


def test_run_scan_caps_osv_queries_at_150(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packages = [
        {
            "name": f"package-{index}",
            "version": "1.0",
            "ecosystem": "PyPI",
            "purl": f"pkg:pypi/package-{index}@1.0",
            "scope": "direct",
            "depends_on": [],
        }
        for index in range(151)
    ]
    monkeypatch.setattr(
        pipeline.sbom_engine,
        "build_sbom",
        lambda path: {
            "ok": True,
            "error": None,
            "warnings": [],
            "packages": packages,
            "edges": [],
            "cyclonedx": {},
            "spdx": {},
            "source": "manifest",
        },
    )
    queries: list[str] = []
    monkeypatch.setattr(
        pipeline.osv_client,
        "query_osv",
        lambda name, version, ecosystem: (
            queries.append(name)
            or {"ok": True, "error": None, "warnings": [], "advisories": []}
        ),
    )
    monkeypatch.setattr(
        pipeline.reachability,
        "analyze",
        lambda path, targets: {
            "ok": True,
            "error": None,
            "warnings": [],
            "findings": [],
            "entry_points": [],
            "parse_failures": [],
            "degraded": False,
        },
    )
    monkeypatch.setattr(
        pipeline.typo_inspector,
        "inspect",
        lambda packages: {
            "ok": True,
            "error": None,
            "warnings": [],
            "typo_flags": [],
            "provenance": [],
        },
    )
    monkeypatch.setattr(
        pipeline.vex_generator,
        "generate",
        lambda *args: {
            "ok": True,
            "error": None,
            "warnings": [],
            "findings": [],
            "metrics": {},
            "openvex": {},
            "cyclonedx_vex": {},
        },
    )

    scan = pipeline.run_scan(str(tmp_path))
    assert len(queries) == 150
    assert any("capped at 150" in warning for warning in scan["osv"]["warnings"])


def test_public_app_hides_local_path_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StopApp(Exception):
        pass

    class Sidebar:
        def __init__(self) -> None:
            self.inputs: list[str] = []
            self.buttons: list[str] = []

        def title(self, label: str) -> None:
            pass

        def text_input(self, label: str, *args: object, **kwargs: object) -> str:
            self.inputs.append(label)
            return ""

        def button(self, label: str, *args: object, **kwargs: object) -> bool:
            self.buttons.append(label)
            return False

    sidebar = Sidebar()
    fake_streamlit = types.ModuleType("streamlit")
    setattr(fake_streamlit, "sidebar", sidebar)
    setattr(fake_streamlit, "session_state", {})
    setattr(fake_streamlit, "set_page_config", lambda **kwargs: None)
    setattr(fake_streamlit, "info", lambda message: None)
    setattr(fake_streamlit, "stop", lambda: (_ for _ in ()).throw(StopApp()))

    fake_pipeline = types.ModuleType("pipeline")
    setattr(fake_pipeline, "run_scan", lambda path: pytest.fail("public mode must not scan a local path"))
    setattr(fake_pipeline, "run_scan_url", lambda url: pytest.fail("Scan button was not selected"))
    fake_ui = types.ModuleType("ui")
    for panel_name in (
        "findings_panel",
        "graph_panel",
        "callpath_panel",
        "export_panel",
    ):
        setattr(fake_ui, panel_name, types.SimpleNamespace(render=lambda scan: None))

    monkeypatch.setenv("HAWKEYE_PUBLIC", "1")
    monkeypatch.setitem(sys.modules, "streamlit", fake_streamlit)
    monkeypatch.setitem(sys.modules, "pipeline", fake_pipeline)
    monkeypatch.setitem(sys.modules, "ui", fake_ui)
    with pytest.raises(StopApp):
        runpy.run_path(str(ROOT / "app.py"))

    assert sidebar.inputs == ["GitHub repository URL"]
    assert sidebar.buttons == ["Scan", "Scan ground-truth demo"]
