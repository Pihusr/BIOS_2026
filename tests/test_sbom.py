import json
from pathlib import Path

from sbom_engine import build_sbom


ROOT = Path(__file__).resolve().parents[1]


def test_ground_truth_manifest_packages():
    result = build_sbom(str(ROOT / "fixtures" / "ground_truth_repo"))
    assert result["ok"] is True
    assert len(result["packages"]) >= 8
    names = {package["name"] for package in result["packages"]}
    assert "reqeusts" in names
    assert all(package["purl"].startswith("pkg:pypi/") for package in result["packages"])
    assert result["cyclonedx"]["specVersion"] == "1.5"
    assert result["spdx"]["spdxVersion"] == "SPDX-2.3"


def test_requirements_includes_extras_and_unpinned(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text(
        "requests[socks]==2.31.0  # comment\nflask>=2.0\n-r nested.txt\n",
        encoding="utf-8",
    )
    (tmp_path / "nested.txt").write_text("urllib3==2.2.1\n", encoding="utf-8")
    result = build_sbom(str(tmp_path))
    packages = {package["name"]: package for package in result["packages"]}
    assert packages["requests"]["version"] == "2.31.0"
    assert packages["urllib3"]["version"] == "2.2.1"
    assert packages["flask"]["version"] == ""
    assert any("unpinned version for flask" in warning for warning in result["warnings"])


def test_pyproject_pipfile_and_package_json(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["httpx==0.27.0", "click>=8"]\n[tool.poetry.dependencies]\nflask = "2.2.2"\npython = "^3.11"\n',
        encoding="utf-8",
    )
    (tmp_path / "Pipfile").write_text('[packages]\ndjango = "==5.0"\n', encoding="utf-8")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.21"}}), encoding="utf-8")
    result = build_sbom(str(tmp_path))
    names = {package["name"]: package for package in result["packages"]}
    assert "httpx" in names and names["httpx"]["version"] == "0.27.0"
    assert "click" in names and names["click"]["version"] == ""
    assert "django" in names
    assert names["lodash"]["ecosystem"] == "npm"


def test_malformed_manifest_and_empty_directory(tmp_path: Path):
    malformed = tmp_path / "package.json"
    malformed.write_text("{ definitely not json", encoding="utf-8")
    result = build_sbom(str(tmp_path))
    assert result["ok"] is True
    assert result["packages"] == []
    assert any("malformed package.json" in warning for warning in result["warnings"])

    empty = tmp_path / "empty"
    empty.mkdir()
    empty_result = build_sbom(str(empty))
    assert empty_result["ok"] is True
    assert empty_result["packages"] == []
    assert empty_result["cyclonedx"]["components"] == []


def test_nonexistent_path():
    result = build_sbom("C:\\definitely\\missing\\repository")
    assert result["ok"] is False
    assert result["packages"] == []
    assert result["error"]
