from pathlib import Path

from contracts import VulnTarget
from reachability import analyze

ROOT = Path(__file__).resolve().parents[1]
GROUND_TRUTH = ROOT / "fixtures" / "ground_truth_repo"


def _target(cve_id: str, package: str, *symbols: str) -> VulnTarget:
    return {
        "cve_id": cve_id,
        "package": package,
        "symbols": list(symbols),
        "severity": "HIGH",
        "cvss": 8.0,
    }


def test_ground_truth_entries_aliases_paths_and_package_fallback() -> None:
    result = analyze(
        str(GROUND_TRUTH),
        [
            _target("CVE-FLASK", "flask", "flask.Flask"),
            _target("CVE-REQUESTS", "requests", "requests.get"),
            _target("CVE-YAML", "yaml", "yaml.load"),
            _target("CVE-PACKAGE", "requests"),
        ],
    )

    assert result["ok"] is True
    assert "app.status" in result["entry_points"]
    assert any(point.startswith("@module:app") for point in result["entry_points"])

    flask = next(item for item in result["findings"] if item["cve_id"] == "CVE-FLASK")
    assert flask["reach_status"] == "reachable"
    assert flask["paths"]
    assert all(
        frame["file"] and frame["line"] > 0 and frame["symbol"]
        for path in flask["paths"]
        for frame in path
    )
    assert len(flask["paths"]) <= 3

    requests = next(item for item in result["findings"] if item["cve_id"] == "CVE-REQUESTS")
    assert requests["reach_status"] == "reachable"
    assert any(
        frame["file"] == "services/http_client.py"
        for path in requests["paths"]
        for frame in path
    )

    dead_code = next(item for item in result["findings"] if item["cve_id"] == "CVE-YAML")
    assert dead_code["reach_status"] == "unreachable"
    assert dead_code["confidence"] == 1.0
    assert "package-level only" in result["warnings"]
    package_call = next(item for item in result["findings"] if item["cve_id"] == "CVE-PACKAGE")
    assert package_call["reach_status"] == "reachable"
    assert package_call["paths"]


def test_aliases_constant_branches_and_command_entries(tmp_path: Path) -> None:
    (tmp_path / "lib.py").write_text(
        "def vulnerable():\n"
        "    return 'reached'\n"
        "\n"
        "def dead():\n"
        "    return 'dead'\n"
        "\n"
        "def maybe():\n"
        "    return 'maybe'\n"
        "\n"
        "def other():\n"
        "    return 'other'\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "import argparse\n"
        "from typing import TYPE_CHECKING as TC\n"
        "from lib import vulnerable as safe, dead\n"
        "DEBUG = False\n"
        "cli = object()\n"
        "app = object()\n"
        "@cli.command()\n"
        "def run():\n"
        "    safe()\n"
        "    wrapped()\n"
        "    if False:\n"
        "        dead()\n"
        "    if DEBUG:\n"
        "        dead()\n"
        "    if TYPE_CHECKING:\n"
        "        dead()\n"
        "    if TC or None:\n"
        "        dead()\n"
        "    if should_run:\n"
        "        import lib as alias\n"
        "        alias.maybe()\n"
        "@app.get('/')\n"
        "def endpoint():\n"
        "    safe()\n"
        "def command():\n"
        "    safe()\n"
        "@custom_wrapper\n"
        "def wrapped():\n"
        "    import lib as alias\n"
        "    alias.other()\n"
        "parser = argparse.ArgumentParser()\n"
        "parser.set_defaults(func=command)\n",
        encoding="utf-8",
    )

    result = analyze(
        str(tmp_path),
        [
            _target("CVE-LIB", "lib", "lib.vulnerable"),
            _target("CVE-DEAD", "lib", "lib.dead"),
            _target("CVE-MAYBE", "lib", "lib.maybe"),
            _target("CVE-DECORATED", "lib", "lib.other"),
        ],
    )

    assert result["ok"] is True
    assert "main.run" in result["entry_points"]
    assert "main.endpoint" in result["entry_points"]
    assert "main.command" in result["entry_points"]
    findings = {item["cve_id"]: item for item in result["findings"]}
    assert findings["CVE-LIB"]["reach_status"] == "reachable"
    assert findings["CVE-DEAD"]["reach_status"] == "unreachable"
    assert findings["CVE-MAYBE"]["reach_status"] == "over_approximated_path"
    assert findings["CVE-MAYBE"]["confidence"] < 1.0
    assert findings["CVE-MAYBE"]["needs_manual_review"] is True
    assert findings["CVE-DECORATED"]["reach_status"] == "over_approximated_path"
    assert findings["CVE-DECORATED"]["confidence"] < 1.0


def test_dynamic_execution_and_parse_failures_are_conservative(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "def run(name):\n"
        "    module = __import__(name)\n"
        "    import importlib as importer\n"
        "    loaded = importer.import_module(name)\n"
        "    eval('1')\n"
        "    exec('pass')\n"
        "    return getattr(loaded, 'entry')\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    run('plugins')\n",
        encoding="utf-8",
    )
    (tmp_path / "broken.py").write_text("def unfinished(:\n", encoding="utf-8")

    target = _target("CVE-DYNAMIC", "vulnerable_pkg", "vulnerable_pkg.run")
    result = analyze(str(tmp_path), [target])

    assert result["ok"] is True
    assert result["parse_failures"] == ["broken.py"]
    assert result["degraded"] is False
    finding = result["findings"][0]
    assert finding["reach_status"] == "unknown_dynamic_execution"
    assert finding["confidence"] < 1.0
    assert finding["paths"]
    assert any("broken.py" in warning for warning in result["warnings"])

    broken_repo = tmp_path / "all-broken"
    broken_repo.mkdir()
    (broken_repo / "one.py").write_text("def invalid(:\n", encoding="utf-8")
    (broken_repo / "two.py").write_text("if True print('invalid')\n", encoding="utf-8")
    degraded = analyze(str(broken_repo), [target])
    assert degraded["ok"] is False
    assert degraded["degraded"] is True
    assert degraded["findings"] == []
    assert degraded["parse_failures"] == ["one.py", "two.py"]


def test_garbage_input_returns_an_error_result() -> None:
    invalid_path = analyze("", [])
    invalid_targets = analyze(str(GROUND_TRUTH), None)  # type: ignore[arg-type]
    invalid_item = analyze(str(GROUND_TRUTH), [{}])  # type: ignore[list-item]

    for result in (invalid_path, invalid_targets, invalid_item):
        assert result["ok"] is False
        assert result["error"]
        assert result["findings"] == []
