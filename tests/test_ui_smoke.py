import copy
import json
from pathlib import Path
from typing import Mapping

import networkx as nx
import pytest
from streamlit.testing.v1 import AppTest

from contracts import ScanResult
from ui import SEMANTIC_COLORS, THEMES, chip_colors, mix
from ui import callpath_panel, export_panel, findings_panel, graph_panel

ROOT = Path(__file__).resolve().parents[1]
with (ROOT / "fixtures" / "golden" / "scan_result.json").open(encoding="utf-8") as golden_file:
    GOLDEN_SCAN: ScanResult = json.load(golden_file)

EMPTY_SCAN: ScanResult = {
    "ok": True,
    "error": None,
    "warnings": [],
    "target": "inline-empty",
    "sbom": {
        "ok": True,
        "error": None,
        "warnings": [],
        "packages": [],
        "edges": [],
        "cyclonedx": {},
        "spdx": {},
        "source": "manifest",
    },
    "osv": {"ok": True, "error": None, "warnings": [], "advisories": []},
    "reach": {
        "ok": True,
        "error": None,
        "warnings": [],
        "findings": [],
        "entry_points": [],
        "parse_failures": [],
        "degraded": False,
    },
    "inspect": {
        "ok": True,
        "error": None,
        "warnings": [],
        "typo_flags": [],
        "provenance": [],
    },
    "vex": {
        "ok": True,
        "error": None,
        "warnings": [],
        "findings": [],
        "metrics": {
            "raw_cve_count": 0,
            "actionable_count": 0,
            "suppressed_count": 0,
            "under_investigation_count": 0,
            "noise_reduction_pct": 0.0,
            "actionable_rate_pct": 100.0,
        },
        "openvex": {"statements": []},
        "cyclonedx_vex": {"vulnerabilities": []},
    },
}
DEGRADED_SCAN: ScanResult = {
    **EMPTY_SCAN,
    "reach": {**EMPTY_SCAN["reach"], "degraded": True},
}
INVALID_VEX_SCAN: ScanResult = {
    **EMPTY_SCAN,
    "vex": {**EMPTY_SCAN["vex"], "ok": False, "error": "inline validation error"},
}
def _render_selected_panel() -> None:
    """Render the selected panel from Streamlit test state."""
    import streamlit as st

    from ui import callpath_panel, export_panel, findings_panel, graph_panel

    renderers = {
        "findings": findings_panel,
        "export": export_panel,
        "callpath": callpath_panel,
        "graph": graph_panel,
    }
    renderers[st.session_state["panel_name"]].render(st.session_state["scan"])


def _contrast_ratio(foreground: str, background: str) -> float:
    def luminance(color: str) -> float:
        channels = [int(color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [
            channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4
            for channel in channels
        ]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    brighter, darker = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (brighter + 0.05) / (darker + 0.05)


def _text_background_pairs(theme: Mapping[str, str]) -> list[tuple[str, str]]:
    pairs = [
        (theme["text"], theme["background"]),
        (theme["muted"], theme["background"]),
        (theme["text"], theme["surface"]),
        (theme["muted"], theme["surface"]),
        (theme["text"], theme["secondary"]),
        (theme["text"], theme["alert"]),
    ]
    for state in SEMANTIC_COLORS:
        fill, text = chip_colors(state, theme)
        pairs.append((text, fill))
    good_fill = mix(SEMANTIC_COLORS["safe"], theme["surface"], 0.2)
    good_text = mix(SEMANTIC_COLORS["safe"], "#FFFFFF", 0.45)
    pairs.append((good_text, good_fill))
    warning_fill = mix(SEMANTIC_COLORS["suppressed"], theme["surface"], 0.2)
    warning_text = mix(SEMANTIC_COLORS["suppressed"], "#FFFFFF", 0.45)
    pairs.append((warning_text, warning_fill))
    return pairs


def _copy_scan() -> ScanResult:
    return copy.deepcopy(GOLDEN_SCAN)


@pytest.mark.parametrize("state", ["reachable", "typosquat", "investigating", "suppressed", "safe"])
def test_package_state_covers_each_state(state: str) -> None:
    packages = {
        "reachable": "Flask",
        "typosquat": "reqeusts",
        "investigating": "Werkzeug",
        "suppressed": "Pillow",
        "safe": "isolated-package",
    }
    if state == "safe":
        scan = _copy_scan()
        scan["sbom"]["packages"].append(
            {
                "name": "isolated-package",
                "version": "1.0",
                "ecosystem": "PyPI",
                "purl": "pkg:pypi/isolated-package@1.0",
                "scope": "transitive",
                "depends_on": [],
            }
        )
    else:
        scan = GOLDEN_SCAN
    package_name = packages[state]
    assert graph_panel.package_state(package_name, scan) == state


def test_package_state_risk_precedence() -> None:
    scan = _copy_scan()
    finding = scan["vex"]["findings"][0]
    finding["provenance_tag"] = "provenance violation"
    finding["reach"]["reach_status"] = "reachable"
    scan["inspect"]["typo_flags"].append(
        {"package": finding["package"], "matched": "other", "distance": 1, "homoglyph": False, "risk_score": 1.0}
    )
    assert graph_panel.package_state("Flask", scan) == "reachable"

    finding["status"] = "under_investigation"
    finding["reach"]["reach_status"] = "over_approximated_path"
    assert graph_panel.package_state("Flask", scan) == "typosquat"

    scan["inspect"]["typo_flags"].clear()
    finding["provenance_tag"] = None
    assert graph_panel.package_state("Flask", scan) == "investigating"


def test_findings_filter_searches_filters_and_sorts() -> None:
    findings = [
        {"id": "CVE-M", "package": "medium", "status": "affected", "priority": "MEDIUM"},
        {"id": "CVE-C", "package": "critical", "status": "affected", "priority": "CRITICAL"},
        {"id": "CVE-H", "package": "high", "status": "not_affected", "priority": "HIGH"},
    ]
    assert [row["priority"] for row in findings_panel.filter_findings(findings)] == [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
    ]
    filtered = findings_panel.filter_findings(
        findings, search="CVE-H", statuses=["not_affected"], priorities=["HIGH"]
    )
    assert [row["id"] for row in filtered] == ["CVE-H"]
    assert findings_panel.filter_findings(findings, statuses=[], priorities=[]) == []


def test_evidence_text_uses_path_then_justification_then_provenance() -> None:
    finding = GOLDEN_SCAN["vex"]["findings"][0]
    assert findings_panel.evidence_text(finding).startswith("1 call-path hops:")
    no_path = {"reach": {"paths": []}, "justification": "inline_code_not_reachable"}
    assert findings_panel.evidence_text(no_path) == "inline_code_not_reachable"
    assert findings_panel.evidence_text({"provenance_tag": "missing source"}) == "missing source"
    assert findings_panel.evidence_text({}) == "—"


def test_untrusted_package_text_is_escaped_in_tooltip_and_table() -> None:
    name = "<script>alert(1)</script>"
    tooltip = graph_panel.package_tooltip(
        {"name": name, "version": "1.0", "purl": "pkg:pypi/untrusted@1.0"},
        EMPTY_SCAN,
    )
    table = findings_panel.findings_table_html(
        [{"package": name, "version": "1.0", "id": "CVE-1", "status": "affected"}]
    )
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in tooltip
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in table
    assert "<script>" not in tooltip
    assert "<script>" not in table


@pytest.mark.parametrize("theme", THEMES.values())
def test_all_generated_text_background_pairs_meet_wcag_aa(theme: Mapping[str, str]) -> None:
    for foreground, background in _text_background_pairs(theme):
        assert _contrast_ratio(foreground, background) >= 4.5, (foreground, background)


def test_graph_includes_isolated_nodes_and_marks_reachable_route() -> None:
    scan = _copy_scan()
    scan["sbom"]["packages"] = [
        {"name": "root", "version": "1", "ecosystem": "PyPI", "purl": "pkg:pypi/root@1", "scope": "direct", "depends_on": []},
        {"name": "middle", "version": "1", "ecosystem": "PyPI", "purl": "pkg:pypi/middle@1", "scope": "transitive", "depends_on": []},
        {"name": "leaf", "version": "1", "ecosystem": "PyPI", "purl": "pkg:pypi/leaf@1", "scope": "transitive", "depends_on": []},
        {"name": "isolated", "version": "1", "ecosystem": "PyPI", "purl": "pkg:pypi/isolated@1", "scope": "transitive", "depends_on": []},
    ]
    scan["sbom"]["edges"] = [
        ("pkg:pypi/root@1", "pkg:pypi/middle@1"),
        ("pkg:pypi/middle@1", "pkg:pypi/leaf@1"),
    ]
    scan["vex"]["findings"] = [
        {
            "id": "CVE-1",
            "package": "leaf",
            "version": "1",
            "status": "affected",
            "priority": "HIGH",
            "justification": None,
            "impact_statement": "",
            "reach": {"reach_status": "reachable"},
            "provenance_tag": None,
            "needs_manual_review": False,
        }
    ]
    graph = graph_panel.build_graph(scan)
    assert graph.number_of_nodes() == 4
    assert "pkg:pypi/isolated@1" in graph
    assert graph_panel.reachable_route_edges(graph, scan) == {
        ("pkg:pypi/root@1", "pkg:pypi/middle@1"),
        ("pkg:pypi/middle@1", "pkg:pypi/leaf@1"),
    }


@pytest.mark.parametrize(
    "panel_name",
    ["findings", "export", "callpath", "graph"],
)
@pytest.mark.parametrize("scan", [GOLDEN_SCAN, DEGRADED_SCAN, INVALID_VEX_SCAN, EMPTY_SCAN])
def test_each_panel_renders_supported_scans(panel_name: str, scan: ScanResult) -> None:
    at = AppTest.from_function(_render_selected_panel)
    at.session_state["panel_name"] = panel_name
    at.session_state["scan"] = scan
    at.run()
    assert not at.exception


def test_degraded_scan_shows_required_warning() -> None:
    at = AppTest.from_function(_render_selected_panel)
    at.session_state["panel_name"] = "findings"
    at.session_state["scan"] = DEGRADED_SCAN
    at.run()
    assert any(
        warning.value
        == "Manifest-only mode: reachability could not be computed. "
        "CVEs are treated as affected, nothing is suppressed."
        for warning in at.warning
    )


def test_invalid_vex_disables_both_downloads() -> None:
    at = AppTest.from_function(_render_selected_panel)
    at.session_state["panel_name"] = "export"
    at.session_state["scan"] = INVALID_VEX_SCAN
    at.run()
    assert len(at.download_button) == 2
    assert all(button.disabled for button in at.download_button)


def test_app_smoke_with_preloaded_golden_scan() -> None:
    at = AppTest.from_file(str(ROOT / "app.py"))
    at.session_state["scan"] = GOLDEN_SCAN
    at.run()
    assert not at.exception
