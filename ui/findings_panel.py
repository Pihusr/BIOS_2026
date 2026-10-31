from collections.abc import Mapping, Sequence

import streamlit as st

from contracts import ScanResult
from ui import (
    active_theme,
    chip_colors,
    escape_html,
    html_document,
    show_degraded_warning,
)

STATUS_OPTIONS = ("affected", "not_affected", "under_investigation")
PRIORITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "INFORMATIONAL")
STATUS_STATES = {
    "affected": "reachable",
    "not_affected": "suppressed",
    "under_investigation": "investigating",
}


def evidence_text(finding: Mapping[str, object]) -> str:
    """Build the evidence summary from a path, justification, or provenance tag."""
    reach = finding.get("reach")
    if isinstance(reach, Mapping):
        paths = reach.get("paths") or []
        if paths and isinstance(paths[0], Sequence):
            frames = paths[0]
            symbols = [
                str(frame.get("symbol") or frame.get("file") or "")
                for frame in frames
                if isinstance(frame, Mapping)
            ]
            if symbols:
                hops = max(0, len(symbols) - 1)
                return f"{hops} call-path hops: {' → '.join(symbols)}"
    justification = finding.get("justification")
    if justification:
        return str(justification)
    provenance_tag = finding.get("provenance_tag")
    if provenance_tag:
        return str(provenance_tag)
    return "—"


def priority_sort_key(finding: Mapping[str, object]) -> tuple[int, str]:
    """Return a stable severity-first sort key for a finding."""
    priority = str(finding.get("priority") or "").upper()
    try:
        rank = PRIORITY_ORDER.index(priority)
    except ValueError:
        rank = len(PRIORITY_ORDER)
    return rank, str(finding.get("id") or "")


def filter_findings(
    findings: Sequence[Mapping[str, object]],
    search: str = "",
    statuses: Sequence[str] | None = None,
    priorities: Sequence[str] | None = None,
) -> list[Mapping[str, object]]:
    """Filter findings by text, status, and priority, then sort by severity."""
    needle = search.casefold().strip()
    filtered = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        status = str(finding.get("status") or "")
        priority = str(finding.get("priority") or "").upper()
        if statuses is not None and status not in statuses:
            continue
        if priorities is not None and priority not in priorities:
            continue
        searchable = " ".join(
            str(finding.get(key) or "")
            for key in ("package", "version", "id", "status", "priority")
        )
        searchable += " " + evidence_text(finding)
        if needle and needle not in searchable.casefold():
            continue
        filtered.append(finding)
    return sorted(filtered, key=priority_sort_key)


def findings_table_html(
    findings: Sequence[Mapping[str, object]],
    theme: Mapping[str, str] | None = None,
) -> str:
    """Build an escaped HTML findings table."""
    palette = theme or active_theme()
    rows = []
    for finding in findings:
        status = str(finding.get("status") or "unknown")
        state = STATUS_STATES.get(status, "investigating")
        fill, text = chip_colors(state, palette)
        cells = (
            finding.get("package") or "—",
            finding.get("version") or "—",
            finding.get("id") or "—",
            status,
            finding.get("priority") or "—",
            evidence_text(finding),
            "Yes" if finding.get("needs_manual_review") else "No",
        )
        escaped_cells = [escape_html(value) for value in cells]
        escaped_cells[3] = (
            f'<span class="chip" style="background:{fill};color:{text}">'
            f"{escaped_cells[3]}</span>"
        )
        rows.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in escaped_cells) + "</tr>")
    headers = ("Package", "Version", "Finding id", "Status", "Priority", "Evidence", "Manual review")
    header_html = "".join(f"<th scope=\"col\">{escape_html(header)}</th>" for header in headers)
    table = (
        '<div class="table-wrap"><table><thead><tr>'
        f"{header_html}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )
    return html_document(table, palette)


def _number(value: object, default: int | float = 0) -> int | float:
    if not isinstance(value, (int, float, str)):
        return default
    try:
        return float(value) if isinstance(default, float) else int(value)
    except (TypeError, ValueError):
        return default


def render(scan: ScanResult) -> None:
    """Render VEX metrics, noise reduction, and filterable findings."""
    show_degraded_warning(scan)
    vex = scan.get("vex") or {}
    metrics = vex.get("metrics") or {}
    findings = vex.get("findings") or []
    if not isinstance(metrics, Mapping):
        metrics = {}
    if not isinstance(findings, list):
        findings = []

    raw_count = _number(metrics.get("raw_cve_count"))
    actionable_count = _number(metrics.get("actionable_count"))
    suppressed_count = _number(metrics.get("suppressed_count"))
    noise_reduction = float(_number(metrics.get("noise_reduction_pct"), 0.0))
    actionable_rate = float(_number(metrics.get("actionable_rate_pct"), 100.0))

    st.subheader("Findings")
    metric_cols = st.columns(3)
    metric_cols[0].metric("Raw CVEs → actionable", f"{raw_count} → {actionable_count}")
    metric_cols[1].metric("Noise reduction", f"{noise_reduction:.1f}%")
    metric_cols[2].metric("Actionable rate", f"{actionable_rate:.1f}%")
    if actionable_rate != 100.0:
        st.error(f"Actionable rate is {actionable_rate:.1f}%; expected 100.0%.")
    else:
        st.success("All actionable findings have supporting evidence.")

    banner_state = "good" if noise_reduction >= 50.0 else "warning"
    banner_class = "banner-good" if banner_state == "good" else "banner-warning"
    banner = (
        f'<div class="banner {banner_class}">{escape_html(suppressed_count)} of '
        f'{escape_html(raw_count)} raw CVE alerts eliminated '
        f'({noise_reduction:.0f}%)</div>'
    )
    st.markdown(html_document(banner), unsafe_allow_html=True)

    if not findings:
        st.info("No findings are available.")
        return

    search = st.text_input("Search findings")
    selected_statuses = st.multiselect("Status", STATUS_OPTIONS, default=list(STATUS_OPTIONS))
    priorities = sorted(
        {str(finding.get("priority") or "").upper() for finding in findings if isinstance(finding, Mapping)},
        key=lambda item: (PRIORITY_ORDER.index(item) if item in PRIORITY_ORDER else len(PRIORITY_ORDER), item),
    )
    selected_priorities = st.multiselect("Priority", priorities, default=priorities)
    visible = filter_findings(findings, search, selected_statuses, selected_priorities)
    if visible:
        st.markdown(findings_table_html(visible), unsafe_allow_html=True)
    else:
        st.info("No findings match the selected filters.")
