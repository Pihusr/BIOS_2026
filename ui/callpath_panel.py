from collections.abc import Mapping, Sequence

import streamlit as st

from contracts import ScanResult
from ui import active_theme, escape_html, html_document, show_degraded_warning

REVIEW_STATUSES = {
    "over_approximated_path",
    "unknown_dynamic_execution",
    "needs_manual_review",
}
UNKNOWN_DYNAMIC_WARNING = (
    "Dynamic call (getattr/eval/importlib) on the route. Static analysis cannot "
    "rule this out, so it is not suppressed."
)


def _is_manual_review_finding(finding: Mapping[str, object]) -> bool:
    reach = finding.get("reach")
    if not isinstance(reach, Mapping):
        return False
    return (
        reach.get("reach_status") in REVIEW_STATUSES
        or finding.get("needs_manual_review") is True
        or reach.get("needs_manual_review") is True
    )


def _reachable_first_key(finding: Mapping[str, object]) -> int:
    reach = finding.get("reach")
    return int(not isinstance(reach, Mapping) or reach.get("reach_status") != "reachable")


def path_findings(scan: Mapping[str, object]) -> list[Mapping[str, object]]:
    """Return findings with reach data, placing reachable routes first."""
    vex = scan.get("vex") or {}
    findings = vex.get("findings", []) if isinstance(vex, Mapping) else []
    selected = []
    for finding in findings if isinstance(findings, list) else []:
        if not isinstance(finding, Mapping):
            continue
        reach = finding.get("reach")
        if not isinstance(reach, Mapping):
            continue
        selected.append(finding)
    return sorted(selected, key=_reachable_first_key)


def finding_label(finding: Mapping[str, object]) -> str:
    """Build the CVE, package, and reach-status selector label."""
    reach = finding.get("reach")
    reach = reach if isinstance(reach, Mapping) else {}
    identifier = reach.get("cve_id") or finding.get("id") or "Unknown finding"
    package = reach.get("package") or finding.get("package") or "Unknown package"
    status = reach.get("reach_status") or "unknown"
    return f"{identifier} · {package} · {status}"


def callpath_html(path: Sequence[Mapping[str, object]]) -> str:
    """Build an escaped, indented call-frame tree with the final frame highlighted."""
    palette = active_theme()
    frames = []
    for depth, frame in enumerate(path):
        file_name = escape_html(frame.get("file") or "unknown file")
        line = escape_html(frame.get("line") if frame.get("line") is not None else "?")
        symbol = escape_html(frame.get("symbol") or "unknown symbol")
        final_class = " path-frame-vulnerable" if depth == len(path) - 1 else ""
        frames.append(
            f'<div class="path-frame{final_class}" style="margin-left:{depth * 20}px">'
            f"<code>{file_name}:{line}</code> &nbsp; <strong>{symbol}</strong></div>"
        )
    return html_document("".join(frames), palette)


def _paths_for(finding: Mapping[str, object]) -> list[list[Mapping[str, object]]]:
    reach = finding.get("reach")
    paths = reach.get("paths") if isinstance(reach, Mapping) else []
    if not isinstance(paths, list):
        return []
    valid_paths = []
    for path in paths:
        if not isinstance(path, list):
            continue
        frames = [frame for frame in path if isinstance(frame, Mapping)]
        if frames:
            valid_paths.append(frames)
    return valid_paths


def render(scan: ScanResult) -> None:
    """Render reachable call paths and manual-review context."""
    show_degraded_warning(scan)
    st.subheader("Call Paths")
    findings = path_findings(scan)
    if not findings:
        st.info("No finding has an available call path.")
        return
    has_path = any(any(_paths_for(finding)) for finding in findings)
    has_review_flag = any(_is_manual_review_finding(finding) for finding in findings)
    if not has_path and not has_review_flag:
        st.info("No finding has an available call path.")
        return

    labels = [finding_label(finding) for finding in findings]
    chosen_index = st.selectbox(
        "Finding",
        options=list(range(len(findings))),
        format_func=lambda index: labels[index],
    )
    finding = findings[chosen_index]
    reach = finding.get("reach")
    reach = reach if isinstance(reach, Mapping) else {}
    status = reach.get("reach_status")
    manual_review = (
        status == "over_approximated_path"
        or finding.get("needs_manual_review") is True
        or reach.get("needs_manual_review") is True
    )
    if manual_review:
        palette = active_theme()
        st.markdown(
            html_document(
                f'<span class="chip" style="background:{palette["secondary"]};'
                f'color:{palette["text"]}">'
                "Manual review</span>",
                palette,
            ),
            unsafe_allow_html=True,
        )
    if status == "unknown_dynamic_execution":
        st.warning(UNKNOWN_DYNAMIC_WARNING)

    confidence = reach.get("confidence")
    st.caption(f"Confidence: {confidence if confidence is not None else 'unknown'}")
    notes = escape_html(reach.get("notes") or "")
    st.markdown(
        html_document(f'<div class="card">{notes or "No additional notes."}</div>'),
        unsafe_allow_html=True,
    )

    paths = _paths_for(finding)
    if not paths or not any(paths):
        st.info("No call path is available for this finding.")
        return
    path_index = 0
    if len(paths) > 1:
        path_index = st.selectbox(
            "Call path",
            options=list(range(len(paths))),
            format_func=lambda index: f"Path {index + 1}",
        )
    st.markdown(callpath_html(paths[path_index]), unsafe_allow_html=True)
