import json
from collections.abc import Mapping, Sequence

import streamlit as st

from contracts import ScanResult
from ui import show_degraded_warning


def statement_ids(document: Mapping[str, object], key: str) -> list[str]:
    """Extract stable identifiers from OpenVEX statements or CycloneDX vulnerabilities."""
    entries = document.get(key) or []
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        return []
    identifiers = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        vulnerability = entry.get("vulnerability")
        identifier = None
        if isinstance(vulnerability, Mapping):
            identifier = vulnerability.get("name") or vulnerability.get("id")
        identifier = identifier or entry.get("id") or entry.get("cve_id")
        if identifier:
            identifiers.append(str(identifier))
    return identifiers


def build_preview(document: Mapping[str, object], key: str) -> dict[str, object]:
    """Build a bounded preview with total count and the first three identifiers."""
    entries = document.get(key) or []
    safe_entries = entries if isinstance(entries, list) else []
    return {
        "count": len(safe_entries),
        "ids": statement_ids(document, key)[:3],
        "preview": safe_entries[:3],
    }


def render(scan: ScanResult) -> None:
    """Render validated VEX downloads and a short statement preview."""
    show_degraded_warning(scan)
    vex = scan.get("vex") or {}
    if not isinstance(vex, Mapping):
        vex = {}
    is_valid = vex.get("ok") is True
    error = vex.get("error") or "VEX validation failed"
    openvex = vex.get("openvex")
    cyclonedx_vex = vex.get("cyclonedx_vex")
    openvex = openvex if isinstance(openvex, Mapping) else {}
    cyclonedx_vex = cyclonedx_vex if isinstance(cyclonedx_vex, Mapping) else {}

    st.subheader("VEX Export")
    if not is_valid:
        st.error(str(error))
    openvex_col, cyclonedx_col = st.columns(2)
    openvex_col.download_button(
        "Download OpenVEX",
        data=json.dumps(openvex, indent=2),
        file_name="hawkeye-openvex.json",
        mime="application/json",
        disabled=not is_valid,
        key="hawkeye-openvex-download",
    )
    cyclonedx_col.download_button(
        "Download CycloneDX VEX",
        data=json.dumps(cyclonedx_vex, indent=2),
        file_name="hawkeye-cyclonedx-vex.json",
        mime="application/json",
        disabled=not is_valid,
        key="hawkeye-cyclonedx-vex-download",
    )

    openvex_preview = build_preview(openvex, "statements")
    cyclonedx_preview = build_preview(cyclonedx_vex, "vulnerabilities")
    openvex_ids = statement_ids(openvex, "statements")[:3]
    cyclonedx_ids = statement_ids(cyclonedx_vex, "vulnerabilities")[:3]
    st.caption(
        f"OpenVEX: {openvex_preview['count']} statements · "
        f"IDs: {', '.join(openvex_ids) or 'none'}"
    )
    st.code(json.dumps(openvex_preview, indent=2), language="json")
    st.caption(
        f"CycloneDX: {cyclonedx_preview['count']} vulnerabilities · "
        f"IDs: {', '.join(cyclonedx_ids) or 'none'}"
    )
    st.code(json.dumps(cyclonedx_preview, indent=2), language="json")
