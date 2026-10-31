import os

import streamlit as st
from pipeline import run_scan, run_scan_url, run_scan_zip
from ui import findings_panel, graph_panel, callpath_panel, export_panel
from ui.theme import apply_hawkeye_theme

_MAX_UPLOAD_BYTES = 10 * 1024 * 1024

st.set_page_config(page_title="HawkEye", layout="wide")
_logo_data_uri = apply_hawkeye_theme()
st.sidebar.markdown(
    f"""
    <div class="hawkeye-brand">
        <img src="{_logo_data_uri}" alt="" />
        <div>
            <div class="hawkeye-brand-name">HawkEye</div>
            <div class="hawkeye-brand-tagline">
                Reachability-aware supply-chain security
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)
public_mode = os.environ.get("HAWKEYE_PUBLIC") == "1"
repo_path = "fixtures/ground_truth_repo"
if not public_mode:
    with st.sidebar.expander("Advanced: local folder"):
        repo_path = st.text_input("Repository path", "fixtures/ground_truth_repo")
github_url = st.sidebar.text_input("GitHub repository URL")
if st.sidebar.button("Scan"):
    with st.status("Downloading... Analysing... Querying OSV...") as status:
        scan_result = run_scan_url(github_url)
        status.update(
            label="Scan complete" if scan_result.get("ok") is not False else "Scan failed",
            state="complete" if scan_result.get("ok") is not False else "error",
        )
    st.session_state["scan"] = scan_result
if hasattr(st.sidebar, "file_uploader"):
    uploaded_zip = st.sidebar.file_uploader(
        "Upload a project (.zip, max 10 MB)", type=["zip"]
    )
    upload_too_large = (
        uploaded_zip is not None and uploaded_zip.size > _MAX_UPLOAD_BYTES
    )
    if upload_too_large:
        st.error("ZIP upload exceeds the 10 MB limit.")
    if st.sidebar.button(
        "Scan upload", disabled=uploaded_zip is None or upload_too_large
    ):
        if uploaded_zip is None:
            st.error("Select a ZIP file to upload.")
        else:
            upload_data = uploaded_zip.getvalue()
            if len(upload_data) > _MAX_UPLOAD_BYTES:
                st.error("ZIP upload exceeds the 10 MB limit.")
            else:
                with st.status("Uploading... Analysing... Querying OSV...") as status:
                    scan_result = run_scan_zip(upload_data)
                    status.update(
                        label="Scan complete"
                        if scan_result.get("ok") is not False
                        else "Scan failed",
                        state="complete"
                        if scan_result.get("ok") is not False
                        else "error",
                    )
                st.session_state["scan"] = scan_result
if st.sidebar.button("Scan ground-truth demo"):
    with st.spinner("Scanning repository..."):
        demo_path = "fixtures/ground_truth_repo" if public_mode else repo_path
        st.session_state["scan"] = run_scan(demo_path)
if not public_mode and "scan" not in st.session_state:
    with st.spinner("Scanning repository..."):
        st.session_state["scan"] = run_scan("fixtures/ground_truth_repo")
if "scan" not in st.session_state:
    st.info("Scan a GitHub repository or choose the bundled demo to get started.")
    st.stop()
scan = st.session_state["scan"]
if scan.get("ok") is False:
    st.error(scan.get("error") or "Scan failed")
stage_names = ("sbom", "osv", "reach", "inspect", "vex")
scan_warnings = scan.get("warnings", [])
if not isinstance(scan_warnings, list):
    scan_warnings = []
for stage_name in stage_names:
    stage = scan.get(stage_name, {})
    if not isinstance(stage, dict):
        st.error(f"Invalid {stage_name} result")
        continue
    if stage.get("ok") is False:
        st.error(f"{stage_name} failed: {stage.get('error') or 'unspecified error'}")
    stage_warnings = stage.get("warnings", [])
    if isinstance(stage_warnings, list):
        scan_warnings.extend(
            warning for warning in stage_warnings if isinstance(warning, str)
        )
scan_notes = list(dict.fromkeys(w for w in scan_warnings if isinstance(w, str)))
reach_stage = scan.get("reach")
if isinstance(reach_stage, dict) and reach_stage.get("degraded"):
    st.error("Reachability analysis degraded: findings are shown without suppression.")

tabs = st.tabs(["Overview", "Dependency Graph", "Call Paths", "VEX Export"])
with tabs[0]: findings_panel.render(scan)
with tabs[1]: graph_panel.render(scan)
with tabs[2]: callpath_panel.render(scan)
with tabs[3]: export_panel.render(scan)
if scan_notes:
    with st.expander(f"Scan notes ({len(scan_notes)})"):
        for note in scan_notes:
            st.caption(note)
