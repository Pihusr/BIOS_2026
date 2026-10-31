import os

import streamlit as st
from pipeline import run_scan, run_scan_url
from ui import findings_panel, graph_panel, callpath_panel, export_panel

st.set_page_config(page_title="Reachability-Aware Supply-Chain Security", layout="wide")
st.sidebar.title("Supply-Chain Scan")
public_mode = os.environ.get("HAWKEYE_PUBLIC") == "1"
if not public_mode:
    repo_path = st.sidebar.text_input("Repository path", "fixtures/ground_truth_repo")
github_url = st.sidebar.text_input("GitHub repository URL")
if st.sidebar.button("Scan"):
    with st.status("Downloading... Analysing... Querying OSV...") as status:
        scan_result = run_scan_url(github_url)
        status.update(
            label="Scan complete" if scan_result.get("ok") is not False else "Scan failed",
            state="complete" if scan_result.get("ok") is not False else "error",
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
for warning in dict.fromkeys(
    warning for warning in scan_warnings if isinstance(warning, str)
):
    st.warning(warning)

tabs = st.tabs(["Overview", "Dependency Graph", "Call Paths", "VEX Export"])
with tabs[0]: findings_panel.render(scan)
with tabs[1]: graph_panel.render(scan)
with tabs[2]: callpath_panel.render(scan)
with tabs[3]: export_panel.render(scan)
