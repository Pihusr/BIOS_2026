import streamlit as st
from pipeline import run_scan
from ui import findings_panel, graph_panel, callpath_panel, export_panel

st.set_page_config(page_title="Reachability-Aware Supply-Chain Security", layout="wide")
st.sidebar.title("Supply-Chain Scan")
repo_path = st.sidebar.text_input("Repository path", "fixtures/ground_truth_repo")
if st.sidebar.button("Scan ground-truth demo"):
    with st.spinner("Scanning repository..."):
        st.session_state["scan"] = run_scan(repo_path)
if "scan" not in st.session_state:
    with st.spinner("Scanning repository..."):
        st.session_state["scan"] = run_scan("fixtures/ground_truth_repo")
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
