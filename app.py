import streamlit as st
from pipeline import run_scan
from ui import findings_panel, graph_panel, callpath_panel, export_panel

st.set_page_config(page_title="Reachability-Aware Supply-Chain Security", layout="wide")
st.sidebar.title("Supply-Chain Scan")
repo_path = st.sidebar.text_input("Repository path", "fixtures/ground_truth_repo")
if st.sidebar.button("Scan ground-truth demo"):
    st.session_state["scan"] = run_scan(repo_path)
if "scan" not in st.session_state:
    st.session_state["scan"] = run_scan("fixtures/ground_truth_repo")
scan = st.session_state["scan"]
if not scan.get("ok", False):
    st.error(scan.get("error") or "Scan failed")

tabs = st.tabs(["Overview", "Dependency Graph", "Call Paths", "VEX Export"])
with tabs[0]: findings_panel.render(scan)
with tabs[1]: graph_panel.render(scan)
with tabs[2]: callpath_panel.render(scan)
with tabs[3]: export_panel.render(scan)
