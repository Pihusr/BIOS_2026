import streamlit as st
from contracts import ScanResult

def render(scan: ScanResult) -> None:
    """Render the dependency graph panel JSON."""
    st.json(scan)
