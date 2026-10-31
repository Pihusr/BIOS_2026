import streamlit as st
from contracts import ScanResult

def render(scan: ScanResult) -> None:
    """Render the VEX export panel JSON."""
    st.json(scan)
