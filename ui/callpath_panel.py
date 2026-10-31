import streamlit as st
from contracts import ScanResult

def render(scan: ScanResult) -> None:
    """Render the call-path panel JSON."""
    st.json(scan)
