import streamlit as st
from contracts import ScanResult

def render(scan: ScanResult) -> None:
    """Render the findings panel JSON."""
    st.json(scan)
