import html
import os
from typing import Mapping

import streamlit as st

THEMES: dict[str, dict[str, str]] = {
    "danger": {
        "background": "#080808",
        "surface": "#0F0F0F",
        "border": "#2B2B2B",
        "accent": "#6B1C1C",
        "alert": "#4D0A0A",
        "secondary": "#3E072D",
        "text": "#EDEDED",
        "muted": "#A3A3A3",
    },
    "safe": {
        "background": "#0A0A0A",
        "surface": "#121212",
        "border": "#2A2A2A",
        "accent": "#1A4D2E",
        "alert": "#0F3818",
        "secondary": "#0C2B54",
        "text": "#EDEDED",
        "muted": "#A3A3A3",
    },
}

SEMANTIC_COLORS = {
    "safe": "#2ecc71",
    "suppressed": "#f1c40f",
    "reachable": "#e74c3c",
    "typosquat": "#9b59b6",
    "investigating": "#3498db",
}


def active_theme() -> dict[str, str]:
    """Return the selected palette, defaulting to the safe palette."""
    return THEMES.get(os.environ.get("HAWKEYE_THEME", "safe").lower(), THEMES["safe"])


def mix(color: str, background: str, amount: float) -> str:
    """Blend a hexadecimal foreground color over a background color."""
    amount = max(0.0, min(1.0, amount))
    foreground = tuple(int(color[index:index + 2], 16) for index in (1, 3, 5))
    base = tuple(int(background[index:index + 2], 16) for index in (1, 3, 5))
    channels = tuple(round(bg + (fg - bg) * amount) for fg, bg in zip(foreground, base))
    return "#" + "".join(f"{channel:02X}" for channel in channels)


def chip_colors(state: str, theme: Mapping[str, str]) -> tuple[str, str]:
    """Return dark fill and light text colors for a semantic state chip."""
    semantic = SEMANTIC_COLORS[state]
    return mix(semantic, theme["surface"], 0.2), mix(semantic, "#FFFFFF", 0.45)


def escape_html(value: object) -> str:
    """Escape untrusted text for generated HTML and PyVis labels."""
    return html.escape(str(value), quote=True)


def html_document(content: str, theme: Mapping[str, str] | None = None) -> str:
    """Wrap generated panel markup in the active palette's scoped styles."""
    palette = theme or active_theme()
    return f"""<style>
.hawkeye-ui {{ color: {palette["text"]}; font-family: sans-serif; }}
.hawkeye-ui .card {{ background: {palette["surface"]}; border: 1px solid {palette["border"]}; border-radius: 8px; padding: 12px; }}
.hawkeye-ui .chip {{ display: inline-block; border-radius: 999px; padding: 3px 9px; font-size: 0.85rem; }}
.hawkeye-ui .banner {{ border-radius: 8px; padding: 14px 16px; font-weight: 600; }}
.hawkeye-ui .banner-good {{ background: {mix(SEMANTIC_COLORS["safe"], palette["surface"], 0.2)}; color: {mix(SEMANTIC_COLORS["safe"], "#FFFFFF", 0.45)}; }}
.hawkeye-ui .banner-warning {{ background: {mix(SEMANTIC_COLORS["suppressed"], palette["surface"], 0.2)}; color: {mix(SEMANTIC_COLORS["suppressed"], "#FFFFFF", 0.45)}; border: 1px solid {palette["alert"]}; }}
.hawkeye-ui .secondary {{ background: {palette["secondary"]}; color: {palette["text"]}; }}
.hawkeye-ui .legend {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 8px 0; }}
.hawkeye-ui .legend-item {{ display: inline-flex; align-items: center; gap: 6px; }}
.hawkeye-ui .legend-shape {{ width: 11px; height: 11px; display: inline-block; }}
.hawkeye-ui .table-wrap {{ overflow-x: auto; }}
.hawkeye-ui table {{ width: 100%; border-collapse: collapse; color: {palette["text"]}; }}
.hawkeye-ui th, .hawkeye-ui td {{ border-bottom: 1px solid {palette["border"]}; padding: 8px; text-align: left; vertical-align: top; }}
.hawkeye-ui th {{ color: {palette["text"]}; }}
.hawkeye-ui .muted {{ color: {palette["muted"]}; }}
.hawkeye-ui .path-frame {{ padding: 5px 8px; border-left: 2px solid {palette["border"]}; }}
.hawkeye-ui .path-frame-vulnerable {{ background: {palette["secondary"]}; border-radius: 4px; }}
.hawkeye-ui :focus-visible {{ outline: 2px solid #EDEDED; outline-offset: 2px; }}
</style><div class="hawkeye-ui">{content}</div>"""


def show_degraded_warning(scan: Mapping[str, object]) -> None:
    """Show the manifest-only warning when reachability is degraded."""
    reach = scan.get("reach") or {}
    if isinstance(reach, Mapping) and reach.get("degraded") is True:
        st.warning(
            "Manifest-only mode: reachability could not be computed. "
            "CVEs are treated as affected, nothing is suppressed."
        )
