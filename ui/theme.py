import base64
from pathlib import Path

import streamlit as st


def apply_hawkeye_theme() -> str:
    logo_path = Path(__file__).resolve().parent.parent / "assets" / "hawkeye_logo.svg"
    logo_data = base64.b64encode(logo_path.read_bytes()).decode("ascii")
    st.markdown(
        """
        <style>
        body,
        div[data-testid="stAppViewContainer"] {
            background-color: #080808;
            color: #F2F2F2;
        }

        section[data-testid="stSidebar"] {
            background: linear-gradient(180deg, #0F0F0F 72%, #3E072D 150%);
            border-right: 1px solid #2B2B2B;
        }

        .hawkeye-brand {
            display: flex;
            align-items: center;
            gap: 0.85rem;
            margin: 0.15rem 0 1.5rem;
        }

        .hawkeye-brand img {
            box-sizing: border-box;
            width: 64px;
            height: 64px;
            padding: 5px;
            flex: 0 0 64px;
            object-fit: contain;
            background: #F2F2F2;
            border: 1px solid #2B2B2B;
            border-radius: 12px;
        }

        .hawkeye-brand-name {
            color: #F2F2F2;
            font-size: 1.35rem;
            font-weight: 700;
            line-height: 1.2;
        }

        .hawkeye-brand-tagline {
            max-width: 13rem;
            margin-top: 0.3rem;
            color: #B3B3B3;
            font-size: 0.72rem;
            line-height: 1.35;
        }

        .hawkeye-splash {
            display: flex;
            flex-direction: column;
            align-items: center;
            padding-top: 6vh;
            text-align: center;
        }

        .hawkeye-splash img {
            box-sizing: border-box;
            width: min(400px, 70vw);
            height: min(400px, 70vw);
            padding: 18px;
            object-fit: contain;
            background: #F2F2F2;
            border: 1px solid #2B2B2B;
            border-radius: 24px;
        }

        .hawkeye-splash-name {
            margin-top: 1.1rem;
            color: #F2F2F2;
            font-size: clamp(2.5rem, 5vw, 4rem);
            font-weight: 700;
            line-height: 1.1;
        }

        div[data-testid="stTabs"] > div {
            width: 100%;
        }

        div[data-testid="stTabs"] [role="tablist"] {
            display: flex;
            align-items: stretch;
            width: 100%;
            gap: 0.35rem;
            border-bottom: 1px solid #2B2B2B;
        }

        div[data-testid="stTabs"] [data-testid="stTab"] {
            flex: 1 1 0;
            justify-content: center;
            min-width: 0;
            text-align: center;
            color: #B3B3B3;
            transition: color 160ms ease, transform 160ms ease,
                box-shadow 160ms ease, text-shadow 160ms ease;
        }

        div[data-testid="stTabs"] [data-testid="stTab"]:hover {
            color: #F2F2F2;
            transform: translateY(-2px);
        }

        div[data-testid="stTabs"] [data-testid="stTab"][aria-selected="true"] {
            z-index: 1;
            color: #E7A8A8;
            text-shadow: 0 0 12px #6B1C1C;
            box-shadow: 0 0 14px #6B1C1C;
            transform: scale(1.06);
        }

        @media (prefers-reduced-motion: reduce) {
            div[data-testid="stTabs"] [data-testid="stTab"] {
                transition: none;
                transform: none;
            }

            div[data-testid="stTabs"] [data-testid="stTab"]:hover,
            div[data-testid="stTabs"] [data-testid="stTab"][aria-selected="true"] {
                transform: none;
            }
        }

        button[data-testid^="stBaseButton-"] {
            transition: filter 140ms ease, transform 140ms ease;
        }

        button[data-testid^="stBaseButton-"]:hover {
            filter: brightness(1.18);
            transform: translateY(-1px);
        }

        button[data-testid^="stBaseButton-"]:focus-visible,
        input:focus-visible,
        textarea:focus-visible,
        [data-baseweb="select"]:focus-within {
            outline: 2px solid #D3B4D3;
            outline-offset: 2px;
        }

        a,
        a:visited {
            color: #9CC8FF;
        }

        input,
        textarea,
        [data-baseweb="select"] > div {
            background-color: #121212;
            border-color: #2A2A2A;
            color: #F2F2F2;
        }

        span[data-baseweb="tag"] {
            background-color: #3E072D;
            color: #F2F2F2;
        }

        div[data-testid="stFileUploaderDropzone"] {
            background-color: #121212;
            border: 1px dashed #6B1C1C;
            border-radius: 8px;
        }

        div[data-testid="stMetric"] {
            padding: 0.9rem;
            background-color: #0F0F0F;
            border: 1px solid #2B2B2B;
            border-radius: 8px;
        }

        div[data-testid="stExpander"] {
            background-color: #0F0F0F;
            border: 1px solid #2B2B2B;
            border-radius: 8px;
        }

        div[data-testid="stDataFrame"] {
            overflow: hidden;
            border: 1px solid #2B2B2B;
            border-radius: 8px;
        }

        div[data-testid="stAlert"] {
            border: 1px solid #2B2B2B;
            border-radius: 8px;
        }

        @media (prefers-reduced-motion: reduce) {
            button[data-testid^="stBaseButton-"] {
                transition: none;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    return f"data:image/svg+xml;base64,{logo_data}"
