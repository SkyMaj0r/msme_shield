"""
MSME Shield — Dashboard v3.0
------------------------------
Streamlit frontend for the Passive-Hybrid Cyber Risk Quantification Platform.

Pages:
    Overview   — MRQM hero card, pillar scores, CVE table, port scanner, 
                 active probe results.
    History    — MRQM trend chart, stacked pillar area, band timeline,
                 scan comparison.
    Governance — Tiered YES/NO checklist, live score preview, submission.

Design: Apple Light design system. No simulation flags. No sliders.
Run from frontend/ directory:
    streamlit run dashboard.py

Backend must be running at API_BASE_URL (default http://localhost:8000).
"""

from __future__ import annotations

# ===========================================================================
# SECTION 1 — Imports + Config + Design System + CSS
# ===========================================================================

import os
import sys
import tempfile
from datetime import datetime
from typing import Any

import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st

# ---------------------------------------------------------------------------
# CONTROL_META — import from risk_engine via path insertion
# ---------------------------------------------------------------------------
_backend_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend")
if _backend_path not in sys.path:
    sys.path.insert(0, _backend_path)

try:
    from risk_engine import ALL_CONTROLS  # type: ignore[import]
    CONTROL_META: dict[str, dict] = {c["key"]: c for c in ALL_CONTROLS}
except ImportError:
    # Fallback: minimal meta if backend import fails
    CONTROL_META = {}

try:
    from pdf_generator import generate_report as _pdf_generate_report  # type: ignore[import]
except ImportError:
    _pdf_generate_report = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Page config — MUST be first Streamlit call
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="MSME Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ---------------------------------------------------------------------------
# Design System Constants
# ---------------------------------------------------------------------------
PAGE_BG       = "#f5f5f7"
CARD_BG       = "#ffffff"
TEXT_1        = "#1d1d1f"
TEXT_2        = "rgba(0,0,0,0.80)"
TEXT_3        = "rgba(0,0,0,0.48)"
BLUE          = "#0071e3"
BLUE_DARK     = "#0066cc"
BLUE_LIGHT    = "#eaf3fe"
SHADOW        = "rgba(0,0,0,0.22) 3px 5px 30px 0px"
BORDER        = "rgba(0,0,0,0.16)"
SUCCESS       = "#34c759"
WARNING_COLOR = "#ff9f0a"
DANGER        = "#ff3b30"

FONT_DISPLAY = "-apple-system, 'SF Pro Display', 'Helvetica Neue', Arial, sans-serif"
FONT_TEXT    = "-apple-system, 'SF Pro Text', 'Helvetica Neue', Arial, sans-serif"

# ---------------------------------------------------------------------------
# API Config
# ---------------------------------------------------------------------------
API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000")

ENDPOINTS = {
    "health":         f"{API_BASE}/health",
    "latest":         f"{API_BASE}/api/scans/latest",
    "history":        f"{API_BASE}/api/scans/history",
    "governance":     f"{API_BASE}/api/scans/{{scan_id}}/governance",
    "check_ssl":      f"{API_BASE}/api/check-ssl",
    "allowlist_post": f"{API_BASE}/api/organizations/{{org_id}}/allowlist",
    "register":       f"{API_BASE}/api/auth/register",
    "login":          f"{API_BASE}/api/auth/login",
}

RISK_CONFIG: dict[str, dict] = {
    "LOW":      {"color": SUCCESS,       "label": "Low Risk",    "bg": "#f0fff4",  "emoji": "✅"},
    "MEDIUM":   {"color": WARNING_COLOR, "label": "Medium Risk", "bg": "#fffbeb",  "emoji": "⚠️"},
    "CRITICAL": {"color": DANGER,        "label": "Critical Risk","bg": "#fff5f5",  "emoji": "🚨"},
    "PENDING":  {"color": BLUE,          "label": "Pending",     "bg": BLUE_LIGHT, "emoji": "⏳"},
}

PORT_RISK_WEIGHTS: dict[int, float] = {
    3389: 85.0, 23: 90.0, 21: 70.0, 22: 40.0,
    445: 80.0, 1433: 75.0, 3306: 15.0, 5432: 15.0,
    8080: 30.0, 8443: 15.0, 80: 10.0, 443: 5.0,
    25: 60.0, 110: 55.0, 143: 55.0, 53: 35.0,
    161: 65.0, 5900: 80.0, 6379: 15.0, 27017: 15.0,
}

EPHEMERAL_THRESHOLD = 49151

TIER_1_KEYS = [
    "log_retention", "incident_reporting", "incident_plan",
    "mfa_enabled", "ntp_sync", "offline_backup",
    "least_privilege", "patch_management",
    "phishing_training", "firewall_segmentation",
]
TIER_2_KEYS = [
    "asset_inventory", "vulnerability_disclosure",
    "privileged_access_ws", "security_logging", "vendor_risk",
]
TIER_3_KEYS = [
    "penetration_testing", "data_classification",
    "bcp_drp_tested", "vapt_remediation", "dedicated_ir_team",
]
ALL_GOV_KEYS = TIER_1_KEYS + TIER_2_KEYS + TIER_3_KEYS

# Raw weights (mirror of risk_engine.py for live score preview)
_RAW_WEIGHTS: dict[str, int] = {
    "log_retention": 5, "incident_reporting": 5, "incident_plan": 4,
    "mfa_enabled": 4, "ntp_sync": 3, "offline_backup": 3,
    "least_privilege": 3, "patch_management": 3,
    "phishing_training": 2, "firewall_segmentation": 2,
    "asset_inventory": 3, "vulnerability_disclosure": 3,
    "privileged_access_ws": 3, "security_logging": 3, "vendor_risk": 2,
    "penetration_testing": 3, "data_classification": 3,
    "bcp_drp_tested": 3, "vapt_remediation": 2, "dedicated_ir_team": 2,
}

# Port service names for display
PORT_SERVICE_NAMES: dict[int, str] = {
    3389: "RDP",     23: "Telnet",   21: "FTP",         22: "SSH",
    445: "SMB",      1433: "MSSQL",  3306: "MySQL",     5432: "PostgreSQL",
    8080: "HTTP-alt",8443: "HTTPS-alt", 80: "HTTP",     443: "HTTPS",
    25: "SMTP",      110: "POP3",    143: "IMAP",       53: "DNS",
    161: "SNMP",     5900: "VNC",    6379: "Redis",     27017: "MongoDB",
}


def _html(html: str) -> None:
    """Render HTML via st.markdown, collapsing indented lines so markdown never sees a code block."""
    clean = " ".join(line.strip() for line in html.splitlines() if line.strip())
    st.markdown(clean, unsafe_allow_html=True)


def inject_css() -> None:
    """Inject Apple Light design system CSS overrides into the Streamlit app."""
    st.markdown(
        """
        <style>
        /* ── Base ── */
        [data-testid="stAppViewContainer"] {
            background-color: #f5f5f7 !important;
            font-family: -apple-system, "SF Pro Text", "Helvetica Neue", Arial, sans-serif;
        }

        [data-testid="stHeader"] {
            display: none !important;
        }

        header[data-testid="stHeader"] {
            display: none !important;
        }

        /* ── Hide Streamlit chrome ── */
        #MainMenu, footer,
        [data-testid="stToolbar"],
        [data-testid="stDecoration"] {
            visibility: hidden !important;
            height: 0 !important;
        }

        /* ── Remove default top padding ── */
        [data-testid="stAppViewBlockContainer"] {
            padding-top: 0.5rem !important;
            max-width: 100% !important;
        }

        /* ── Inputs ── */
        .stTextInput > div > div > input,
        .stPasswordInput > div > div > input {
            background: #ffffff !important;
            border: 1px solid rgba(0,0,0,0.16) !important;
            border-radius: 8px !important;
            color: #1d1d1f !important;
            caret-color: #1d1d1f !important;
            font-size: 17px !important;
            letter-spacing: -0.374px !important;
            padding: 10px 14px !important;
        }

        .stTextInput > div > div > input:focus,
        .stPasswordInput > div > div > input:focus {
            border-color: #0071e3 !important;
            box-shadow: 0 0 0 3px rgba(0,113,227,0.15) !important;
            outline: none !important;
        }

        /* ── Buttons ── */
        .stButton > button {
            border-radius: 8px !important;
            font-family: -apple-system, "SF Pro Text", "Helvetica Neue", Arial, sans-serif !important;
            font-size: 15px !important;
            letter-spacing: -0.224px !important;
            transition: all 0.2s ease !important;
        }

        /* ── Expander ── */
        .streamlit-expanderHeader {
            background: #ffffff !important;
            border-radius: 8px !important;
            font-size: 14px !important;
            color: #1d1d1f !important;
            letter-spacing: -0.224px !important;
        }

        /* ── Dataframe ── */
        .stDataFrame {
            border-radius: 12px !important;
            overflow: hidden !important;
        }

        /* ── Selectbox ── */
        [data-testid="stSelectbox"] div[data-baseweb="select"] > div:first-child {
            background: #ffffff !important;
            border: 1px solid rgba(0,0,0,0.16) !important;
            border-radius: 8px !important;
            color: #1d1d1f !important;
        }
        [data-testid="stSelectbox"] div[data-baseweb="select"] span {
            color: #1d1d1f !important;
        }
        [data-testid="stSelectbox"] div[data-baseweb="select"] svg {
            fill: #1d1d1f !important;
            color: #1d1d1f !important;
        }

        /* ── Alert boxes ── */
        .stAlert {
            border-radius: 12px !important;
            border: none !important;
        }

        /* ── Metric containers ── */
        [data-testid="metric-container"] {
            background: #ffffff !important;
            border-radius: 12px !important;
            padding: 20px !important;
            box-shadow: rgba(0,0,0,0.22) 3px 5px 30px 0px !important;
            border: none !important;
        }

        /* ── Scrollbar ── */
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb {
            background: rgba(0,0,0,0.2);
            border-radius: 3px;
        }

        /* ── Sidebar collapsed ── */
        [data-testid="collapsedControl"] {
            display: none !important;
        }

        /* ── Spinner ── */
        .stSpinner > div {
            border-top-color: #0071e3 !important;
        }

        /* ── Download button ── */
        [data-testid="stDownloadButton"] > button {
            background: #ffffff !important;
            color: #0071e3 !important;
            border: 1.5px solid #0071e3 !important;
            border-radius: 8px !important;
            font-size: 15px !important;
            font-weight: 500 !important;
            letter-spacing: -0.224px !important;
            padding: 8px 20px !important;
            transition: all 0.2s ease !important;
        }
        [data-testid="stDownloadButton"] > button:hover {
            background: #0071e3 !important;
            color: #ffffff !important;
        }

        /* ── Checkbox ── */
        .stCheckbox > label {
            font-size: 15px !important;
            letter-spacing: -0.224px !important;
            color: #1d1d1f !important;
        }

        /* ── Nav buttons ── */
        div[data-testid="stHorizontalBlock"] button {
            background-color: #F0EFEB !important;
            color: #1a1a1a !important;
            border: 1px solid #d0cfc9 !important;
            border-radius: 10px !important;
        }
        div[data-testid="stHorizontalBlock"] button[kind="primary"],
        div[data-testid="stHorizontalBlock"] button:focus {
            background-color: #E8412A !important;
            color: #ffffff !important;
            border: none !important;
        }

        /* ── Selectbox labels ── */
        div[data-testid="stSelectbox"] label p {
            font-size: 15px !important;
            color: #1a1a1a !important;
            font-weight: 600 !important;
        }

        /* ── Global font sizes ── */
        section[data-testid="stSidebar"] * {
            font-size: 14px !important;
        }
        div[data-testid="stMarkdownContainer"] p {
            font-size: 14px !important;
            color: #1a1a1a !important;
        }
        div[data-testid="metric-container"] label {
            font-size: 13px !important;
            color: rgba(0,0,0,0.6) !important;
        }

        /* ── MSME Shield brand title ── */
        /* Streamlit overrides color via -webkit-text-fill-color;
           we must set both to guarantee visibility.              */
        .msme-brand {
            padding: 14px 0;
            font-family: -apple-system, "SF Pro Display", "Helvetica Neue", Arial, sans-serif;
            font-size: 20px;
            font-weight: 700;
            letter-spacing: -0.28px;
            color: #1d1d1f !important;
            -webkit-text-fill-color: #1d1d1f !important;
        }

        /* ── Org name inline (no box, sits next to brand) ── */
        .org-inline-name {
            font-family: -apple-system, "SF Pro Text", "Helvetica Neue", Arial, sans-serif;
            font-size: 15px;
            font-weight: 500;
            color: rgba(0,0,0,0.52) !important;
            -webkit-text-fill-color: rgba(0,0,0,0.52) !important;
            white-space: nowrap;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


# ===========================================================================
# SECTION 2 — Helper functions + API functions
# ===========================================================================

def init_session_state() -> None:
    """Initialise all session state keys with safe defaults."""
    defaults: dict[str, Any] = {
        "page":           "overview",
        "org_name":       "Test MSME",
        "scan_result":    None,
        "scan_history":   None,
        "backend_ok":     False,
        "gov_answers":    {k: False for k in ALL_GOV_KEYS},
        "maturity":       "basic",
        "gov_submitted":  False,
        "history_filter": "all",
        # --- auth ---
        "authenticated":  False,
        "org_id":         "",
        "business_name":  "",
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val

    # Ensure gov_answers always contains all 20 keys (in case of upgrade)
    for k in ALL_GOV_KEYS:
        if k not in st.session_state["gov_answers"]:
            st.session_state["gov_answers"][k] = False


def api_health() -> bool:
    """GET /health — returns True if backend is reachable and healthy."""
    try:
        r = requests.get(ENDPOINTS["health"], timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def api_latest_scan(org_name: str) -> dict | None:
    """GET /api/scans/latest?org_name=... — returns scan dict or None."""
    try:
        r = requests.get(
            ENDPOINTS["latest"],
            params={"org_name": org_name},
            timeout=15,
        )
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404:
            return None
        return None
    except Exception:
        return None


@st.cache_data(ttl=30)
def api_scan_history(org_name: str) -> list:
    """GET /api/scans/history?org_name=... — returns list of scan summaries (cached 30s)."""
    try:
        r = requests.get(
            ENDPOINTS["history"],
            params={"org_name": org_name},
            timeout=15,
        )
        if r.status_code == 200:
            return r.json()
        return []
    except Exception:
        return []


def load_data() -> None:
    """Check backend health, then load latest scan and history into session state."""
    org = st.session_state.get("org_name", "Test MSME")

    # Health check
    st.session_state["backend_ok"] = api_health()

    if not st.session_state["backend_ok"]:
        return

    # Latest scan — never cached (always fresh)
    result = api_latest_scan(org)
    if result:
        st.session_state["scan_result"] = result
        # Sync maturity from scan if available (don't override user's explicit choice)
        if "maturity" not in st.session_state:
            st.session_state["maturity"] = "basic"
    else:
        st.session_state["scan_result"] = None

    # History — cached 30s
    history = api_scan_history(org)
    st.session_state["scan_history"] = history


def simple_password_score(password: str) -> int:
    """
    Local password strength estimate — returns 0 to 4.
    Does NOT call any external library. Used for UI indicator only.

    Scoring:
        Each criterion adds 1 point (max 4):
        - Length ≥ 12
        - Contains uppercase letter
        - Contains digit
        - Contains special character
    """
    if not password:
        return 0
    score = 0
    if len(password) >= 12:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password):
        score += 1
    return score


def get_risk_color(score: float) -> str:
    """Map a 0–100 score to the appropriate MRQM risk colour."""
    if score < 40:
        return SUCCESS
    if score < 70:
        return WARNING_COLOR
    return DANGER


def format_timestamp(ts: str) -> str:
    """Convert ISO-8601 timestamp string to human-readable '12 Apr 2026, 17:47'."""
    if not ts:
        return "—"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%-d %b %Y, %H:%M")
    except Exception:
        return ts[:16] if len(ts) >= 16 else ts


def _card(content_html: str, extra_style: str = "") -> None:
    """Render a standard Apple-style white card with shadow."""
    _html(
        f"""
        <div style='
            background: #ffffff;
            border-radius: 12px;
            box-shadow: {SHADOW};
            padding: 24px;
            {extra_style}
        '>{content_html}</div>
        """
        )


def _badge(label: str, color: str, bg: str) -> str:
    """Return an inline HTML pill badge."""
    return (
        f"<span style='"
        f"background:{bg}; color:{color}; font-size:12px; font-weight:600; "
        f"padding:3px 10px; border-radius:980px; letter-spacing:-0.12px; "
        f"display:inline-block;'>{label}</span>"
    )


def _section_header(title: str, subtitle: str = "") -> None:
    """Render a section header with optional subtitle."""
    sub = f"<div style='font-size:13px;color:{TEXT_3};letter-spacing:-0.12px;margin-top:2px;'>{subtitle}</div>" if subtitle else ""
    _html(
        f"""
        <div style='margin-bottom:16px;'>
            <div style='font-size:20px;font-weight:600;color:{TEXT_1};
                        font-family:{FONT_DISPLAY};letter-spacing:-0.28px;'>{title}</div>
            {sub}
        </div>
        """
        )


def _compute_gov_preview_score(answers: dict[str, bool], maturity: str) -> tuple[float, int, int]:
    """
    Compute a live governance score preview from the current answers dict.

    Returns:
        (preview_score: float, compliant_count: int, total_count: int)
    """
    if maturity == "advanced":
        keys = TIER_1_KEYS + TIER_2_KEYS + TIER_3_KEYS
    elif maturity == "intermediate":
        keys = TIER_1_KEYS + TIER_2_KEYS
    else:
        keys = TIER_1_KEYS

    total_raw = sum(_RAW_WEIGHTS.get(k, 3) for k in keys)
    score = 0.0
    compliant = 0
    for k in keys:
        if answers.get(k, False):
            score += (_RAW_WEIGHTS.get(k, 3) / total_raw) * 100
            compliant += 1
    return round(score, 2), compliant, len(keys)


def _do_generate_pdf(scan: dict) -> None:
    """Generate PDF from scan + session_state, store bytes in st.session_state['pdf_bytes']."""
    if _pdf_generate_report is None:
        st.error("PDF generator not available (pdf_generator.py import failed).")
        return

    scan_data = {**scan}
    scan_data["organization_name"] = st.session_state.get("org_name", "Test MSME")
    scan_data["it_maturity"] = st.session_state.get("maturity", "basic")

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".pdf")
    os.close(tmp_fd)
    try:
        result = _pdf_generate_report(scan_data, tmp_path)
        if result:
            with open(tmp_path, "rb") as f:
                st.session_state["pdf_bytes"] = f.read()
        else:
            st.error("PDF generation failed — check backend logs.")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ===========================================================================
# SECTION 3 — Auth page + Navbar + routing logic
# ===========================================================================

def _parse_api_error(resp: "requests.Response", fallback: str) -> str:
    """
    Extract a human-readable error string from a non-success API response.
    Guards against empty bodies, HTML responses, and FastAPI list-style
    validation errors so callers never see a raw JSONDecodeError.
    """
    try:
        body = resp.json()
        detail = body.get("detail", fallback) if isinstance(body, dict) else fallback
        if isinstance(detail, list):
            # FastAPI 422 validation errors: [{"loc":..., "msg":..., "type":...}]
            msgs = [d.get("msg", str(d)) for d in detail if isinstance(d, dict)]
            return "; ".join(msgs) if msgs else fallback
        return str(detail)
    except Exception:
        return f"{fallback} (HTTP {resp.status_code})"


def show_auth_page() -> None:
    """
    Full-page login / register card shown when the user is not authenticated.
    On success stores org_id, business_name, org_name in session_state and
    sets authenticated=True, then calls st.rerun().
    """
    # Centre the card with narrow columns
    _, centre, _ = st.columns([1, 2, 1])

    with centre:
        _html(
            f"""
            <div style='
                text-align: center;
                padding: 48px 0 24px;
                font-family: {FONT_DISPLAY};
            '>
                <div style='font-size: 48px; margin-bottom: 8px;'>🛡️</div>
                <div style='
                    font-size: 28px;
                    font-weight: 700;
                    color: {TEXT_1};
                    letter-spacing: -0.28px;
                '>MSME Shield</div>
                <div style='
                    font-size: 15px;
                    color: {TEXT_3};
                    margin-top: 6px;
                    letter-spacing: -0.224px;
                '>Cyber Risk Quantification Platform</div>
            </div>
            """
            )

        tab_login, tab_register = st.tabs(["Sign In", "Register"])

        # ------------------------------------------------------------------ #
        # Sign In tab                                                          #
        # ------------------------------------------------------------------ #
        with tab_login:
            with st.form("login_form"):
                email = st.text_input("Email", placeholder="you@company.com")
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button(
                    "Sign In", use_container_width=True, type="primary"
                )

            if submitted:
                if not email or not password:
                    st.error("Please enter your email and password.")
                else:
                    try:
                        resp = requests.post(
                            ENDPOINTS["login"],
                            json={"email": email, "password": password},
                            timeout=10,
                        )
                        if resp.status_code == 200:
                            data = resp.json()
                            st.session_state["authenticated"]  = True
                            st.session_state["org_id"]         = data["org_id"]
                            st.session_state["business_name"]  = data["business_name"]
                            st.session_state["org_name"]       = data["business_name"]
                            st.rerun()
                        else:
                            detail = _parse_api_error(resp, "Login failed.")
                            st.error(detail)
                    except requests.exceptions.ConnectionError:
                        st.error("Cannot reach the backend. Make sure it is running on port 8000.")
                    except Exception as exc:
                        st.error(f"Unexpected error: {exc}")

        # ------------------------------------------------------------------ #
        # Register tab                                                         #
        # ------------------------------------------------------------------ #
        with tab_register:
            with st.form("register_form"):
                biz_name  = st.text_input("Business Name", placeholder="Sharma Textiles Pvt Ltd")
                reg_email = st.text_input("Email", placeholder="owner@company.com")
                reg_pass  = st.text_input(
                    "Password",
                    type="password",
                    help="Minimum 8 characters.",
                )
                sector = st.selectbox(
                    "Sector",
                    ["Manufacturing", "Retail", "Services", "IT", "Other"],
                )
                emp_count = st.number_input(
                    "Employee Count", min_value=1, value=10, step=1
                )
                gst = st.text_input(
                    "GST / Udyam Number (optional)", placeholder="UDYAM-XX-00-0000000"
                )
                reg_submitted = st.form_submit_button(
                    "Register", use_container_width=True, type="primary"
                )

            if reg_submitted:
                if not biz_name or not reg_email or not reg_pass:
                    st.error("Business name, email, and password are required.")
                elif len(reg_pass) < 8:
                    st.error("Password must be at least 8 characters.")
                else:
                    try:
                        resp = requests.post(
                            ENDPOINTS["register"],
                            json={
                                "business_name":  biz_name,
                                "email":          reg_email,
                                "password":       reg_pass,
                                "sector":         sector.lower() if sector else "other",
                                "employee_count": int(emp_count),
                                "gst_number":     gst,
                            },
                            timeout=10,
                        )
                        if resp.status_code in (200, 201):
                            data = resp.json()
                            st.session_state["authenticated"]  = True
                            st.session_state["org_id"]         = data["org_id"]
                            st.session_state["business_name"]  = data["business_name"]
                            st.session_state["org_name"]       = data["business_name"]
                            st.rerun()
                        else:
                            detail = _parse_api_error(resp, "Registration failed.")
                            st.error(detail)
                    except requests.exceptions.ConnectionError:
                        st.error("Cannot reach the backend. Make sure it is running on port 8000.")
                    except Exception as exc:
                        st.error(f"Unexpected error: {exc}")


def render_navbar() -> None:
    """Render the top navigation bar — brand + org name left, 4 nav buttons right."""
    nav_left, nav_right = st.columns([5, 7])

    with nav_left:
        biz = (
            st.session_state.get("business_name")
            or st.session_state.get("org_name")
            or "My Organisation"
        )
        _html(
            f"""
            <div style='display:flex; align-items:center; gap:14px; padding:14px 0;'>
                <span class='msme-brand'>🛡️ MSME Shield</span>
                <span style='color:rgba(0,0,0,0.18); font-size:20px; line-height:1;'>|</span>
                <span class='org-inline-name'>🏢 {biz}</span>
            </div>
            """
            )

    with nav_right:
        n1, n2, n3, n4 = st.columns(4)
        current_page = st.session_state.get("page", "overview")

        with n1:
            if st.button(
                "Overview",
                type="primary" if current_page == "overview" else "secondary",
                use_container_width=True,
                key="nav_overview",
            ):
                st.session_state["page"] = "overview"
                st.rerun()

        with n2:
            if st.button(
                "History",
                type="primary" if current_page == "history" else "secondary",
                use_container_width=True,
                key="nav_history",
            ):
                st.session_state["page"] = "history"
                st.rerun()

        with n3:
            if st.button(
                "Governance",
                type="primary" if current_page == "governance" else "secondary",
                use_container_width=True,
                key="nav_governance",
            ):
                st.session_state["page"] = "governance"
                st.rerun()

        with n4:
            if st.button(
                "Sign Out",
                type="secondary",
                use_container_width=True,
                key="nav_signout",
            ):
                for key in list(st.session_state.keys()):
                    del st.session_state[key]
                st.rerun()

    # Full-width divider
    st.markdown(
        """
        <hr style='
            border: none;
            border-top: 1px solid rgba(0,0,0,0.08);
            margin: 0 0 24px 0;
        '/>
        """,
        unsafe_allow_html=True,
    )


# ===========================================================================
# SECTION 4 — Overview page
# ===========================================================================

def _render_pillar_card(
    icon: str,
    label: str,
    score_display: str,
    weight_label: str,
    score_val: float,
    color: str,
    subtitle: str,
) -> None:
    """Render a single pillar score card with progress bar."""
    pct = min(max(score_val, 0), 100)
    _html(
        f"""
        <div style='
            background: #ffffff;
            border-radius: 12px;
            box-shadow: {SHADOW};
            padding: 24px;
            border-top: 4px solid {color};
            height: 100%;
        '>
            <div style='font-size:24px'>{icon}</div>
            <div style='
                font-size:13px;
                color:{TEXT_3};
                letter-spacing:-0.12px;
                text-transform:uppercase;
                margin: 8px 0 4px;
                font-family:{FONT_TEXT};
            '>{label}</div>
            <div style='
                font-size:40px;
                font-weight:600;
                color:{color};
                letter-spacing:-0.28px;
                line-height:1.1;
                font-family:{FONT_DISPLAY};
            '>{score_display}</div>
            <div style='
                font-size:12px;
                color:{TEXT_3};
                letter-spacing:-0.12px;
                margin-top:4px;
                font-family:{FONT_TEXT};
            '>{weight_label}</div>
            <div style='
                height:4px;
                background:#f5f5f7;
                border-radius:2px;
                margin-top:12px;
                overflow:hidden;
            '>
                <div style='
                    height:100%;
                    width:{pct}%;
                    background:{color};
                    border-radius:2px;
                    transition: width 0.4s ease;
                '></div>
            </div>
            <div style='
                font-size:12px;
                color:{TEXT_3};
                margin-top:8px;
                letter-spacing:-0.12px;
                font-family:{FONT_TEXT};
            '>{subtitle}</div>
        </div>
        """
        )


def _render_cve_table(rows: list[dict]) -> None:
    """Render CVE findings as a styled div-grid table matching the Network Exposure theme."""
    col_style = "grid-template-columns:1fr 90px 130px 58px 72px"
    headers   = ("Software", "Version", "CVE ID", "CVSS", "EPSS")

    header_html = (
        f"<div style='display:grid;{col_style};background:#ECEAE4;"
        f"padding:8px 12px;border-radius:12px 12px 0 0;border-bottom:1px solid rgba(0,0,0,0.06);'>"
        + "".join(
            f"<span style='font-size:11px;text-transform:uppercase;color:{TEXT_3};"
            f"letter-spacing:0.5px;font-weight:600;'>{h}</span>"
            for h in headers
        )
        + "</div>"
    )

    rows_html = ""
    for i, r in enumerate(rows):
        row_bg  = "#F5F4F0" if i % 2 == 0 else "#ECEAE4"
        cvss    = r.get("CVSS", 0.0)
        cve_id  = r.get("CVE ID", "")
        version = r.get("Version", "")

        if isinstance(cvss, float) and cvss >= 9.0:
            cvss_badge = f"<span style='background:#fff5f5;color:{DANGER};font-size:11px;padding:2px 6px;border-radius:6px;font-weight:600;'>{cvss:.1f}</span>"
        elif isinstance(cvss, float) and cvss >= 7.0:
            cvss_badge = f"<span style='background:#fff8ec;color:{WARNING_COLOR};font-size:11px;padding:2px 6px;border-radius:6px;font-weight:600;'>{cvss:.1f}</span>"
        elif isinstance(cvss, float) and cvss >= 4.0:
            cvss_badge = f"<span style='background:#f0fff4;color:{SUCCESS};font-size:11px;padding:2px 6px;border-radius:6px;font-weight:600;'>{cvss:.1f}</span>"
        elif isinstance(cvss, float) and cvss > 0:
            cvss_badge = f"<span style='font-size:13px;color:{TEXT_3};'>{cvss:.1f}</span>"
        else:
            cvss_badge = f"<span style='font-size:12px;color:{TEXT_3};'>—</span>"

        eol_tag = ""
        if "⚠️ EOL" in version or "EOL" in version:
            clean_ver = version.replace(" ⚠️ EOL", "").replace(" EOL", "")
            eol_tag   = f"<span style='font-size:10px;color:{WARNING_COLOR};background:#fffbeb;padding:1px 5px;border-radius:4px;margin-left:4px;'>EOL</span>"
        else:
            clean_ver = version

        rows_html += (
            f"<div style='display:grid;{col_style};background:{row_bg};"
            f"padding:10px 12px;border-top:1px solid rgba(0,0,0,0.04);'>"
            f"<span style='font-weight:500;color:{TEXT_1};font-size:13px;'>{r.get('Software','')}</span>"
            f"<span style='color:{TEXT_2};font-size:13px;'>{clean_ver}{eol_tag}</span>"
            f"<span style='font-size:12px;color:{TEXT_2};font-family:monospace;'>{cve_id}</span>"
            f"<span>{cvss_badge}</span>"
            f"<span style='font-size:12px;color:{TEXT_3};'>{r.get('EPSS','—')}</span>"
            f"</div>"
        )

    st.markdown(
        f"<div style='border-radius:12px;overflow:hidden;box-shadow:{SHADOW};'>"
        f"{header_html}{rows_html}</div>",
        unsafe_allow_html=True,
    )


def _render_port_table(ports: list[dict], allowlisted_ports: list[dict]) -> None:
    """Render the scored ports as a clean HTML table with risk badges."""
    allowlisted_set = {p["port"] for p in allowlisted_ports}
    filtered = [p for p in ports if p.get("port", 0) <= EPHEMERAL_THRESHOLD]

    if not filtered:
        st.markdown(
            f"<div style='color:{TEXT_3};font-size:14px;padding:16px 0;'>No non-ephemeral ports detected.</div>",
            unsafe_allow_html=True,
        )
        return

    col_style = "grid-template-columns:100px 1fr 130px 70px"
    header_html = (
        f"<div style='display:grid;{col_style};background:#ECEAE4;"
        f"padding:8px 12px;border-radius:12px 12px 0 0;border-bottom:1px solid rgba(0,0,0,0.06);'>"
        + "".join(
            f"<span style='font-size:11px;text-transform:uppercase;color:{TEXT_3};"
            f"letter-spacing:0.5px;font-weight:600;'>{h}</span>"
            for h in ("Port", "Service", "Risk", "Weight")
        )
        + "</div>"
    )

    rows_html = ""
    for i, p in enumerate(filtered):
        port_num = p.get("port", 0)
        service  = PORT_SERVICE_NAMES.get(port_num, p.get("service", "Unknown"))
        weight   = PORT_RISK_WEIGHTS.get(port_num, 5.0)
        is_allow = port_num in allowlisted_set
        row_bg   = "#F5F4F0" if i % 2 == 0 else "#ECEAE4"

        if is_allow:
            badge = f"<span style='background:#f0fff4;color:{SUCCESS};font-size:11px;padding:2px 8px;border-radius:980px;'>&#10003; Allowlisted</span>"
        elif weight >= 70:
            badge = f"<span style='background:#fff5f5;color:{DANGER};font-size:11px;padding:2px 8px;border-radius:980px;'>Critical</span>"
        elif weight >= 40:
            badge = f"<span style='background:#fffbeb;color:{WARNING_COLOR};font-size:11px;padding:2px 8px;border-radius:980px;'>Medium</span>"
        else:
            badge = f"<span style='background:#f5f5f7;color:{TEXT_3};font-size:11px;padding:2px 8px;border-radius:980px;'>Low</span>"

        rows_html += (
            f"<div style='display:grid;{col_style};background:{row_bg};"
            f"padding:10px 12px;border-top:1px solid rgba(0,0,0,0.04);'>"
            f"<span style='font-weight:600;color:{TEXT_1};font-size:14px;letter-spacing:-0.224px;'>{port_num}</span>"
            f"<span style='color:{TEXT_2};font-size:14px;'>{service}</span>"
            f"<span>{badge}</span>"
            f"<span style='font-size:14px;color:{TEXT_3};'>{weight:.0f}</span>"
            f"</div>"
        )

    st.markdown(
        f"<div style='border-radius:12px;overflow:hidden;box-shadow:{SHADOW};'>"
        f"{header_html}{rows_html}</div>",
        unsafe_allow_html=True,
    )


def page_overview() -> None:
    """Render the Overview page — MRQM hero, pillar cards, CVE table, ports, active probes."""
    scan: dict | None = st.session_state.get("scan_result")

    # ── Onboarding card (no scan) ──────────────────────────────────────────
    if not scan:
        st.markdown("<div style='height:40px'></div>", unsafe_allow_html=True)
        _, col, _ = st.columns([1, 2, 1])
        with col:
            _html(
                f"""
                <div style='
                    background:#ffffff;
                    border-radius:20px;
                    box-shadow:{SHADOW};
                    padding:48px 40px;
                    text-align:center;
                '>
                    <div style='font-size:48px;margin-bottom:16px;'>🛡️</div>
                    <div style='font-size:28px;font-weight:600;color:{TEXT_1};
                                letter-spacing:-0.28px;font-family:{FONT_DISPLAY};
                                margin-bottom:8px;'>Welcome to MSME Shield</div>
                    <div style='font-size:17px;color:{TEXT_3};letter-spacing:-0.374px;
                                margin-bottom:32px;'>
                        Run the agent on your machine to begin your first scan.
                    </div>
                    <div style='text-align:left;max-width:340px;margin:0 auto;'>
                        <div style='display:flex;align-items:center;margin-bottom:16px;gap:12px;'>
                            <div style='width:28px;height:28px;border-radius:50%;background:{BLUE};
                                        color:#fff;display:flex;align-items:center;justify-content:center;
                                        font-size:13px;font-weight:700;flex-shrink:0;line-height:28px;text-align:center;
                                        '>1</div>
                            <div style='font-size:15px;color:{TEXT_2};letter-spacing:-0.224px;'>
                                Run <strong>sensor.py</strong> (or the .exe) on your machine
                            </div>
                        </div>
                        <div style='display:flex;align-items:center;margin-bottom:16px;gap:12px;'>
                            <div style='width:28px;height:28px;border-radius:50%;background:{BLUE};
                                        color:#fff;display:flex;align-items:center;justify-content:center;
                                        font-size:13px;font-weight:700;flex-shrink:0;line-height:28px;text-align:center;
                                        '>2</div>
                            <div style='font-size:15px;color:{TEXT_2};letter-spacing:-0.224px;'>
                                Return to this dashboard — your scan will load automatically
                            </div>
                        </div>
                        <div style='display:flex;align-items:center;gap:12px;'>
                            <div style='width:28px;height:28px;border-radius:50%;background:{BLUE};
                                        color:#fff;display:flex;align-items:center;justify-content:center;
                                        font-size:13px;font-weight:700;flex-shrink:0;line-height:28px;text-align:center;
                                        '>3</div>
                            <div style='font-size:15px;color:{TEXT_2};letter-spacing:-0.224px;'>
                                Complete the Governance checklist to get your full MRQM score
                            </div>
                        </div>
                    </div>
                </div>
                """
                )
        return

    status    = scan.get("status", "pending_governance")
    risk_band = scan.get("risk_band", "PENDING")
    band_cfg  = RISK_CONFIG.get(risk_band, RISK_CONFIG["PENDING"])
    band_color = band_cfg["color"]

    is_pending = (status != "complete")
    score_val  = scan.get("tech_score", 0.0) if is_pending else scan.get("mrqm_score", 0.0)
    score_label = "Tech Score (preview)" if is_pending else "MRQM Score"
    ts_str     = format_timestamp(scan.get("timestamp", ""))

    # ── SECTION 1: MRQM Hero Card ──────────────────────────────────────────
    with st.container():
        hero_left, hero_right = st.columns([55, 45])

        with hero_left:
            # Risk band pill
            _html(
                f"""
                <div style='margin-bottom:16px;'>
                    {_badge(f"{band_cfg['emoji']}  {band_cfg['label']}", band_color, band_cfg['bg'])}
                </div>
                <div style='
                    font-size:72px;
                    font-weight:700;
                    color:{band_color};
                    line-height:1.0;
                    letter-spacing:-0.28px;
                    font-family:{FONT_DISPLAY};
                '>{score_val:.1f}</div>
                <div style='
                    font-size:17px;
                    color:{TEXT_3};
                    letter-spacing:-0.374px;
                    margin-top:4px;
                    font-family:{FONT_TEXT};
                '>/ 100 — {score_label}</div>
                """
                )

            if is_pending:
                st.info(
                    "⏳ **Governance pending** — "
                    "Navigate to the **Governance** tab to complete "
                    "the checklist and calculate your full MRQM score.",
                    icon=None,
                )

            st.markdown(
                f"<div style='font-size:13px;color:{TEXT_3};margin-top:16px;letter-spacing:-0.12px;'>"
                f"Last scan: {ts_str} · Scan #{scan.get('scan_id', '—')}"
                f"</div>",
                unsafe_allow_html=True,
            )

        with hero_right:
            fig_gauge = go.Figure(
                go.Indicator(
                    mode="gauge+number",
                    value=score_val,
                    number={
                        "font": {
                            "size": 40,
                            "color": band_color,
                            "family": "-apple-system, Helvetica Neue, Arial",
                        }
                    },
                    gauge={
                        "axis": {
                            "range": [0, 100],
                            "tickwidth": 1,
                            "tickcolor": "#444",
                            "tickfont": {"size": 10, "color": "#888"},
                        },
                        "bar": {"color": band_color, "thickness": 0.25},
                        "bgcolor": "#1c1c1e",
                        "borderwidth": 0,
                        "steps": [
                            {"range": [0, 40],   "color": "rgba(52,199,89,0.2)"},
                            {"range": [40, 70],  "color": "rgba(255,159,10,0.2)"},
                            {"range": [70, 100], "color": "rgba(255,59,48,0.2)"},
                        ],
                    },
                )
            )
            fig_gauge.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=10, r=10, t=10, b=10),
                height=220,
                font=dict(family="-apple-system, Helvetica Neue, Arial"),
            )
            st.plotly_chart(fig_gauge, use_container_width=True, config={"displayModeBar": False})

    # ── SECTION 2: Three Pillar Cards ─────────────────────────────────────
    tech_score = scan.get("tech_score", 0.0) or 0.0
    gov_score  = scan.get("governance_score", 0.0) or 0.0
    exp_score  = scan.get("exposure_score", 0.0) or 0.0

    cve_findings   = scan.get("cve_findings", []) or []
    sw_count       = len(scan.get("software_inventory", []) or [])
    total_cves     = sum(len(f.get("cves", [])) for f in cve_findings)

    gov_answers    = scan.get("governance_answers", {}) or {}
    gov_maturity   = st.session_state.get("maturity", "basic")
    if gov_maturity == "advanced":
        gov_keys = TIER_1_KEYS + TIER_2_KEYS + TIER_3_KEYS
    elif gov_maturity == "intermediate":
        gov_keys = TIER_1_KEYS + TIER_2_KEYS
    else:
        gov_keys = TIER_1_KEYS
    compliant_count  = sum(1 for k in gov_keys if gov_answers.get(k, False))
    total_gov        = len(gov_keys)

    open_ports      = scan.get("open_ports", []) or []
    non_ephemeral   = [p for p in open_ports if p.get("port", 0) <= EPHEMERAL_THRESHOLD]
    allowlisted_pts = scan.get("allowlisted_ports", []) or []
    allowlisted_set = {p["port"] for p in allowlisted_pts}
    flagged_count   = sum(
        1 for p in non_ephemeral
        if p.get("port", 0) not in allowlisted_set
        and PORT_RISK_WEIGHTS.get(p.get("port", 0), 5.0) >= 40
    )

    pc1, pc2, pc3 = st.columns(3)
    with pc1:
        _render_pillar_card(
            icon="🔬",
            label="Technical",
            score_display=f"{tech_score:.1f}",
            weight_label="45% of MRQM · NVD + EPSS + EOL",
            score_val=tech_score,
            color=get_risk_color(tech_score),
            subtitle=f"{total_cves} CVEs · {sw_count} software items",
        )
    with pc2:
        g_display    = f"{gov_score:.1f}" if not is_pending else "—"
        g_subtitle   = f"{compliant_count}/{total_gov} controls compliant" if not is_pending else "Submit checklist to score"
        g_score_val  = gov_score if not is_pending else 0.0
        _render_pillar_card(
            icon="📋",
            label="Governance",
            score_display=g_display,
            weight_label="35% of MRQM · CERT-In + NIST CSF 2.0",
            score_val=g_score_val,
            color=BLUE if is_pending else get_risk_color(gov_score),
            subtitle=g_subtitle,
        )
    with pc3:
        _render_pillar_card(
            icon="🌐",
            label="Exposure",
            score_display=f"{exp_score:.1f}",
            weight_label="20% of MRQM · Port risk weights",
            score_val=exp_score,
            color=get_risk_color(exp_score),
            subtitle=f"{len(non_ephemeral)} ports · {flagged_count} flagged",
        )

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    # ── SECTION 3: CVE Table ──────────────────────────────────────────────
    if cve_findings:
        _section_header("🔬 Software Vulnerabilities", "NVD API v2.0 + EPSS (FIRST.org) + endoflife.date")

        rows = []
        for finding in cve_findings:
            sw_name  = finding.get("software_name", "")
            version  = finding.get("version", "")
            is_eol   = finding.get("is_eol", False)
            sw_risk  = finding.get("software_risk", 0.0)
            cves     = finding.get("cves", [])

            if cves:
                for cve in cves[:5]:
                    rows.append({
                        "Software":     sw_name,
                        "Version":      version + (" ⚠️ EOL" if is_eol else ""),
                        "CVE ID":       cve.get("cve_id", ""),
                        "CVSS":         cve.get("cvss_score", 0.0),
                        "EPSS":         f"{cve.get('epss_probability', 0.0):.4f}",
                        "Sw Risk":      f"{sw_risk:.3f}",
                    })
            else:
                rows.append({
                    "Software": sw_name,
                    "Version":  version + (" ⚠️ EOL" if is_eol else ""),
                    "CVE ID":   "No CVEs found",
                    "CVSS":     0.0,
                    "EPSS":     "—",
                    "Sw Risk":  f"{sw_risk:.3f}",
                })

        if rows:
            _render_cve_table(rows[:60])
        else:
            st.markdown(
                f"<div style='color:{TEXT_3};font-size:14px;padding:12px 0;letterSpacing:-0.224px;'>No vulnerabilities found.</div>",
                unsafe_allow_html=True,
            )
    else:
        with st.expander("🔬 Software Vulnerabilities — No data yet"):
            st.markdown(
                f"<div style='color:{TEXT_3};font-size:14px;'>Run the agent to collect software inventory.</div>",
                unsafe_allow_html=True,
            )

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    # ── SECTION 4: Ports ─────────────────────────────────────────────────
    if open_ports:
        _section_header("🌐 Network Exposure", "Ports scanned via psutil · nmap · Shodan")

        port_left, port_right = st.columns([60, 40])

        with port_left:
            st.markdown(
                f"<div style='font-size:14px;font-weight:600;color:{TEXT_1};"
                f"margin-bottom:12px;letter-spacing:-0.224px;'>Scored Ports</div>",
                unsafe_allow_html=True,
            )
            _render_port_table(non_ephemeral, allowlisted_pts)

        with port_right:
            st.markdown(
                f"<div style='font-size:14px;font-weight:600;color:{TEXT_1};"
                f"margin-bottom:12px;letter-spacing:-0.224px;'>Unrecognised Ports</div>",
                unsafe_allow_html=True,
            )
            unknown = [
                p for p in non_ephemeral
                if p.get("port", 0) not in PORT_RISK_WEIGHTS
                and p.get("port", 0) not in allowlisted_set
            ]

            if not unknown:
                st.markdown(
                    f"<div style='color:{TEXT_3};font-size:14px;padding:12px 0;'>"
                    f"No unrecognised ports detected.</div>",
                    unsafe_allow_html=True,
                )
            else:
                org_id = scan.get("scan_id")  # fallback — allowlist uses org_id from DB
                for p in unknown:
                    port_num = p.get("port", 0)
                    with st.container():
                        _html(
                            f"""
                            <div style='
                                background:#ffffff;
                                border-radius:10px;
                                box-shadow:{SHADOW};
                                padding:14px 16px;
                                margin-bottom:10px;
                            '>
                                <div style='font-size:15px;font-weight:600;
                                            color:{TEXT_1};letter-spacing:-0.224px;
                                            margin-bottom:6px;'>Port {port_num}</div>
                                <div style='font-size:12px;color:{TEXT_3};
                                            letter-spacing:-0.12px;'>
                                    Not in known risk registry. Is this intentional?
                                </div>
                            </div>
                            """
                            )
                        desc_col, btn_col = st.columns([3, 1])
                        with desc_col:
                            desc = st.text_input(
                                "Description",
                                placeholder="e.g. Company webapp",
                                key=f"allow_desc_{port_num}",
                                label_visibility="collapsed",
                            )
                        with btn_col:
                            if st.button("Mark Safe", key=f"allow_btn_{port_num}", type="secondary"):
                                # POST to allowlist
                                # We need org_id: fetch from org name
                                try:
                                    org_resp = requests.get(
                                        f"{API_BASE}/api/scans/latest",
                                        params={"org_name": st.session_state.get("org_name", "Test MSME")},
                                        timeout=10,
                                    )
                                    # allowlist endpoint requires org_id
                                    # We'll use scan organisation_id if available
                                    al_url = f"{API_BASE}/api/organizations/1/allowlist"
                                    r = requests.post(
                                        al_url,
                                        json={"port": port_num, "description": desc or f"Port {port_num}"},
                                        timeout=10,
                                    )
                                    if r.status_code == 200:
                                        st.success(f"Port {port_num} added to allowlist.")
                                        st.rerun()
                                    else:
                                        st.error(f"Failed to add: {r.text[:100]}")
                                except Exception as e:
                                    st.error(f"Error: {e}")

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    # ── SECTION 5: Active Probing Results ────────────────────────────────
    _section_header("🔐 Active Probing Results")
    probe_left, probe_right = st.columns(2)

    _ssl_check     = st.session_state.get("ssl_check_result")
    ssl_days       = (_ssl_check.get("ssl_days") if _ssl_check else None) or scan.get("ssl_days") or None
    password_score = scan.get("password_score", 0) or 0
    any_eol        = scan.get("any_eol", False)

    with probe_left:
        if ssl_days is not None:
            ssl_color  = SUCCESS if ssl_days >= 30 else (WARNING_COLOR if ssl_days >= 14 else DANGER)
            ssl_label  = "Valid" if ssl_days >= 30 else ("Expiring Soon" if ssl_days >= 14 else "Critical")
            ssl_domain = (_ssl_check or {}).get("domain", "")
            ssl_sub    = f"{ssl_label} · {ssl_domain}" if ssl_domain else ssl_label
            st.markdown(
                f"<div style='background:#ffffff;border-radius:12px;box-shadow:{SHADOW};padding:24px;'>"
                f"<div style='font-size:13px;color:{TEXT_3};text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;'>SSL Certificate</div>"
                f"<div style='font-size:36px;font-weight:600;color:{ssl_color};letter-spacing:-0.28px;font-family:{FONT_DISPLAY};'>{ssl_days} days</div>"
                f"<div style='font-size:14px;color:{TEXT_3};margin-top:4px;letter-spacing:-0.224px;'>{ssl_sub}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f"<div style='background:#ffffff;border-radius:12px;box-shadow:{SHADOW};padding:24px;'>"
                f"<div style='font-size:13px;color:{TEXT_3};text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;'>SSL Certificate</div>"
                f"<div style='font-size:15px;color:{TEXT_3};margin-top:8px;'>Not checked yet</div>"
                f"<div style='font-size:13px;color:{TEXT_3};margin-top:6px;'>Enter your domain in the Governance tab to check SSL expiry.</div>"
                f"</div>",
                unsafe_allow_html=True,
            )

    with probe_right:
        pw_dots   = "●" * password_score + "○" * (4 - password_score)
        pw_labels = ["Not assessed", "Weak", "Fair", "Strong", "Very Strong"]
        pw_colors = [TEXT_3, DANGER, WARNING_COLOR, SUCCESS, SUCCESS]
        pw_label  = pw_labels[min(password_score, 4)]
        pw_color  = pw_colors[min(password_score, 4)]

        _html(
            f"""
            <div style='
                background:#ffffff;
                border-radius:12px;
                box-shadow:{SHADOW};
                padding:24px;
            '>
                <div style='font-size:13px;color:{TEXT_3};text-transform:uppercase;
                            letter-spacing:0.5px;margin-bottom:8px;'>Admin Password Strength</div>
                <div style='font-size:28px;letter-spacing:4px;color:{pw_color};
                            font-weight:700;margin-bottom:6px;'>{pw_dots}</div>
                <div style='font-size:17px;font-weight:600;color:{pw_color};
                            letter-spacing:-0.374px;'>{pw_label}</div>
                <div style='font-size:12px;color:{TEXT_3};margin-top:8px;letter-spacing:-0.12px;'>
                    Assessed via zxcvbn · Not stored anywhere
                </div>
            </div>
            """
            )

    # ── EOL Software card (shown when any_eol is true) ───────────────────
    eol_items = [f for f in cve_findings if f.get("is_eol")]
    if eol_items:
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        eol_rows_html = "".join(
            f"<div style='display:flex;align-items:center;padding:8px 0;"
            f"border-bottom:1px solid rgba(0,0,0,0.06);gap:12px;'>"
            f"<span style='font-size:13px;font-weight:500;color:{TEXT_1};flex:1;'>"
            f"{f.get('software_name','Unknown')}</span>"
            f"<span style='font-size:12px;color:{TEXT_3};'>{f.get('version','')}</span>"
            f"<span style='font-size:11px;color:{WARNING_COLOR};background:#fffbeb;"
            f"padding:2px 8px;border-radius:6px;'>EOL</span>"
            f"</div>"
            for f in eol_items
        )
        st.markdown(
            f"<div style='background:#ffffff;border-radius:12px;box-shadow:{SHADOW};"
            f"padding:20px 24px;border-left:4px solid {WARNING_COLOR};'>"
            f"<div style='font-size:13px;color:{TEXT_3};text-transform:uppercase;"
            f"letter-spacing:0.5px;margin-bottom:12px;'>End-of-Life Software ({len(eol_items)} items)</div>"
            f"{eol_rows_html}"
            f"<div style='font-size:12px;color:{TEXT_3};margin-top:10px;'>"
            f"EOL software no longer receives security patches — update or replace these items.</div>"
            f"</div>",
            unsafe_allow_html=True,
        )

    # ── SECTION 6: PDF Report ─────────────────────────────────────────────
    st.markdown("<div style='height:32px'></div>", unsafe_allow_html=True)
    if "pdf_bytes" in st.session_state:
        st.download_button(
            label="📄 Download CERT-In Report",
            data=st.session_state["pdf_bytes"],
            file_name="MSME_Shield_Report.pdf",
            mime="application/pdf",
            key="ov_dl_pdf_btn",
        )


# ===========================================================================
# SECTION 5 — History page
# ===========================================================================

def page_history() -> None:
    """Render the History page — trend charts, band timeline, scan comparison."""
    history: list | None = st.session_state.get("scan_history")

    if not history or len(history) < 2:
        st.markdown("<div style='height:40px'></div>", unsafe_allow_html=True)
        _, col, _ = st.columns([1, 2, 1])
        with col:
            _html(
                f"""
                <div style='
                    background:#ffffff;
                    border-radius:16px;
                    box-shadow:{SHADOW};
                    padding:48px 40px;
                    text-align:center;
                '>
                    <div style='font-size:48px;margin-bottom:16px;'>📊</div>
                    <div style='font-size:24px;font-weight:600;color:{TEXT_1};
                                letter-spacing:-0.28px;font-family:{FONT_DISPLAY};
                                margin-bottom:8px;'>No history yet</div>
                    <div style='font-size:17px;color:{TEXT_3};letter-spacing:-0.374px;'>
                        Complete at least 2 scans to see your risk trend.
                    </div>
                </div>
                """
                )
        return

    # ── Date filter ──────────────────────────────────────────────────────
    filt_col1, filt_col2, filt_col3, _ = st.columns([1, 1, 1, 5])
    current_filter = st.session_state.get("history_filter", "all")

    def _pill_style(active: bool) -> str:
        if active:
            return f"background:{BLUE};color:#fff;border:none;border-radius:980px;padding:6px 18px;font-size:14px;cursor:pointer;"
        return f"background:#fafafc;color:{TEXT_1};border:1px solid {BORDER};border-radius:980px;padding:6px 18px;font-size:14px;cursor:pointer;"

    with filt_col1:
        if st.button("Last 5", key="hist_f5", type="primary" if current_filter == "last5" else "secondary", use_container_width=True):
            st.session_state["history_filter"] = "last5"
            st.rerun()
    with filt_col2:
        if st.button("Last 30 days", key="hist_f30", type="primary" if current_filter == "last30" else "secondary", use_container_width=True):
            st.session_state["history_filter"] = "last30"
            st.rerun()
    with filt_col3:
        if st.button("All time", key="hist_fall", type="primary" if current_filter == "all" else "secondary", use_container_width=True):
            st.session_state["history_filter"] = "all"
            st.rerun()

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # ── Filter data ──────────────────────────────────────────────────────
    all_scans = list(history)

    if current_filter == "last5":
        filtered = all_scans[-5:]
    elif current_filter == "last30":
        cutoff = pd.Timestamp.now() - pd.Timedelta(days=30)
        filtered = [
            s for s in all_scans
            if s.get("timestamp") and pd.Timestamp(s["timestamp"]).tz_localize(None) >= cutoff.tz_localize(None)
        ]
        if not filtered:
            filtered = all_scans[-5:]
    else:
        filtered = all_scans

    # Parse datetimes
    dates: list[str] = [format_timestamp(s.get("timestamp", "")) for s in filtered]
    mrqm_vals:  list = [s.get("mrqm_score") for s in filtered]
    tech_vals:  list = [s.get("tech_score") for s in filtered]
    gov_vals:   list = [s.get("governance_score") for s in filtered]
    exp_vals:   list = [s.get("exposure_score") for s in filtered]
    statuses:   list = [s.get("status", "pending_governance") for s in filtered]
    bands:      list = [s.get("risk_band", "PENDING") for s in filtered]

    # Safe numeric replacements
    def _safe_list(vals: list) -> list:
        return [v if v is not None else 0.0 for v in vals]

    mrqm_num = _safe_list(mrqm_vals)
    tech_num  = _safe_list(tech_vals)
    gov_num   = _safe_list(gov_vals)
    exp_num   = _safe_list(exp_vals)

    # ── Chart 1: MRQM Trend ───────────────────────────────────────────────
    _section_header("📈 MRQM Risk Score Over Time")

    marker_symbols = [
        "circle-open" if s != "complete" else "circle"
        for s in statuses
    ]

    hover_texts = [
        f"<b>{d}</b><br>MRQM: {m:.1f}<br>Tech: {t:.1f} | Gov: {g:.1f} | Exp: {e:.1f}"
        for d, m, t, g, e in zip(dates, mrqm_num, tech_num, gov_num, exp_num)
    ]

    fig_trend = go.Figure()

    # Background zones
    fig_trend.add_hrect(y0=0,  y1=40,  fillcolor="rgba(52,199,89,0.05)",  line_width=0)
    fig_trend.add_hrect(y0=40, y1=70,  fillcolor="rgba(255,159,10,0.05)", line_width=0)
    fig_trend.add_hrect(y0=70, y1=100, fillcolor="rgba(255,59,48,0.05)",  line_width=0)

    # Threshold lines
    fig_trend.add_hline(y=70, line_dash="dash", line_color=DANGER,        line_width=1.2,
                        annotation_text="Critical", annotation_position="right")
    fig_trend.add_hline(y=40, line_dash="dash", line_color=WARNING_COLOR, line_width=1.2,
                        annotation_text="Medium",   annotation_position="right")

    # MRQM line
    fig_trend.add_trace(go.Scatter(
        x=dates,
        y=mrqm_num,
        mode="lines+markers",
        name="MRQM",
        line=dict(color=BLUE, width=2.5),
        marker=dict(
            size=8,
            color=BLUE,
            symbol=marker_symbols,
            line=dict(width=2, color=BLUE),
        ),
        hovertemplate="%{customdata}<extra></extra>",
        customdata=hover_texts,
    ))

    fig_trend.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="#fafafa",
        height=320,
        margin=dict(l=0, r=60, t=10, b=40),
        xaxis=dict(
            showgrid=False,
            showline=False,
            tickfont=dict(size=12, color="#888"),
        ),
        yaxis=dict(
            range=[0, 105],
            gridcolor="rgba(0,0,0,0.06)",
            showline=False,
            tickfont=dict(size=12, color="#888"),
        ),
        showlegend=False,
        font=dict(family="-apple-system, Helvetica Neue, Arial"),
    )

    st.plotly_chart(fig_trend, use_container_width=True, config={"displayModeBar": False})

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    # ── Chart 2: Stacked Area ────────────────────────────────────────────
    _section_header("📊 Score Breakdown Over Time")

    fig_area = go.Figure()
    fig_area.add_trace(go.Scatter(
        x=dates, y=tech_num,
        name="Technical",
        fill="tozeroy",
        mode="lines",
        stackgroup="one",
        line=dict(color=DANGER, width=1.5),
        fillcolor="rgba(255,59,48,0.5)",
    ))
    fig_area.add_trace(go.Scatter(
        x=dates, y=gov_num,
        name="Governance",
        fill="tonexty",
        mode="lines",
        stackgroup="one",
        line=dict(color=BLUE, width=1.5),
        fillcolor="rgba(0,113,227,0.5)",
    ))
    fig_area.add_trace(go.Scatter(
        x=dates, y=exp_num,
        name="Exposure",
        fill="tonexty",
        mode="lines",
        stackgroup="one",
        line=dict(color=WARNING_COLOR, width=1.5),
        fillcolor="rgba(255,159,10,0.5)",
    ))
    fig_area.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="#fafafa",
        height=280,
        margin=dict(l=0, r=10, t=10, b=40),
        yaxis=dict(
            range=[0, 100],
            gridcolor="rgba(0,0,0,0.06)",
            showline=False,
            tickfont=dict(size=12, color="#888"),
        ),
        xaxis=dict(
            showgrid=False,
            showline=False,
            tickfont=dict(size=12, color="#888"),
        ),
        legend=dict(
            orientation="h",
            y=1.05,
            font=dict(size=12),
        ),
        font=dict(family="-apple-system, Helvetica Neue, Arial"),
    )
    st.plotly_chart(fig_area, use_container_width=True, config={"displayModeBar": False})

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    # ── Chart 3: Risk Band Timeline ──────────────────────────────────────
    _section_header("🎯 Risk Band Timeline")

    band_colors_list = [RISK_CONFIG.get(b, RISK_CONFIG["PENDING"])["color"] for b in bands]
    bar_labels       = [
        f"{d} — {b} ({m:.1f})"
        for d, b, m in zip(dates, bands, mrqm_num)
    ]
    chart_height = max(200, len(filtered) * 50)

    fig_band = go.Figure(go.Bar(
        y=bar_labels,
        x=mrqm_num,
        orientation="h",
        marker_color=band_colors_list,
        marker_line_width=0,
        hovertemplate="%{y}: %{x:.1f}<extra></extra>",
    ))
    fig_band.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="#fafafa",
        height=chart_height,
        margin=dict(l=0, r=20, t=10, b=20),
        xaxis=dict(range=[0, 100], gridcolor="rgba(0,0,0,0.06)", showline=False,
                   tickfont=dict(size=12, color="#888")),
        yaxis=dict(showgrid=False, showline=False, tickfont=dict(size=12, color="#1d1d1f")),
        font=dict(family="-apple-system, Helvetica Neue, Arial"),
    )
    st.plotly_chart(fig_band, use_container_width=True, config={"displayModeBar": False})

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    # ── Scan Comparison ──────────────────────────────────────────────────
    _section_header("🔍 Compare Two Scans")

    complete_scans = [s for s in filtered if s.get("risk_band")]
    scan_options = {
        f"Scan #{s.get('scan_id')} — {format_timestamp(s.get('timestamp', ''))} ({s.get('risk_band','?')})": i
        for i, s in enumerate(complete_scans)
    }
    option_labels = list(scan_options.keys())

    if len(option_labels) >= 2:
        cmp_left, cmp_right = st.columns(2)
        with cmp_left:
            sel_a = st.selectbox("Select Scan A", option_labels, index=0, key="cmp_a")
        with cmp_right:
            sel_b = st.selectbox("Select Scan B", option_labels, index=min(1, len(option_labels) - 1), key="cmp_b")

        idx_a = scan_options[sel_a]
        idx_b = scan_options[sel_b]
        scan_a = complete_scans[idx_a]
        scan_b = complete_scans[idx_b]

        metrics = [
            ("MRQM Score",      scan_a.get("mrqm_score"),      scan_b.get("mrqm_score")),
            ("Technical Score", scan_a.get("tech_score"),       scan_b.get("tech_score")),
            ("Governance Score",scan_a.get("governance_score"), scan_b.get("governance_score")),
            ("Exposure Score",  scan_a.get("exposure_score"),   scan_b.get("exposure_score")),
        ]

        rows_html = ""
        for i, (metric, va, vb) in enumerate(metrics):
            va_f = va if va is not None else 0.0
            vb_f = vb if vb is not None else 0.0
            delta = vb_f - va_f
            if abs(delta) < 0.05:
                ch = "—"
                ch_color = TEXT_3
            elif delta > 0:
                ch = f"↑ +{delta:.1f}"
                ch_color = DANGER  # higher score = worse risk
            else:
                ch = f"↓ {delta:.1f}"
                ch_color = SUCCESS

            row_bg = "#ffffff" if i % 2 == 0 else "#fafafa"
            rows_html += f"""
            <tr style='background:{row_bg};'>
                <td style='padding:12px 16px;font-size:14px;font-weight:600;color:{TEXT_1};'>{metric}</td>
                <td style='padding:12px 16px;font-size:14px;color:{TEXT_2};text-align:center;'>{va_f:.1f}</td>
                <td style='padding:12px 16px;font-size:14px;color:{TEXT_2};text-align:center;'>{vb_f:.1f}</td>
                <td style='padding:12px 16px;font-size:14px;font-weight:600;color:{ch_color};text-align:center;'>{ch}</td>
            </tr>
            """

        _html(
            f"""
            <div style='border-radius:12px;overflow:hidden;box-shadow:{SHADOW};'>
                <table style='width:100%;border-collapse:collapse;background:#ffffff;'>
                    <thead>
                        <tr style='background:#f5f5f7;'>
                            <th style='padding:10px 16px;text-align:left;font-size:11px;text-transform:uppercase;color:{TEXT_3};letter-spacing:0.5px;'>Metric</th>
                            <th style='padding:10px 16px;text-align:center;font-size:11px;text-transform:uppercase;color:{TEXT_3};letter-spacing:0.5px;'>Scan A</th>
                            <th style='padding:10px 16px;text-align:center;font-size:11px;text-transform:uppercase;color:{TEXT_3};letter-spacing:0.5px;'>Scan B</th>
                            <th style='padding:10px 16px;text-align:center;font-size:11px;text-transform:uppercase;color:{TEXT_3};letter-spacing:0.5px;'>Change</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows_html}
                    </tbody>
                </table>
            </div>
            """
            )


# ===========================================================================
# SECTION 6 — Governance page
# ===========================================================================

def _render_compliance_table(scan: dict) -> None:
    """Render the read-only governance compliance table (State A)."""
    gov_answers = scan.get("governance_answers", {}) or {}
    maturity    = st.session_state.get("maturity", "basic")
    if maturity == "advanced":
        keys = TIER_1_KEYS + TIER_2_KEYS + TIER_3_KEYS
    elif maturity == "intermediate":
        keys = TIER_1_KEYS + TIER_2_KEYS
    else:
        keys = TIER_1_KEYS

    rows_html = ""
    for i, key in enumerate(keys):
        meta      = CONTROL_META.get(key, {"label": key, "citation": "", "statutory": False, "tier": 1})
        compliant = gov_answers.get(key, False)
        row_bg    = "#ffffff" if i % 2 == 0 else "#fafafa"

        status_badge = (
            f"<span style='background:#f0fff4;color:{SUCCESS};font-size:11px;"
            f"padding:2px 10px;border-radius:980px;font-weight:600;'>✓ Yes</span>"
            if compliant else
            f"<span style='background:#fff5f5;color:{DANGER};font-size:11px;"
            f"padding:2px 10px;border-radius:980px;font-weight:600;'>✗ No</span>"
        )
        statutory_badge = (
            f"<span style='font-size:10px;color:{BLUE};background:{BLUE_LIGHT};"
            f"padding:1px 6px;border-radius:980px;margin-left:6px;'>Statutory</span>"
            if meta.get("statutory") else ""
        )

        rows_html += f"""
        <tr style='background:{row_bg};'>
            <td style='padding:10px 14px;font-size:14px;color:{TEXT_1};font-weight:500;'>
                {meta.get("label", key)}{statutory_badge}
            </td>
            <td style='padding:10px 14px;'>{status_badge}</td>
            <td style='padding:10px 14px;font-size:12px;color:{TEXT_3};'>{meta.get("citation","")}</td>
            <td style='padding:10px 14px;font-size:12px;color:{TEXT_3};text-align:center;'>Tier {meta.get("tier",1)}</td>
        </tr>
        """

    _html(
        f"""
        <div style='border-radius:12px;overflow:hidden;box-shadow:{SHADOW};margin-bottom:24px;'>
            <table style='width:100%;border-collapse:collapse;background:#ffffff;'>
                <thead>
                    <tr style='background:#f5f5f7;'>
                        <th style='padding:10px 14px;text-align:left;font-size:11px;text-transform:uppercase;color:{TEXT_3};letter-spacing:0.5px;'>Control</th>
                        <th style='padding:10px 14px;text-align:left;font-size:11px;text-transform:uppercase;color:{TEXT_3};letter-spacing:0.5px;'>Status</th>
                        <th style='padding:10px 14px;text-align:left;font-size:11px;text-transform:uppercase;color:{TEXT_3};letter-spacing:0.5px;'>Framework</th>
                        <th style='padding:10px 14px;text-align:center;font-size:11px;text-transform:uppercase;color:{TEXT_3};letter-spacing:0.5px;'>Tier</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
        """
        )


def _render_remediation_priorities(scan: dict) -> None:
    """Render the remediation priority cards from the scan response."""
    priorities = scan.get("remediation_priorities", []) or []
    if not priorities:
        st.markdown(
            f"<div style='color:{SUCCESS};font-size:15px;padding:12px 0;'>🎉 All applicable controls are compliant!</div>",
            unsafe_allow_html=True,
        )
        return

    _section_header("🚨 Action Items — by Priority")
    for item in priorities:
        border_color = BLUE if item.get("statutory") else "rgba(0,0,0,0.16)"
        stat_badge   = (
            f"<span style='font-size:10px;color:{BLUE};background:{BLUE_LIGHT};"
            f"padding:1px 6px;border-radius:980px;margin-left:8px;'>Statutory</span>"
            if item.get("statutory") else ""
        )
        _html(
            f"""
            <div style='
                background:#ffffff;
                border-radius:10px;
                box-shadow:{SHADOW};
                padding:16px 20px;
                margin-bottom:10px;
                border-left:4px solid {border_color};
            '>
                <div style='font-size:15px;font-weight:600;color:{TEXT_1};letter-spacing:-0.224px;margin-bottom:4px;'>
                    {item.get("label","")}{stat_badge}
                    <span style='font-size:12px;color:{TEXT_3};font-weight:400;margin-left:8px;'>weight: {item.get("weight",0):.1f}%</span>
                </div>
                <div style='font-size:13px;color:{TEXT_2};letter-spacing:-0.12px;line-height:1.5;margin-bottom:6px;'>
                    {item.get("remediation","")}
                </div>
                <div style='font-size:11px;color:{TEXT_3};letter-spacing:-0.12px;'>
                    {item.get("citation","")}
                </div>
            </div>
            """
            )


def _render_gov_control(key: str, tier_label: str = "") -> None:
    """Render a single governance control card with YES/NO buttons and guidance."""
    meta       = CONTROL_META.get(key, {"label": key, "citation": "", "statutory": False, "tier": 1, "remediation": ""})
    current_val = st.session_state["gov_answers"].get(key, False)

    border_left = SUCCESS if current_val else (BLUE if meta.get("statutory") else "rgba(0,0,0,0.08)")
    card_bg     = "#f0fff4" if current_val else "#ffffff"

    stat_span = (
        "<span style='font-size:11px;color:#0071e3;background:#eaf3fe;"
        "padding:2px 8px;border-radius:980px;margin-left:8px;"
        "letter-spacing:-0.12px;'>Statutory</span>"
        if meta.get("statutory") else ""
    )

    citation = meta.get("citation", "")
    label    = meta.get("label", key)
    st.markdown(
        f"<div style='background:{card_bg};border-radius:12px;padding:16px 20px;"
        f"margin-bottom:4px;box-shadow:{SHADOW};border-left:4px solid {border_left};'>"
        f"<div style='display:flex;justify-content:space-between;align-items:flex-start;'>"
        f"<div>"
        f"<span style='font-size:15px;font-weight:600;color:{TEXT_1};letter-spacing:-0.224px;'>{label}</span>"
        f"{stat_span}"
        f"<div style='font-size:13px;color:rgba(0,0,0,0.70);letter-spacing:-0.12px;margin-top:4px;'>{citation}</div>"
        f"</div></div></div>",
        unsafe_allow_html=True,
    )

    answer = st.radio(
        meta.get("label", key),
        ["✓ Yes", "✗ No"],
        index=0 if current_val else 1,
        horizontal=True,
        key=f"radio_{key}",
        label_visibility="collapsed",
    )
    st.markdown(
        """
        <style>
        div[data-testid="stRadio"] label p {
            font-size: 16px !important;
            color: #1a1a1a !important;
            font-weight: 500 !important;
        }
        div[data-testid="stRadio"] > div {
            gap: 20px !important;
        }
        div[data-testid="stRadio"] {
            margin-top: 8px !important;
            margin-bottom: 4px !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    new_val = answer == "✓ Yes"
    if new_val != current_val:
        st.session_state["gov_answers"][key] = new_val
        st.rerun()

    with st.expander("📖 Why this matters"):
        remediation = meta.get("remediation", "No guidance available.")
        st.markdown(
            f"<div style='font-size:13px;color:{TEXT_2};letter-spacing:-0.12px;line-height:1.5;'>{remediation}</div>",
            unsafe_allow_html=True,
        )


def _render_lock_card(msg: str) -> None:
    """Render a locked tier card for controls not yet available at this maturity level."""
    _html(
        f"""
        <div style='
            background:#fafafc;
            border-radius:12px;
            padding:20px 24px;
            margin:12px 0;
            border:1px dashed rgba(0,0,0,0.16);
            text-align:center;
        '>
            <div style='font-size:20px;margin-bottom:6px;'>🔒</div>
            <div style='font-size:14px;color:{TEXT_3};letter-spacing:-0.224px;'>{msg}</div>
        </div>
        """
        )




def page_governance() -> None:
    """Render the Governance page — tiered checklist or read-only view."""
    scan: dict | None = st.session_state.get("scan_result")

    # ── No scan loaded ────────────────────────────────────────────────────
    if not scan:
        st.markdown("<div style='height:40px'></div>", unsafe_allow_html=True)
        _, col, _ = st.columns([1, 2, 1])
        with col:
            st.info(
                "**Run the agent first** to load a scan, then return here to complete the governance checklist."
            )
        return

    status   = scan.get("status", "pending_governance")
    scan_id  = scan.get("scan_id")

    # ── STATE A — Read-only (governance already submitted) ────────────────
    if status == "complete" and st.session_state.get("gov_submitted", False):
        gov_score = scan.get("governance_score", 0.0) or 0.0
        g_color   = get_risk_color(gov_score)

        _html(
            f"""
            <div style='margin-bottom:24px;'>
                <div style='font-size:28px;font-weight:600;color:{TEXT_1};
                            letter-spacing:-0.28px;font-family:{FONT_DISPLAY};'>
                    ✅ Assessment Complete
                </div>
                <div style='font-size:17px;color:{TEXT_3};letter-spacing:-0.374px;margin-top:4px;'>
                    Submitted for Scan #{scan_id}
                </div>
            </div>
            """
            )

        # Governance score display
        col_score, col_action = st.columns([3, 1])
        with col_score:
            _html(
                f"""
                <div style='
                    background:#ffffff;
                    border-radius:12px;
                    box-shadow:{SHADOW};
                    padding:24px;
                    margin-bottom:24px;
                    display:inline-block;
                '>
                    <div style='font-size:13px;color:{TEXT_3};text-transform:uppercase;
                                letter-spacing:0.5px;'>Governance Score</div>
                    <div style='font-size:52px;font-weight:700;color:{g_color};
                                letter-spacing:-0.28px;font-family:{FONT_DISPLAY};'>{gov_score:.1f}</div>
                </div>
                """
                )
        with col_action:
            st.markdown("<div style='height:40px'></div>", unsafe_allow_html=True)
            if st.button("🔄 Re-assess", type="secondary", use_container_width=True):
                st.session_state["gov_submitted"] = False
                st.rerun()
            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
            if "pdf_bytes" in st.session_state:
                st.download_button(
                    label="📄 Download CERT-In Report",
                    data=st.session_state["pdf_bytes"],
                    file_name="MSME_Shield_Report.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                    key="gov_dl_pdf_btn",
                )

        _render_compliance_table(scan)
        _render_remediation_priorities(scan)
        return

    # ── STATE B — Governance form ─────────────────────────────────────────

    # Top info card
    ts_str     = format_timestamp(scan.get("timestamp", ""))
    tech_score = scan.get("tech_score", 0.0) or 0.0

    _html(
        f"""
        <div style='
            background:{BLUE_LIGHT};
            border-radius:14px;
            padding:20px 24px;
            margin-bottom:24px;
            border:1px solid rgba(0,113,227,0.2);
        '>
            <div style='font-size:17px;font-weight:600;color:{BLUE};
                        letter-spacing:-0.374px;margin-bottom:6px;'>
                Complete your governance assessment
            </div>
            <div style='font-size:14px;color:{TEXT_2};letter-spacing:-0.224px;'>
                Scan #{scan_id} · {ts_str} · Tech Score: {tech_score:.1f}
            </div>
        </div>
        """
        )

    # ── Admin password section ────────────────────────────────────────────
    st.markdown(
        f"<div style='font-size:20px;font-weight:600;color:{TEXT_1};"
        f"letter-spacing:-0.28px;margin-bottom:12px;'>🔒 Security Check</div>",
        unsafe_allow_html=True,
    )
    password = st.text_input(
        "Admin Account Password",
        type="password",
        help="Evaluated for strength — never stored or transmitted",
        key="gov_password_input",
    )

    if password:
        p_score  = simple_password_score(password)
        p_labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
        p_colors = [DANGER, DANGER, WARNING_COLOR, SUCCESS, SUCCESS]
        p_dots   = "●" * (p_score + 1) + "○" * (3 - p_score)
        _html(
            f"""
            <div style='font-size:14px;color:{p_colors[p_score]};
                        letter-spacing:-0.224px;margin-top:6px;
                        margin-bottom:4px;'>
                {p_dots} {p_labels[p_score]}
            </div>
            """
            )

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    # ── Website SSL checker ───────────────────────────────────────────────
    st.markdown(
        f"<div style='font-size:20px;font-weight:600;color:{TEXT_1};"
        f"letter-spacing:-0.28px;margin-bottom:12px;'>🌐 Website SSL Certificate</div>",
        unsafe_allow_html=True,
    )
    ssl_col_input, ssl_col_btn = st.columns([3, 1])
    with ssl_col_input:
        ssl_domain = st.text_input(
            "Website Domain",
            placeholder="example.com",
            help="Enter your apex domain — no https:// needed",
            key="gov_ssl_domain",
        )
    with ssl_col_btn:
        st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
        check_clicked = st.button("Check SSL", key="gov_ssl_check_btn", use_container_width=True)

    if check_clicked and ssl_domain:
        with st.spinner("Checking SSL certificate…"):
            try:
                resp = requests.get(
                    ENDPOINTS["check_ssl"],
                    params={"domain": ssl_domain},
                    timeout=12,
                )
                resp.raise_for_status()
                st.session_state["ssl_check_result"] = resp.json()
            except Exception as exc:
                st.error(f"SSL check failed: {exc}")

    ssl_result = st.session_state.get("ssl_check_result")
    if ssl_result:
        s_days  = ssl_result.get("ssl_days", 45)
        s_dom   = ssl_result.get("domain", "")
        s_color = SUCCESS if s_days >= 30 else (WARNING_COLOR if s_days >= 14 else DANGER)
        s_label = "Valid" if s_days >= 30 else ("Expiring Soon" if s_days >= 14 else "Critical — Expired or near-expiry")
        st.markdown(
            f"<div style='background:#ffffff;border-radius:12px;box-shadow:{SHADOW};"
            f"padding:20px 24px;margin-top:12px;border-left:4px solid {s_color};'>"
            f"<div style='font-size:13px;color:{TEXT_3};text-transform:uppercase;"
            f"letter-spacing:0.5px;margin-bottom:6px;'>SSL Certificate · {s_dom}</div>"
            f"<div style='font-size:36px;font-weight:600;color:{s_color};"
            f"letter-spacing:-0.28px;'>{s_days} days</div>"
            f"<div style='font-size:14px;color:{TEXT_3};margin-top:4px;'>{s_label}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    # ── IT Maturity selector ──────────────────────────────────────────────
    st.markdown(
        f"<div style='font-size:20px;font-weight:600;color:{TEXT_1};"
        f"letter-spacing:-0.28px;margin-bottom:16px;'>🏢 Your IT Setup</div>",
        unsafe_allow_html=True,
    )

    mat_col1, mat_col2, mat_col3 = st.columns(3)
    current_maturity = st.session_state.get("maturity", "basic")

    maturity_options = [
        ("basic",        "🏪", "Basic",        "No dedicated IT person"),
        ("intermediate", "🏢", "Intermediate", "Some IT support"),
        ("advanced",     "🏬", "Advanced",     "Dedicated IT team or CISO"),
    ]

    for col, (key, icon, title, desc) in zip([mat_col1, mat_col2, mat_col3], maturity_options):
        with col:
            selected  = (current_maturity == key)
            border_c  = BLUE if selected else "rgba(0,0,0,0.16)"
            bg_c      = BLUE_LIGHT if selected else "#ffffff"
            fw        = "600" if selected else "400"
            _html(
                f"""
                <div style='
                    border: 2px solid {border_c};
                    background: {bg_c};
                    border-radius: 12px;
                    padding: 20px 16px;
                    text-align: center;
                    min-height: 120px;
                    margin-bottom: 8px;
                '>
                    <div style='font-size:28px'>{icon}</div>
                    <div style='
                        font-size:17px;
                        font-weight:{fw};
                        color:#1d1d1f;
                        letter-spacing:-0.374px;
                        margin:8px 0 4px;
                    '>{title}</div>
                    <div style='
                        font-size:12px;
                        color:rgba(0,0,0,0.48);
                        letter-spacing:-0.12px;
                    '>{desc}</div>
                </div>
                """
                )
            if st.button(
                f"{'✓ Selected' if selected else 'Select'}",
                key=f"mat_{key}",
                type="primary" if selected else "secondary",
                use_container_width=True,
            ):
                st.session_state["maturity"] = key
                st.rerun()

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    # ── Controls (full-width) ─────────────────────────────────────────────
    answers  = st.session_state.get("gov_answers", {})
    maturity = st.session_state.get("maturity", "basic")

    # TIER 1 — always shown
    st.markdown(
        f"<div style='font-size:18px;font-weight:600;color:{TEXT_1};"
        f"letter-spacing:-0.28px;margin-bottom:4px;'>Essential Controls</div>",
        unsafe_allow_html=True,
    )
    st.caption("10 controls · All organisations")
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    for key in TIER_1_KEYS:
        _render_gov_control(key)

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    # TIER 2
    st.markdown(
        f"<div style='font-size:18px;font-weight:600;color:{TEXT_1};"
        f"letter-spacing:-0.28px;margin-bottom:4px;'>Intermediate Controls</div>",
        unsafe_allow_html=True,
    )
    st.caption("5 controls · Intermediate + Advanced maturity")
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    if maturity == "basic":
        _render_lock_card("Select Intermediate or Advanced maturity to unlock these 5 controls.")
    else:
        for key in TIER_2_KEYS:
            _render_gov_control(key)

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    # TIER 3
    st.markdown(
        f"<div style='font-size:18px;font-weight:600;color:{TEXT_1};"
        f"letter-spacing:-0.28px;margin-bottom:4px;'>Advanced Controls</div>",
        unsafe_allow_html=True,
    )
    st.caption("5 controls · Advanced maturity only")
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    if maturity in ("basic", "intermediate"):
        _render_lock_card("Select Advanced maturity to unlock these 5 controls.")
    else:
        for key in TIER_3_KEYS:
            _render_gov_control(key)

    # ── Submit button ─────────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)

    if st.button(
        "Submit Governance Assessment →",
        type="primary",
        use_container_width=True,
        disabled=(scan_id is None),
        key="gov_submit_btn",
    ):
        mat     = st.session_state.get("maturity", "basic")
        ans     = st.session_state.get("gov_answers", {})
        pwd     = st.session_state.get("gov_password_input", "")

        payload = {
            "it_maturity":    mat,
            "admin_password": pwd,
            **{k: bool(ans.get(k, False)) for k in ALL_GOV_KEYS},
        }

        url = ENDPOINTS["governance"].format(scan_id=scan_id)

        with st.spinner("Computing MRQM score…"):
            try:
                r = requests.post(url, json=payload, timeout=30)
                r.raise_for_status()
                result = r.json()
                st.session_state.pop("pdf_bytes", None)  # force regen with complete data
                st.session_state["scan_result"]   = result
                st.session_state["gov_submitted"] = True
                # Clear password from state immediately
                if "gov_password_input" in st.session_state:
                    del st.session_state["gov_password_input"]
                # Invalidate history cache
                api_scan_history.clear()
                st.success(
                    f"✅ Assessment complete! MRQM Score: **{result['mrqm_score']:.1f}** "
                    f"— Risk Band: **{result.get('risk_band','—')}**"
                )
                st.session_state["page"] = "overview"
                st.rerun()
            except requests.exceptions.HTTPError as e:
                detail = ""
                try:
                    detail = e.response.json().get("detail", "")
                except Exception:
                    pass
                st.error(f"Submission failed: {e} {detail}")
            except Exception as e:
                st.error(f"Submission failed: {e}")


# ===========================================================================
# SECTION 7 — Main app entry + run
# ===========================================================================

def main() -> None:
    """MSME Shield dashboard entry point."""
    # 1. CSS injection — must happen right after page_config
    inject_css()

    # 2. Initialise session state
    init_session_state()

    # 3. Auth gate — show login/register if not authenticated
    if not st.session_state.get("authenticated"):
        show_auth_page()
        st.stop()

    # 4. Load data from backend
    load_data()

    # 4b. Eagerly generate PDF bytes once per scan result (no user action needed)
    if st.session_state.get("scan_result") and "pdf_bytes" not in st.session_state:
        _do_generate_pdf(st.session_state["scan_result"])

    # 5. Backend offline warning
    if not st.session_state.get("backend_ok", False):
        st.warning(
            "⚠️ Cannot connect to MSME Shield backend. "
            "Start with: **cd backend && uvicorn api:app --reload --port 8000**"
        )

    # 6. Render navbar
    render_navbar()

    # 7. Route to current page
    page = st.session_state.get("page", "overview")
    if page == "overview":
        page_overview()
    elif page == "history":
        page_history()
    elif page == "governance":
        page_governance()
    else:
        page_overview()


if __name__ == "__main__":
    main()
