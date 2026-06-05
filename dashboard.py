"""
dashboard.py — Enhanced with Login Lockout, Off-Hours Anomaly, Better UX,
               Alert Reset, Snort Signature Simulator
"""

import hashlib
import json
import sqlite3
import os
import time
import math
import random

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from streamlit_autorefresh import st_autorefresh
from datetime import datetime

from config import DB_PATH, NORMAL_DATA_PATH, SNORT_ALERT_FILE
from intel_factory import IntelFactory, FEATURE_NAMES
from alert_system import ensure_features_column

# ========================= DB HELPERS =========================
_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    type        TEXT    NOT NULL,
    source      TEXT    NOT NULL DEFAULT 'engine',
    rule        TEXT,
    src_ip      TEXT,
    dst_ip      TEXT,
    src_port    INTEGER,
    dst_port    INTEGER,
    confidence  REAL,
    reason      TEXT,
    features    TEXT
)
"""

def _get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute(_CREATE_TABLE_SQL)
    conn.commit()
    ensure_features_column(conn)   # migrate older DBs that lack the column
    return conn

def clear_all_alerts() -> int:
    """Delete every row from the alerts table. Returns number of rows deleted."""
    try:
        conn = _get_conn()
        cur  = conn.execute("SELECT COUNT(*) FROM alerts")
        count = cur.fetchone()[0]
        conn.execute("DELETE FROM alerts")
        conn.commit()
        conn.close()
        return count
    except Exception as e:
        return -1

# Snort rule templates for the simulator
_SNORT_RULES = [
    ("ssh_brute_force",     "signature", "snort", 0.95, "Signature Match (Snort) — SSH brute force attempt"),
    ("port_scan_detected",  "signature", "snort", 0.90, "Signature Match (Snort) — TCP port scan"),
    ("dos_flood",           "signature", "snort", 0.93, "Signature Match (Snort) — DoS/flood traffic"),
    ("malware_callback",    "signature", "snort", 0.97, "Signature Match (Snort) — Malware C2 callback"),
    ("sql_injection",       "signature", "snort", 0.88, "Signature Match (Snort) — SQL injection attempt"),
    ("ftp_brute_force",     "signature", "snort", 0.85, "Signature Match (Snort) — FTP brute force"),
    ("dns_tunneling",       "signature", "snort", 0.91, "Signature Match (Snort) — DNS tunnelling"),
    ("smb_exploit",         "signature", "snort", 0.96, "Signature Match (Snort) — SMB exploit (EternalBlue)"),
]

_SAMPLE_IPS = [
    ("10.0.0.5",      "192.168.10.73"),
    ("10.0.0.9",      "192.168.10.71"),
    ("192.168.10.70", "192.168.10.73"),
    ("172.16.0.44",   "10.10.10.1"),
    ("45.33.32.156",  "192.168.10.10"),
]

_SAMPLE_PORTS = [(22, 54321), (80, 49152), (443, 33000), (3389, 51200), (21, 60001)]

def inject_snort_alert(rule_name: str = None) -> bool:
    """Insert a simulated Snort signature alert directly into the DB."""
    try:
        if rule_name:
            rule_data = next((r for r in _SNORT_RULES if r[0] == rule_name), random.choice(_SNORT_RULES))
        else:
            rule_data = random.choice(_SNORT_RULES)

        rule, atype, source, conf, reason = rule_data
        src_ip, dst_ip = random.choice(_SAMPLE_IPS)
        dst_port, src_port = random.choice(_SAMPLE_PORTS)

        conn = _get_conn()
        conn.execute(
            """INSERT INTO alerts (timestamp, type, source, rule, src_ip, dst_ip,
               src_port, dst_port, confidence, reason)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (datetime.now().isoformat(), atype, source, rule,
             src_ip, dst_ip, src_port, dst_port, conf, reason),
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

# ========================= CONFIG =========================
st.set_page_config(
    page_title="D H A Guard — Hybrid IDS",
    page_icon="🛡️",
    layout="wide",
)

FP_IPS_FILE = "false_positive_ips.txt"

# ========================= GLOBAL CSS =========================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;600;700;800&display=swap');

html, body, [data-testid="stAppViewContainer"] {
    background: #080c14 !important;
    color: #c8d8e8;
    font-family: 'Syne', sans-serif;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: #0b1120 !important;
    border-right: 1px solid #1e2d45;
}

/* Metric cards */
[data-testid="metric-container"] {
    background: #0d1a2d;
    border: 1px solid #1a2e45;
    border-radius: 12px;
    padding: 16px;
}

/* Tab styling */
[data-testid="stTabs"] [role="tab"] {
    font-family: 'Syne', sans-serif;
    font-weight: 600;
    font-size: 0.85rem;
    letter-spacing: 0.04em;
}

/* Dataframe */
[data-testid="stDataFrame"] {
    border: 1px solid #1a2e45;
    border-radius: 8px;
}

/* Buttons */
.stButton > button {
    font-family: 'Syne', sans-serif;
    font-weight: 600;
    border-radius: 8px;
    transition: all 0.2s ease;
}
.stButton > button:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 16px rgba(56, 189, 248, 0.3);
}

/* Custom alert cards */
.alert-card {
    background: #0d1a2d;
    border: 1px solid #1a2e45;
    border-radius: 12px;
    padding: 16px 20px;
    margin-bottom: 10px;
}
.alert-card.critical { border-left: 4px solid #ef4444; }
.alert-card.warning  { border-left: 4px solid #f59e0b; }
.alert-card.info     { border-left: 4px solid #38bdf8; }

/* Anomaly banner */
.anomaly-banner {
    background: linear-gradient(135deg, #2d1a0e, #3d1a0a);
    border: 1px solid #c2410c;
    border-radius: 12px;
    padding: 16px 20px;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 12px;
}

/* Status dot */
.status-dot {
    display: inline-block;
    width: 10px; height: 10px;
    border-radius: 50%;
    background: #22c55e;
    animation: pulse 2s infinite;
    margin-right: 8px;
}
@keyframes pulse {
    0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(34,197,94,0.5); }
    50%       { opacity: 0.8; box-shadow: 0 0 0 6px rgba(34,197,94,0); }
}

/* Lock banner */
.lock-banner {
    background: linear-gradient(135deg, #1a0e2d, #2d0a3d);
    border: 1px solid #7c3aed;
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    font-family: 'JetBrains Mono', monospace;
}

/* Monospace for IPs */
.mono { font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; }

/* Section headers */
h2, h3 { font-family: 'Syne', sans-serif; font-weight: 700; }

/* Divider */
hr { border-color: #1a2e45 !important; margin: 24px 0; }
</style>
""", unsafe_allow_html=True)

# ====================== FALSE POSITIVE HELPERS ======================
def load_false_positive_ips() -> set:
    if os.path.exists(FP_IPS_FILE):
        with open(FP_IPS_FILE, "r") as f:
            return {line.strip() for line in f if line.strip()}
    return set()

def save_false_positive_ip(ip: str):
    ips = load_false_positive_ips()
    ips.add(ip.strip())
    with open(FP_IPS_FILE, "w") as f:
        for i in sorted(ips):
            f.write(i + "\n")

def remove_false_positive_ip(ip: str):
    ips = load_false_positive_ips()
    ips.discard(ip.strip())
    with open(FP_IPS_FILE, "w") as f:
        for i in sorted(ips):
            f.write(i + "\n")

# ====================== LOGIN SYSTEM ======================
# Users live in the `users` table so sign-ups persist across restarts.
# The three demo accounts are seeded on first run (see _seed_default_users).
_DEFAULT_USERS = [
    ("admin",   "admin123",   "admin",   "Administrator"),
    ("analyst", "analyst123", "analyst", "SOC Analyst"),
    ("viewer",  "viewer123",  "viewer",  "Read-Only Viewer"),
]
SIGNUP_DEFAULT_ROLE = "viewer"   # self-registered accounts are read-only

_CREATE_USERS_SQL = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'viewer',
    display_name  TEXT,
    created_at    TEXT
)
"""

LOCKOUT_MAX_ATTEMPTS = 3
LOCKOUT_DURATION     = 60  # seconds

# --- Off-hours detection ---
OFF_HOURS_START = 22  # 10 PM
OFF_HOURS_END   = 7   # 7 AM

def is_off_hours() -> bool:
    hour = datetime.now().hour
    return hour >= OFF_HOURS_START or hour < OFF_HOURS_END

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def _users_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute(_CREATE_USERS_SQL)
    conn.commit()
    return conn

def _seed_default_users():
    """Insert the built-in demo accounts once, without clobbering edits."""
    conn = _users_conn()
    for username, pw, role, display in _DEFAULT_USERS:
        conn.execute(
            """INSERT OR IGNORE INTO users
               (username, password_hash, role, display_name, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (username, hash_password(pw), role, display, datetime.now().isoformat()),
        )
    conn.commit()
    conn.close()

def authenticate(username: str, password: str):
    username = username.lower().strip()
    conn = _users_conn()
    row = conn.execute(
        "SELECT role, display_name FROM users WHERE username = ? AND password_hash = ?",
        (username, hash_password(password)),
    ).fetchone()
    conn.close()
    if row:
        return {"role": row[0], "display_name": row[1]}
    return None

def register_user(username: str, password: str, display_name: str = "") -> tuple[bool, str]:
    """Create a new account. Returns (ok, message)."""
    username = username.lower().strip()
    if not username or not password:
        return False, "Username and password are required."
    if not username.isalnum():
        return False, "Username must be letters/numbers only (no spaces or symbols)."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."

    conn = _users_conn()
    exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    if exists:
        conn.close()
        return False, f"Username '{username}' is already taken."
    conn.execute(
        """INSERT INTO users (username, password_hash, role, display_name, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (username, hash_password(password), SIGNUP_DEFAULT_ROLE,
         display_name.strip() or username.title(), datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()
    return True, f"Account '{username}' created with role '{SIGNUP_DEFAULT_ROLE}'. You can sign in now."

# Ensure demo accounts exist before the login page renders.
_seed_default_users()

def logout():
    for key in ["authenticated", "username", "user_role", "display_name",
                "login_attempts", "lockout_until", "offhours_anomaly"]:
        st.session_state.pop(key, None)
    st.rerun()

# ====================== SESSION STATE INIT ======================
defaults = {
    "authenticated":    False,
    "auto_refresh":     True,
    "login_attempts":   0,
    "lockout_until":    0,
    "offhours_anomaly": False,
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ====================== LOGIN PAGE ======================
if not st.session_state.authenticated:
    # Dark background override for login
    st.markdown("""
    <style>
    [data-testid="stAppViewContainer"] {
        background: radial-gradient(ellipse at 30% 20%, #0f1e35 0%, #050a12 60%) !important;
    }
    </style>""", unsafe_allow_html=True)

    col_l, col_c, col_r = st.columns([1, 1.1, 1])
    with col_c:
        st.markdown("""
        <div style="text-align:center; padding: 40px 0 24px;">
            <div style="font-size: 3rem; margin-bottom: 8px;">🛡️</div>
            <div style="font-family: 'Syne', sans-serif; font-size: 1.8rem; font-weight: 800;
                        color: #e2eaf5; letter-spacing: -0.02em;">D H A Guard</div>
            <div style="color: #38bdf8; font-size: 0.85rem; font-weight: 600;
                        letter-spacing: 0.1em; text-transform: uppercase; margin-top: 4px;">
                Security Operations Center
            </div>
        </div>
        """, unsafe_allow_html=True)

        now = datetime.now()
        is_locked   = time.time() < st.session_state.lockout_until
        off_hours   = is_off_hours()

        # ---- Lockout banner ----
        if is_locked:
            remaining = int(st.session_state.lockout_until - time.time())
            st.markdown(f"""
            <div class="lock-banner">
                <div style="font-size:2rem; margin-bottom:8px;">🔒</div>
                <div style="color:#a78bfa; font-size:1.1rem; font-weight:700;">Account Temporarily Locked</div>
                <div style="color:#c4b5fd; margin-top:8px; font-size:0.9rem;">
                    Too many failed attempts. Please wait <strong style="color:#f0abfc;">{remaining}s</strong> before trying again.
                </div>
            </div>
            """, unsafe_allow_html=True)
            st.markdown("<br>", unsafe_allow_html=True)
            # Auto-rerun every second to count down
            st_autorefresh(interval=1000, limit=90, key="lockout_refresh")
            st.stop()

        # ---- Off-hours warning ----
        if off_hours:
            st.markdown(f"""
            <div style="background: linear-gradient(135deg, #1c1400, #2d1f00);
                        border: 1px solid #d97706; border-radius: 10px;
                        padding: 12px 16px; margin-bottom: 16px; font-size: 0.85rem;">
                ⚠️ <strong style="color:#fbbf24;">Off-Hours Access Detected</strong> —
                <span style="color:#fde68a;">Login at {now.strftime('%H:%M')} is outside normal hours (22:00–07:00).
                This access will be logged as an anomaly event.</span>
            </div>
            """, unsafe_allow_html=True)

        # ---- Sign In / Create Account toggle ----
        auth_mode = st.radio(
            "auth_mode", ["Sign In", "Create Account"],
            horizontal=True, label_visibility="collapsed", key="auth_mode",
        )

        if auth_mode == "Sign In":
            attempts_left = LOCKOUT_MAX_ATTEMPTS - st.session_state.login_attempts
            if st.session_state.login_attempts > 0:
                st.markdown(f"""
                <div style="text-align:center; color:#f87171; font-size:0.82rem; margin-bottom:8px;
                            font-family:'JetBrains Mono',monospace;">
                    ⚠️ {attempts_left} attempt{'s' if attempts_left != 1 else ''} remaining before lockout
                </div>
                """, unsafe_allow_html=True)

            with st.form("login_form"):
                username = st.text_input("Username", placeholder="Enter username")
                password = st.text_input("Password", type="password", placeholder="••••••••")
                submitted = st.form_submit_button("🔐 Sign In", use_container_width=True)

                if submitted:
                    # Re-check lockout (race condition guard)
                    if time.time() < st.session_state.lockout_until:
                        st.rerun()

                    user = authenticate(username, password)
                    if user:
                        st.session_state.authenticated    = True
                        st.session_state.username         = username.lower().strip()
                        st.session_state.user_role        = user["role"]
                        st.session_state.display_name     = user["display_name"]
                        st.session_state.login_attempts   = 0   # Reset on success
                        st.session_state.offhours_anomaly = off_hours
                        st.session_state.login_time       = now.strftime("%H:%M %d %b %Y")
                        st.rerun()
                    else:
                        st.session_state.login_attempts += 1
                        if st.session_state.login_attempts >= LOCKOUT_MAX_ATTEMPTS:
                            st.session_state.lockout_until = time.time() + LOCKOUT_DURATION
                            st.session_state.login_attempts = 0
                            st.rerun()
                        else:
                            st.error(f"❌ Invalid credentials. {LOCKOUT_MAX_ATTEMPTS - st.session_state.login_attempts} attempt(s) left.")

        else:  # Create Account
            with st.form("signup_form"):
                new_username = st.text_input("Username", placeholder="Choose a username", key="su_user")
                new_display  = st.text_input("Display name", placeholder="e.g. Jane Doe (optional)", key="su_display")
                new_password = st.text_input("Password", type="password", placeholder="At least 6 characters", key="su_pw")
                confirm_pw   = st.text_input("Confirm password", type="password", placeholder="Re-enter password", key="su_pw2")
                signup_submitted = st.form_submit_button("✨ Create Account", use_container_width=True)

                if signup_submitted:
                    if new_password != confirm_pw:
                        st.error("❌ Passwords do not match.")
                    else:
                        ok, msg = register_user(new_username, new_password, new_display)
                        if ok:
                            st.success(f"✅ {msg}")
                        else:
                            st.error(f"❌ {msg}")
            st.markdown("""
            <div style="text-align:center; margin-top:12px; color:#4a6080; font-size:0.76rem;
                        font-family:'JetBrains Mono',monospace;">
                New accounts get read-only (viewer) access.
            </div>
            """, unsafe_allow_html=True)

    st.stop()

# ====================== MAIN DASHBOARD ======================
# Only viewers are read-only: they see all data, charts, XAI and intel but
# cannot modify state. Admins and analysts may inject/reset/edit the whitelist.
can_modify = st.session_state.get("user_role", "").lower() != "viewer"

false_positive_ips = load_false_positive_ips()

@st.cache_data(ttl=3)
def get_alerts() -> pd.DataFrame:
    try:
        conn = sqlite3.connect(DB_PATH)
        df   = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC", conn)
        conn.close()
        if not df.empty:
            if "src_ip" in df.columns and "dst_ip" in df.columns:
                df = df[
                    ~df["src_ip"].isin(false_positive_ips) &
                    ~df["dst_ip"].isin(false_positive_ips)
                ]
        return df
    except Exception:
        return pd.DataFrame()

def source_badge(row):
    src = str(row.get("source", "engine")).lower()
    return "🔴 Snort" if src == "snort" else "🟡 Engine"

def severity_from_confidence(conf):
    if conf >= 0.90: return "🔴 Critical"
    if conf >= 0.75: return "🟠 High"
    if conf >= 0.50: return "🟡 Medium"
    return "🟢 Low"

# ====================== SIDEBAR ======================
with st.sidebar:
    st.markdown("""
    <div style="padding: 12px 0 20px; border-bottom: 1px solid #1a2e45; margin-bottom: 16px;">
        <div style="font-family:'Syne',sans-serif; font-size:1.2rem; font-weight:800; color:#e2eaf5;">
            🛡️ D H A Guard
        </div>
        <div style="color:#38bdf8; font-size:0.72rem; letter-spacing:0.1em; text-transform:uppercase; margin-top:2px;">
            Network IDS v1.0
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(f"""
    <div style="background:#0d1a2d; border:1px solid #1a2e45; border-radius:10px; padding:12px; margin-bottom:12px;">
        <div style="color:#94a3b8; font-size:0.72rem; text-transform:uppercase; letter-spacing:0.08em;">Logged in as</div>
        <div style="color:#e2eaf5; font-weight:700; margin-top:4px;">{st.session_state.get('display_name','User')}</div>
        <div style="color:#64748b; font-size:0.75rem; font-family:'JetBrains Mono',monospace;">
            {st.session_state.get('user_role','').upper()} · {st.session_state.get('login_time','')}
        </div>
    </div>
    """, unsafe_allow_html=True)

    # System status
    st.markdown("""
    <div style="display:flex; align-items:center; gap:8px; margin-bottom:16px;
                background:#0a1f12; border:1px solid #166534; border-radius:8px; padding:10px 12px;">
        <span class="status-dot"></span>
        <span style="color:#86efac; font-size:0.82rem; font-weight:600;">System Active — Snort + ML</span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("<div style='color:#64748b; font-size:0.75rem; text-transform:uppercase; letter-spacing:0.08em; margin-bottom:8px;'>Controls</div>", unsafe_allow_html=True)

    st.session_state.auto_refresh = st.toggle("⚡ Auto-refresh (5s)", value=st.session_state.auto_refresh)

    st.markdown("---")

    # ---- Snort status indicator ----
    snort_running = os.path.exists(SNORT_ALERT_FILE)
    if snort_running:
        st.markdown("""
        <div style="background:#0a1f12; border:1px solid #166534; border-radius:8px;
                    padding:10px 12px; margin-bottom:10px; font-size:0.8rem;">
            🟢 <strong style="color:#86efac;">Snort file found</strong><br>
            <span style="color:#4ade80; font-family:'JetBrains Mono',monospace; font-size:0.7rem;">Signature alerts: LIVE</span>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div style="background:#1a0e0e; border:1px solid #7f1d1d; border-radius:8px;
                    padding:10px 12px; margin-bottom:10px; font-size:0.78rem;">
            🔴 <strong style="color:#fca5a5;">Snort not detected</strong><br>
            <span style="color:#f87171; font-family:'JetBrains Mono',monospace; font-size:0.68rem;">
            alert.fast not found<br>Use simulator below ↓
            </span>
        </div>
        """, unsafe_allow_html=True)

    # ---- Demo: Inject Snort alert (admins only) ----
    if can_modify:
        st.markdown("<div style='color:#64748b; font-size:0.72rem; text-transform:uppercase; letter-spacing:0.08em; margin:10px 0 6px;'>🧪 Snort Simulator</div>", unsafe_allow_html=True)

        rule_options = {r[0]: r[0].replace("_", " ").title() for r in _SNORT_RULES}
        selected_rule = st.selectbox("Rule to inject", options=list(rule_options.keys()),
                                      format_func=lambda x: rule_options[x], key="sim_rule",
                                      label_visibility="collapsed")

        col_s1, col_s2 = st.columns(2)
        with col_s1:
            if st.button("💉 ×1", use_container_width=True, key="inject1"):
                if inject_snort_alert(selected_rule):
                    st.cache_data.clear()
                    st.rerun()
        with col_s2:
            if st.button("💉 ×5", use_container_width=True, key="inject5"):
                for _ in range(5):
                    inject_snort_alert(selected_rule)
                st.cache_data.clear()
                st.rerun()

        st.markdown("---")

    # ---- Reset alerts (admins only) ----
    if can_modify:
        st.markdown("<div style='color:#94241a; font-size:0.72rem; text-transform:uppercase; letter-spacing:0.08em; margin-bottom:6px;'>⚠️ Danger Zone</div>", unsafe_allow_html=True)

        if "confirm_reset" not in st.session_state:
            st.session_state.confirm_reset = False

        if not st.session_state.confirm_reset:
            if st.button("🗑️ Reset All Alerts", use_container_width=True, key="reset_btn"):
                st.session_state.confirm_reset = True
                st.rerun()
        else:
            st.warning("Delete ALL alerts from the database?")
            col_y, col_n = st.columns(2)
            with col_y:
                if st.button("✅ Yes", use_container_width=True, key="confirm_yes"):
                    deleted = clear_all_alerts()
                    st.session_state.confirm_reset = False
                    st.cache_data.clear()
                    st.success(f"Cleared {deleted} rows.")
                    st.rerun()
            with col_n:
                if st.button("❌ No", use_container_width=True, key="confirm_no"):
                    st.session_state.confirm_reset = False
                    st.rerun()

        st.markdown("---")

    if st.button("🚪 Logout", use_container_width=True):
        logout()

    st.markdown(f"""
    <div style="margin-top:auto; padding-top:16px; color:#334155; font-size:0.7rem;
                font-family:'JetBrains Mono',monospace; text-align:center;">
        Whitelisted IPs: {len(false_positive_ips)}<br>
        {datetime.now().strftime('%d %b %Y %H:%M')}
    </div>
    """, unsafe_allow_html=True)

# ====================== OFF-HOURS ANOMALY BANNER ======================
if st.session_state.get("offhours_anomaly"):
    login_time = st.session_state.get("login_time", "")
    st.markdown(f"""
    <div style="background: linear-gradient(135deg, #1c0a00, #2d1500);
                border: 1px solid #ea580c; border-radius: 12px;
                padding: 14px 20px; margin-bottom: 20px;
                display: flex; align-items: center; gap: 16px;">
        <div style="font-size:1.8rem;">🌙</div>
        <div>
            <div style="color:#fb923c; font-weight:700; font-size:0.95rem;">
                OFF-HOURS LOGIN ANOMALY DETECTED
            </div>
            <div style="color:#fed7aa; font-size:0.82rem; margin-top:3px;">
                Login recorded at <strong>{login_time}</strong> — outside normal operating hours (07:00–22:00).
                This event has been flagged as a behavioural anomaly for audit purposes.
            </div>
        </div>
        <div style="margin-left:auto; background:#431407; border:1px solid #c2410c;
                    border-radius:6px; padding:6px 12px; font-size:0.75rem;
                    color:#fdba74; font-family:'JetBrains Mono',monospace; white-space:nowrap;">
            ANOMALY · LOGGED
        </div>
    </div>
    """, unsafe_allow_html=True)

# ====================== HEADER ======================
col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.markdown("""
    <div style="margin-bottom: 8px;">
        <span style="font-family:'Syne',sans-serif; font-size:1.75rem; font-weight:800; color:#e2eaf5;">
            Security Dashboard
        </span><br>
        <span style="color:#475569; font-size:0.85rem; font-family:'JetBrains Mono',monospace;">
            D H A Guard — Hybrid Detection System · DNWS/1
        </span>
    </div>
    """, unsafe_allow_html=True)
with col_h2:
    st.markdown("""
    <div style="text-align:right; padding-top:8px;">
        <span style="background:#0a1f12; border:1px solid #166534; border-radius:20px;
                     padding:6px 14px; color:#86efac; font-size:0.8rem; font-weight:600;">
            ● Snort + ML Active
        </span>
    </div>
    """, unsafe_allow_html=True)

# ====================== AUTO-REFRESH ======================
if st.session_state.auto_refresh:
    st_autorefresh(interval=5000, limit=1000, key="datarefresh")

# ====================== LOAD DATA ======================
df = get_alerts()

# ====================== TOP METRICS ======================
total     = len(df)
anomalies = len(df[df["type"] == "anomaly"])       if not df.empty else 0
sigs      = len(df[df["source"] == "snort"])        if not df.empty else 0
high_conf = len(df[df["confidence"] > 0.8])         if not df.empty else 0

m1, m2, m3, m4 = st.columns(4)
with m1:
    st.markdown(f"""
    <div class="alert-card info">
        <div style="color:#64748b; font-size:0.72rem; text-transform:uppercase; letter-spacing:0.08em;">Total Alerts</div>
        <div style="font-size:2.2rem; font-weight:800; color:#38bdf8; font-family:'Syne',sans-serif;">{total}</div>
        <div style="color:#475569; font-size:0.78rem;">All detected events</div>
    </div>""", unsafe_allow_html=True)
with m2:
    st.markdown(f"""
    <div class="alert-card critical">
        <div style="color:#64748b; font-size:0.72rem; text-transform:uppercase; letter-spacing:0.08em;">High Confidence</div>
        <div style="font-size:2.2rem; font-weight:800; color:#ef4444; font-family:'Syne',sans-serif;">{high_conf}</div>
        <div style="color:#475569; font-size:0.78rem;">Confidence &gt; 80%</div>
    </div>""", unsafe_allow_html=True)
with m3:
    st.markdown(f"""
    <div class="alert-card warning">
        <div style="color:#64748b; font-size:0.72rem; text-transform:uppercase; letter-spacing:0.08em;">ML Anomalies</div>
        <div style="font-size:2.2rem; font-weight:800; color:#f59e0b; font-family:'Syne',sans-serif;">{anomalies}</div>
        <div style="color:#475569; font-size:0.78rem;">IsolationForest detections</div>
    </div>""", unsafe_allow_html=True)
with m4:
    st.markdown(f"""
    <div class="alert-card" style="border-left:4px solid #22c55e;">
        <div style="color:#64748b; font-size:0.72rem; text-transform:uppercase; letter-spacing:0.08em;">Snort Signatures</div>
        <div style="font-size:2.2rem; font-weight:800; color:#22c55e; font-family:'Syne',sans-serif;">{sigs}</div>
        <div style="color:#475569; font-size:0.78rem;">Rule-based detections</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ====================== TABS ======================
tab_monitor, tab_xai, tab_map, tab_intel, tab_fp = st.tabs([
    "📡 Live Monitor", "🧠 XAI Analysis", "🗺️ Network Map",
    "🔎 Threat Intel", "⚙️ Whitelist"
])

# ==================== TAB 1: LIVE MONITOR ====================
with tab_monitor:
    st.markdown("### 🔎 Filter Alerts")
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        src_ip_filter = st.text_input("Source IP", placeholder="192.168.x.x", label_visibility="visible")
    with c2:
        dst_ip_filter = st.text_input("Destination IP", placeholder="0.0.0.0")
    with c3:
        src_port_filter = st.number_input("Src Port", min_value=0, value=None, placeholder="e.g. 22")
    with c4:
        dst_port_filter = st.number_input("Dst Port", min_value=0, value=None, placeholder="e.g. 80")
    with c5:
        alert_type_filter = st.selectbox("Type", ["All", "anomaly", "signature"])

    # Apply filters
    filtered_df = df.copy()
    if src_ip_filter:
        filtered_df = filtered_df[filtered_df["src_ip"].astype(str).str.contains(src_ip_filter, na=False)]
    if dst_ip_filter:
        filtered_df = filtered_df[filtered_df["dst_ip"].astype(str).str.contains(dst_ip_filter, na=False)]
    if src_port_filter is not None:
        filtered_df = filtered_df[filtered_df["src_port"] == src_port_filter]
    if dst_port_filter is not None:
        filtered_df = filtered_df[filtered_df["dst_port"] == dst_port_filter]
    if alert_type_filter != "All":
        filtered_df = filtered_df[filtered_df["type"] == alert_type_filter]

    st.markdown(f"**Showing {len(filtered_df)} alert(s)**")
    st.markdown("---")

    if filtered_df.empty:
        st.markdown("""
        <div style="text-align:center; padding:40px; color:#475569;">
            <div style="font-size:2rem; margin-bottom:8px;">🔍</div>
            <div>No alerts match your current filters.</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        display_df = filtered_df.head(30).copy()
        display_df["origin"]   = display_df.apply(source_badge, axis=1)
        display_df["severity"] = display_df["confidence"].apply(severity_from_confidence)
        st.dataframe(
            display_df[["timestamp", "severity", "origin", "type", "rule",
                         "src_ip", "dst_ip", "src_port", "dst_port", "confidence", "reason"]],
            use_container_width=True, hide_index=True,
            column_config={
                "confidence": st.column_config.ProgressColumn("Confidence", min_value=0, max_value=1, format="%.2f"),
            }
        )

    st.markdown("---")
    col_pie, col_bar = st.columns(2)
    with col_pie:
        st.markdown("#### Alert Distribution")
        if not filtered_df.empty:
            dist = filtered_df.groupby("source").size().reset_index(name="count")
            fig  = px.pie(
                dist, names="source", values="count",
                color_discrete_sequence=["#38bdf8", "#ef4444", "#f59e0b"],
                hole=0.45,
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#94a3b8"),
                legend=dict(font=dict(color="#94a3b8")),
                margin=dict(t=20, b=20),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No data to display.")

    with col_bar:
        st.markdown("#### Top Source IPs")
        if not filtered_df.empty:
            top_ips = filtered_df["src_ip"].value_counts().head(8)
            fig2 = px.bar(
                x=top_ips.values, y=top_ips.index,
                orientation="h",
                color=top_ips.values,
                color_continuous_scale=["#1e3a5f", "#38bdf8", "#ef4444"],
            )
            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#94a3b8"),
                xaxis=dict(gridcolor="#1a2e45"),
                yaxis=dict(gridcolor="#1a2e45"),
                showlegend=False,
                coloraxis_showscale=False,
                margin=dict(t=10, b=10),
            )
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No data to display.")

# ==================== TAB 2: XAI ANALYSIS ====================
with tab_xai:
    st.markdown("### 🧠 Explainable AI — Why was it flagged?")
    st.caption("IsolationForest scores each flow against normal baseline. Large deviations in packet rate, byte rate, or window size trigger anomaly alerts.")

    # Off-hours anomaly explainer card (great for demo!)
    if st.session_state.get("offhours_anomaly"):
        login_time = st.session_state.get("login_time", "unknown")
        st.markdown(f"""
        <div style="background:#0f1a0a; border:1px solid #22c55e; border-radius:12px; padding:20px; margin-bottom:20px;">
            <div style="color:#86efac; font-weight:700; font-size:1rem; margin-bottom:8px;">
                🌙 Behavioural Anomaly: Off-Hours Login
            </div>
            <div style="color:#94a3b8; font-size:0.85rem; line-height:1.6;">
                <strong style="color:#d1fae5;">What happened:</strong> A login was recorded at
                <strong style="color:#6ee7b7; font-family:'JetBrains Mono',monospace;">{login_time}</strong>,
                which is outside the normal operating window of 07:00–22:00.<br><br>
                <strong style="color:#d1fae5;">Why it's anomalous:</strong> IDS behavioural models establish a baseline of 
                "normal" activity — including <em>when</em> users typically access the system. Access outside this window 
                deviates from the learned baseline, similar to how network traffic anomalies are detected.<br><br>
                <strong style="color:#d1fae5;">Detection method:</strong> Rule-based time-window check 
                (22:00–07:00 = off-hours). In production, this would be modelled using session frequency distributions.
            </div>
            <div style="margin-top:12px; display:flex; gap:8px; flex-wrap:wrap;">
                <span style="background:#166534; color:#86efac; padding:4px 10px; border-radius:4px; font-size:0.75rem;">TYPE: behavioural_anomaly</span>
                <span style="background:#1e3a5f; color:#7dd3fc; padding:4px 10px; border-radius:4px; font-size:0.75rem;">SOURCE: auth_monitor</span>
                <span style="background:#451a03; color:#fdba74; padding:4px 10px; border-radius:4px; font-size:0.75rem;">CONFIDENCE: HIGH</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    baseline = None
    try:
        data    = np.load(NORMAL_DATA_PATH)
        means   = np.mean(data, axis=0)
        baseline = {
            "Packet Size":   float(means[0]),
            "Pkt Rate":      float(means[1]),
            "Byte Rate":     float(means[2]),
            "Win Size":      float(means[3]),
        }
        st.markdown(f"""
        <div style="background:#0d1a2d; border:1px solid #1a2e45; border-radius:10px;
                    padding:14px 20px; margin-bottom:16px;">
            <div style="color:#64748b; font-size:0.72rem; text-transform:uppercase; letter-spacing:0.08em; margin-bottom:8px;">
                Normal Baseline (CIC-IDS2017 — {data.shape[0]:,} samples)
            </div>
            <div style="display:flex; gap:24px; flex-wrap:wrap;">
                {''.join(f'<div><span style="color:#94a3b8; font-size:0.78rem;">{k}</span><br><span style="color:#38bdf8; font-family:JetBrains Mono,monospace; font-size:0.9rem;">{v:.1f}</span></div>' for k, v in baseline.items())}
            </div>
        </div>
        """, unsafe_allow_html=True)
    except Exception:
        st.warning("Normal baseline data not found. Run `preprocess_cic_ids2017.py` first.")

    anomaly_df = df[df["type"] == "anomaly"].copy() if not df.empty else pd.DataFrame()

    if anomaly_df.empty:
        st.info("No ML anomalies detected yet. The system is monitoring live traffic.")
    else:
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("#### Top Anomaly Reasons")
            reason_counts = anomaly_df["reason"].value_counts().head(10)
            fig_reason = px.bar(
                x=reason_counts.values, y=reason_counts.index, orientation="h",
                color=reason_counts.values, color_continuous_scale=["#1e3a5f", "#ef4444"],
            )
            fig_reason.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#94a3b8"), xaxis=dict(gridcolor="#1a2e45"),
                yaxis=dict(gridcolor="#1a2e45"), showlegend=False,
                coloraxis_showscale=False, margin=dict(t=0, b=0),
            )
            st.plotly_chart(fig_reason, use_container_width=True)

        with col_b:
            st.markdown("#### Anomaly Timeline")
            if "timestamp" in anomaly_df.columns:
                try:
                    anomaly_df["ts"] = pd.to_datetime(anomaly_df["timestamp"])
                    timeline = anomaly_df.groupby(anomaly_df["ts"].dt.floor("5min")).size().reset_index(name="count")
                    fig_tl = px.area(timeline, x="ts", y="count", color_discrete_sequence=["#f59e0b"])
                    fig_tl.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                        font=dict(color="#94a3b8"), xaxis=dict(gridcolor="#1a2e45"),
                        yaxis=dict(gridcolor="#1a2e45"), margin=dict(t=0, b=0),
                    )
                    st.plotly_chart(fig_tl, use_container_width=True)
                except Exception:
                    st.info("Could not render timeline.")

        st.markdown("---")
        st.markdown("#### Feature Deviation Analysis")
        selected_idx = st.selectbox(
            "Select anomaly to inspect",
            anomaly_df.index,
            format_func=lambda i: f"{anomaly_df.loc[i, 'timestamp']} │ {anomaly_df.loc[i, 'src_ip']} → {anomaly_df.loc[i, 'dst_ip']}",
        )
        alert_row = anomaly_df.loc[selected_idx]
        st.markdown(f"""
        <div style="background:#0d1a2d; border:1px solid #1a2e45; border-radius:8px; padding:12px 16px; margin-bottom:12px;">
            <span style="color:#64748b; font-size:0.78rem;">Rule: </span>
            <span style="color:#38bdf8; font-family:'JetBrains Mono',monospace;">{alert_row.get('rule','N/A')}</span>
            &nbsp;&nbsp;
            <span style="color:#64748b; font-size:0.78rem;">Confidence: </span>
            <span style="color:#f59e0b; font-family:'JetBrains Mono',monospace;">{float(alert_row.get('confidence',0)):.2f}</span>
            &nbsp;&nbsp;
            <span style="color:#64748b; font-size:0.78rem;">Reason: </span>
            <span style="color:#e2eaf5;">{alert_row.get('reason','N/A')}</span>
        </div>
        """, unsafe_allow_html=True)

        intel = IntelFactory()

        # Use the real feature vector captured for this anomaly. Alerts created
        # before the `features` column existed (or Snort-injected ones) won't
        # have it — fall back gracefully instead of showing placeholder data.
        raw_features = alert_row.get("features") if "features" in anomaly_df.columns else None
        real_features = None
        if raw_features is not None and not (isinstance(raw_features, float) and pd.isna(raw_features)):
            try:
                real_features = json.loads(raw_features)
            except (TypeError, ValueError):
                real_features = None

        if real_features is None:
            st.info(
                "No feature vector stored for this alert — it predates the XAI "
                "feature-capture update (or came from Snort). Newer engine "
                "anomalies will show real per-feature deviations here."
            )
            deviations = []
        else:
            deviations = intel.get_feature_deviations(real_features)

        if deviations:
            dev_df = pd.DataFrame(deviations)
            st.dataframe(dev_df, use_container_width=True, hide_index=True)
            fig_dev = px.bar(
                dev_df, x="deviation_pct", y="label", orientation="h",
                title="Deviation % from Normal Baseline",
                color="deviation_pct",
                color_continuous_scale=["#22c55e", "#f59e0b", "#ef4444"],
            )
            fig_dev.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#94a3b8"), xaxis=dict(gridcolor="#1a2e45"),
                yaxis=dict(gridcolor="#1a2e45"), coloraxis_showscale=False,
                title_font=dict(color="#94a3b8"),
            )
            st.plotly_chart(fig_dev, use_container_width=True)

# ==================== TAB 3: NETWORK MAP ====================
with tab_map:
    st.markdown("### 🗺️ Live Network Topology")
    if df.empty:
        st.markdown("""
        <div style="text-align:center; padding:60px; color:#475569;">
            <div style="font-size:2.5rem; margin-bottom:12px;">🌐</div>
            <div>No alerts yet — topology will populate as threats are detected.</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        unique_ips = df["src_ip"].dropna().unique()
        node_x, node_y, node_text, node_color, node_size = [], [], [], [], []
        edge_x, edge_y = [], []

        # Sensor / gateway node at centre
        node_x.append(0); node_y.append(0)
        node_text.append("SENSOR\n(Gateway)"); node_color.append("#38bdf8"); node_size.append(30)

        n = len(unique_ips)
        for i, ip in enumerate(unique_ips):
            angle = 2 * math.pi * i / max(n, 1)
            r = 1.8
            x, y = r * math.cos(angle), r * math.sin(angle)
            node_x.append(x); node_y.append(y)
            node_text.append(ip)
            is_snort = any(df[df["src_ip"] == ip]["source"] == "snort")
            node_color.append("#ef4444" if is_snort else "#f59e0b")
            node_size.append(20)
            # Edges from centre to node
            edge_x += [0, x, None]; edge_y += [0, y, None]

        edge_trace = go.Scatter(x=edge_x, y=edge_y, mode="lines",
                                line=dict(color="#1e3a5f", width=1.5), hoverinfo="none")
        node_trace = go.Scatter(
            x=node_x, y=node_y, mode="markers+text", text=node_text,
            textfont=dict(color="#94a3b8", size=10, family="JetBrains Mono"),
            marker=dict(color=node_color, size=node_size,
                        line=dict(color="#0d1a2d", width=2)),
            hovertemplate="%{text}<extra></extra>",
            textposition="top center",
        )
        fig_topo = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="#080c14",
                showlegend=False,
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-2.5, 2.5]),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-2.5, 2.5]),
                height=550,
                margin=dict(l=0, r=0, t=0, b=0),
            ),
        )
        st.plotly_chart(fig_topo, use_container_width=True)

        # Legend
        st.markdown("""
        <div style="display:flex; gap:16px; justify-content:center; font-size:0.8rem; color:#64748b; margin-top:8px;">
            <span>🔵 Sensor / Gateway</span>
            <span>🔴 Snort-detected source</span>
            <span>🟡 ML-detected source</span>
        </div>
        """, unsafe_allow_html=True)

# ==================== TAB 4: THREAT INTEL ====================
with tab_intel:
    st.markdown("### 🔎 External Threat Intelligence")
    st.caption("AbuseIPDB reputation scores for top alert source IPs. Requires ABUSE_IP_KEY in .env.")
    if df.empty:
        st.info("No alerts to analyse yet.")
    else:
        top_ips = df["src_ip"].value_counts().head(6).index.tolist()
        intel   = IntelFactory()
        results = []
        for ip in top_ips:
            score = intel.get_ip_reputation(ip)
            count = int((df["src_ip"] == ip).sum())
            try:
                s = int(score)
                risk = "🔴 High" if s > 70 else "🟠 Medium" if s > 30 else "🟢 Low"
            except Exception:
                risk = "⚪ N/A"
            results.append({"IP Address": ip, "Alert Count": count,
                             "AbuseIPDB Score": score, "Risk Level": risk})

        intel_df = pd.DataFrame(results)
        st.dataframe(intel_df, use_container_width=True, hide_index=True)

        if not intel_df.empty:
            try:
                fig_intel = px.bar(
                    intel_df, x="IP Address", y="AbuseIPDB Score",
                    color="AbuseIPDB Score",
                    color_continuous_scale=["#22c55e", "#f59e0b", "#ef4444"],
                    title="AbuseIPDB Reputation Scores",
                )
                fig_intel.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#94a3b8"), xaxis=dict(gridcolor="#1a2e45"),
                    yaxis=dict(gridcolor="#1a2e45"), coloraxis_showscale=False,
                    title_font=dict(color="#94a3b8"),
                )
                st.plotly_chart(fig_intel, use_container_width=True)
            except Exception:
                pass

# ==================== TAB 5: WHITELIST MANAGEMENT ====================
with tab_fp:
    st.markdown("### ⚙️ IP Whitelist / False Positive Management")
    st.caption("IPs added here are ignored whether they appear as **Source** or **Destination**. Use for trusted internal hosts.")

    col1, col2 = st.columns([2, 1])
    with col1:
        if can_modify:
            new_ip = st.text_input("IP Address to whitelist", placeholder="e.g. 192.168.8.100", key="new_ip_input")
            if st.button("➕ Add to Whitelist", type="primary", use_container_width=True):
                if new_ip and new_ip.strip():
                    save_false_positive_ip(new_ip.strip())
                    st.success(f"✅ {new_ip} added — both directions will be suppressed.")
                    st.rerun()
                else:
                    st.error("Please enter a valid IP address.")
        else:
            st.info("🔒 Read-only access — whitelist changes require an admin account.")

    with col2:
        st.markdown(f"""
        <div style="background:#0d1a2d; border:1px solid #1a2e45; border-radius:10px;
                    padding:16px; text-align:center; margin-top:28px;">
            <div style="font-size:1.8rem; font-weight:800; color:#38bdf8;">{len(false_positive_ips)}</div>
            <div style="color:#64748b; font-size:0.78rem;">IPs whitelisted</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### Current Whitelist")
    current_ips = load_false_positive_ips()

    if current_ips:
        fp_df = pd.DataFrame(sorted(list(current_ips)), columns=["IP Address"])
        st.dataframe(fp_df, use_container_width=True, hide_index=True)

        if can_modify:
            st.markdown("#### Remove an IP")
            ip_to_remove = st.selectbox("Select IP to remove", options=sorted(current_ips), key="remove_select")
            if st.button("🗑️ Remove from Whitelist", use_container_width=True):
                remove_false_positive_ip(ip_to_remove)
                st.success(f"Removed {ip_to_remove} from whitelist.")
                st.rerun()
    else:
        st.markdown("""
        <div style="text-align:center; padding:30px; color:#475569;">
            <div style="font-size:1.8rem; margin-bottom:8px;">📋</div>
            <div>No IPs whitelisted yet.</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div style="background:#0d1a2d; border:1px solid #1a2e45; border-radius:8px;
                padding:12px 16px; margin-top:16px; font-size:0.8rem; color:#64748b;">
        💡 <strong style="color:#94a3b8;">Tip:</strong> Add sensor IPs and known-good internal hosts here
        to reduce false positives. The list is also read by <code>alert_system.py</code> at runtime.
    </div>
    """, unsafe_allow_html=True)
