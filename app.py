# Create a virtual environment
#python3 -m venv venv

# Activate it
#source venv/bin/activate

# Install Streamlit
#pip install streamlit

# Run your app
#streamlit run app.py

import streamlit as st
import pandas as pd
import psutil
import time
import os
import sqlite3
from datetime import datetime
from collections import deque

from log_monitor import stream_system_logs, parse_log

# -----------------------------
# CONFIG
# -----------------------------
st.set_page_config(page_title="ZenByte SOC Lab", layout="wide")

st.title("🛡️ ZenByte SOC - Real Device Monitor")

# -----------------------------
# SESSION STATE
# -----------------------------
if "running" not in st.session_state:
    st.session_state.running = False

if "logs" not in st.session_state:
    st.session_state.logs = deque(maxlen=200)

if "browser" not in st.session_state:
    st.session_state.browser = deque(maxlen=50)

# -----------------------------
# SIDEBAR
# -----------------------------
st.sidebar.header("Controls")

start = st.sidebar.button("▶ Start Monitoring")
stop = st.sidebar.button("⛔ Stop")

allow_browser = st.sidebar.checkbox("Allow Chrome History Access")

if start:
    st.session_state.running = True

if stop:
    st.session_state.running = False

# -----------------------------
# SYSTEM METRICS
# -----------------------------
def system_metrics():
    return {
        "cpu": psutil.cpu_percent(interval=0.5),
        "ram": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage("/").percent,
        "processes": len(psutil.pids())
    }

# -----------------------------
# CHROME HISTORY (REAL)
# -----------------------------
def chrome_history(limit=10):
    base = os.path.expanduser(
        "~/Library/Application Support/Google/Chrome/Default/History"
    )

    if not os.path.exists(base):
        return []

    try:
        conn = sqlite3.connect(base)
        cur = conn.cursor()

        cur.execute("""
            SELECT url, title
            FROM urls
            ORDER BY last_visit_time DESC
            LIMIT ?
        """, (limit,))

        rows = cur.fetchall()
        conn.close()

        return [
            {"time": datetime.now().strftime("%H:%M:%S"), "url": u, "title": t}
            for u, t in rows
        ]

    except:
        return []

# -----------------------------
# MAIN LOOP
# -----------------------------
placeholder = st.empty()

if st.session_state.running:

    logs = stream_system_logs()

    for line in logs:

        if not st.session_state.running:
            break

        # SECURITY LOGS
        event = parse_log(line)
        if event:
            st.session_state.logs.append(event)

        df_logs = pd.DataFrame(list(st.session_state.logs))

        # SYSTEM
        sys = system_metrics()

        # BROWSER
        if allow_browser:
            history = chrome_history()
            st.session_state.browser.extend(history)

        df_browser = pd.DataFrame(list(st.session_state.browser))

        # ---------------- UI ----------------
        with placeholder.container():

            st.subheader("🖥 System Health (REAL)")

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("CPU %", sys["cpu"])
            c2.metric("RAM %", sys["ram"])
            c3.metric("DISK %", sys["disk"])
            c4.metric("PROCESSES", sys["processes"])

            st.divider()

            st.subheader("📡 Security Events")

            if len(df_logs) == 0:
                st.info("Waiting for system events...")
            else:
                st.dataframe(df_logs.tail(10), use_container_width=True)

            st.divider()

            if allow_browser:
                st.subheader("🌐 Chrome History (REAL READ ONLY)")

                if len(df_browser) == 0:
                    st.warning("No browser data or Chrome locked.")
                else:
                    st.dataframe(df_browser.tail(10), use_container_width=True)

        time.sleep(1)

else:
    st.info("Click START to begin monitoring")