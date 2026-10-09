"""
Security Operation Center - a local SOC analyst dashboard.
Upload Zeek, Sysmon, Windows Event, or CloudTrail logs and get anomaly
detection + MITRE ATT&CK mapping + IOC extraction, entirely on your machine.
Nothing here calls an external API - all analysis is rule-based/statistical
and runs in this Python process.
"""

# Create a virtual environment
#python3 -m venv venv

# Activate it
#source venv/bin/activate

# Install Streamlit
#pip install streamlit

# Run your app
#streamlit run app.py

import json
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from parsers import load_raw_records, detect_log_type, normalize


def _ensure_streamlit_runtime() -> None:
    """Fail fast when the dashboard is launched without Streamlit's script runner."""
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx

        if get_script_run_ctx() is None:
            raise RuntimeError("Script run context is unavailable")
    except Exception:
        print("This dashboard must be launched with: streamlit run app.py")
        raise SystemExit(0)


_ensure_streamlit_runtime()
from ioc_extractor import extract_iocs
from mitre_mapper import map_techniques, technique_summary, tactic_summary, TOTAL_KNOWN_TECHNIQUES
from anomaly_detector import detect_anomalies, threat_level_distribution

st.set_page_config(page_title="Security Operation Center", page_icon="🛡️", layout="wide")

# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    .stApp { background-color: #0a0e1a; }
    section[data-testid="stSidebar"] { background-color: #0d1225; }
    div[data-testid="stMetric"] {
        background-color: #10162b; border: 1px solid #1f2947; border-radius: 10px;
        padding: 16px 18px;
    }
    .badge {
        display: inline-block; background: #1c1440; color: #a78bfa; border: 1px solid #3b2f78;
        border-radius: 999px; padding: 4px 14px; font-size: 0.8rem; font-family: monospace;
    }
    .lc-card {
        background-color: #10162b; border: 1px solid #1f2947; border-radius: 10px;
        padding: 20px; margin-bottom: 16px;
    }
    h1, h2, h3, h4 { color: #e5e9f5 !important; }
</style>
""", unsafe_allow_html=True)

LOG_TYPE_LABELS = {
    "zeek": "Zeek (Network)", "sysmon": "Sysmon (Windows System)",
    "windows_event": "Windows Events", "cloudtrail": "AWS CloudTrail", "generic": "Generic",
}
OVERRIDE_MAP = {"Zeek": "zeek", "Sysmon": "sysmon", "Windows Events": "windows_event",
                "CloudTrail": "cloudtrail", "Generic": "generic"}

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### Security Operation Center")
    st.caption("Upload -> Analyze -> Map to MITRE ATT&CK")

    uploaded = st.file_uploader(
        "Upload security logs",
        type=["json", "txt", "csv", "tsv", "log"],
        accept_multiple_files=True,
        help="Zeek (conn/dns/http.log), Sysmon, Windows Events, CloudTrail, or generic logs.",
    )

    override = st.selectbox(
        "Log source",
        ["Auto-detect", "Zeek", "Sysmon", "Windows Events", "CloudTrail", "Generic"],
        help="Override auto-detection if it picks the wrong format for your file.",
    )

    with st.expander("⚙️ Detection settings"):
        sensitivity = st.slider("Anomaly sensitivity (lower = more alerts)", 1.5, 4.0, 2.5, 0.1)

    use_sample = st.button("📂 Load sample data")

    st.markdown("---")
    st.markdown('<span class="badge">🔒 100% Local — no data leaves this machine</span>', unsafe_allow_html=True)
    st.caption("Detection is rule-based & statistical (regex, frequency analysis, "
               "z-scores, MITRE ATT&CK heuristics) — no cloud AI calls are made.")


@st.cache_data(show_spinner=False)
def process_files(file_data, override_type, _sensitivity_cache_key):
    """file_data: list of (filename, bytes). Returns combined normalized df + detected types."""
    frames = []
    detected_types = []
    for filename, content in file_data:
        records, _container = load_raw_records(content, filename)
        log_type = override_type or detect_log_type(records, filename)
        detected_types.append((filename, log_type, len(records)))
        frames.append(normalize(records, log_type))
    df = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    return df, detected_types


def make_sample_files():
    base = datetime.now(timezone.utc).timestamp()

    zeek_header = "#separator \\x09\n#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tquery\tmethod\thost\turi\torig_bytes\n"
    lines = []
    for i in range(40):
        lines.append(f"{base + i * 3}\t10.0.0.{5 + i % 3}\t{50000 + i}\t8.8.8.8\t53\tudp\tbeacon{i % 4}.evil-c2.net\t-\t-\t-\t120")
    for i in range(20):
        lines.append(f"{base + 400 + i * 2}\t10.0.0.5\t{51000 + i}\t203.0.113.{10 + i}\t80\ttcp\t-\tGET\twww.example.com\t/\t500")
    zeek_text = zeek_header + "\n".join(lines)

    now_iso = datetime.now(timezone.utc).isoformat()
    sysmon_records = [
        {"EventID": "1", "UtcTime": now_iso, "Computer": "WKS-042",
         "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "CommandLine": "powershell.exe -enc SQBFAFgA...", "User": "CORP\\jsmith",
         "ParentImage": "C:\\Windows\\explorer.exe"},
        {"EventID": "13", "UtcTime": now_iso, "Computer": "WKS-042",
         "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
         "User": "CORP\\jsmith"},
        {"EventID": "1", "UtcTime": now_iso, "Computer": "WKS-017",
         "Image": "C:\\Users\\bwayne\\Downloads\\invoice.exe", "CommandLine": "invoice.exe",
         "User": "CORP\\bwayne"},
    ]
    sysmon_text = "\n".join(json.dumps(r) for r in sysmon_records)

    cloudtrail_records = {"Records": [
        {"eventTime": now_iso, "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
         "sourceIPAddress": "203.0.113.99", "awsRegion": "us-east-1", "userIdentity": {"userName": "root"}},
        {"eventTime": now_iso, "eventName": "CreateAccessKey", "eventSource": "iam.amazonaws.com",
         "sourceIPAddress": "203.0.113.99", "awsRegion": "us-east-1", "userIdentity": {"userName": "root"}},
        {"eventTime": now_iso, "eventName": "GetObject", "eventSource": "s3.amazonaws.com",
         "sourceIPAddress": "203.0.113.99", "awsRegion": "us-east-1", "userIdentity": {"userName": "root"}},
    ]}
    cloudtrail_text = json.dumps(cloudtrail_records)

    return [
        ("sample_zeek_conn.log", zeek_text.encode()),
        ("sample_sysmon.json", sysmon_text.encode()),
        ("sample_cloudtrail.json", cloudtrail_text.encode()),
    ]


# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------
file_data = None
if use_sample:
    file_data = make_sample_files()
elif uploaded:
    file_data = [(f.name, f.read()) for f in uploaded]

st.markdown("#  SOC Analyst Dashboard")
st.caption("SOC Analyst Dashboard — local, rule-based log analysis with MITRE ATT&CK mapping")

if not file_data:
    st.info("👈 Upload Zeek, Sysmon, Windows Event, or CloudTrail logs in the sidebar — "
            "or click **Load sample data** to try it out.")
    st.stop()

override_type = OVERRIDE_MAP.get(override)
with st.spinner("Parsing logs..."):
    df, detected_types = process_files(file_data, override_type, sensitivity)

if df.empty:
    st.error("Couldn't parse any records from the uploaded file(s). Check the format and try again.")
    st.stop()

for fname, ltype, n in detected_types:
    st.caption(f"📄 **{fname}** → detected as **{LOG_TYPE_LABELS.get(ltype, ltype)}** ({n} records)")

with st.spinner("Running anomaly detection and MITRE ATT&CK mapping..."):
    iocs = extract_iocs(df)
    anomalies = detect_anomalies(df, sensitivity)
    mitre_hits = map_techniques(df)
    tech_summary = technique_summary(mitre_hits)
    tac_summary = tactic_summary(mitre_hits)
    threat_levels = threat_level_distribution(mitre_hits, anomalies)

n_techniques = tech_summary["technique_id"].nunique() if not tech_summary.empty else 0

# ---------------------------------------------------------------------------
# Top metrics
# ---------------------------------------------------------------------------
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Logs", f"{len(df):,}")
c2.metric("Anomalies", f"{len(anomalies):,}")
c3.metric("IOCs Found", f"{len(iocs):,}")
c4.metric("MITRE Techniques", f"{n_techniques}")

tab_analysis, tab_iocs, tab_mitre = st.tabs(["📈 Analysis", "🔍 IOCs", "🎯 MITRE ATT&CK"])

# ---------------------------------------------------------------------------
# Analysis tab
# ---------------------------------------------------------------------------
with tab_analysis:
    valid_ts = df["timestamp"].dropna()
    period = f"{valid_ts.min():%Y-%m-%d} – {valid_ts.max():%Y-%m-%d}" if not valid_ts.empty else "unknown"
    anomaly_rate = (len(anomalies) / len(df) * 100) if len(df) else 0
    verdict = ("No significant threats detected in the analyzed timeframe."
               if len(anomalies) == 0 and n_techniques == 0
               else f"Review the {len(anomalies)} flagged anomalies and {n_techniques} mapped technique(s) below.")
    st.markdown(f"""
    <div class="lc-card">
    <h4>📈 Analysis Summary</h4>
    <p>Analyzed {len(df):,} log entries and detected {len(anomalies)} anomalies ({anomaly_rate:.1f}% anomaly rate).
    Mapped activities to {n_techniques} MITRE ATT&CK technique(s), indicating potential adversary tactics. {verdict}</p>
    <p>🕐 <b>Analysis period:</b> {period}</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### ⚠️ Anomaly Timeline")
        if not anomalies.empty:
            hourly = anomalies.copy()
            hourly["hour"] = pd.to_datetime(hourly["timestamp"]).dt.floor("h")
            counts = hourly.groupby("hour").size().reset_index(name="count")
            fig = px.line(counts, x="hour", y="count", markers=True)
            fig.update_layout(template="plotly_dark", paper_bgcolor="#10162b", plot_bgcolor="#10162b", height=320)
            fig.update_traces(line_color="#f59e0b", marker_color="#f59e0b")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.caption("No anomalies detected to plot.")

    with col2:
        st.markdown("#### 📶 Event Types")
        if "action" in df.columns and df["action"].notna().any():
            counts = df["action"].dropna().astype(str).value_counts().head(8).reset_index()
            counts.columns = ["event_type", "count"]
            fig = px.bar(counts, x="event_type", y="count", color_discrete_sequence=["#8b5cf6"])
            fig.update_layout(template="plotly_dark", paper_bgcolor="#10162b", plot_bgcolor="#10162b", height=320)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.caption("No event-type field available for this log source.")

    st.markdown("#### 🛡️ Threat Level Distribution")
    if sum(threat_levels.values()) > 0:
        fig = go.Figure(data=[go.Pie(
            labels=list(threat_levels.keys()), values=list(threat_levels.values()), hole=0.35,
            marker=dict(colors=["#f87171", "#fb923c", "#facc15", "#818cf8"]),
        )])
        fig.update_layout(template="plotly_dark", paper_bgcolor="#10162b", height=380)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.caption("No findings yet — nothing to plot.")

    if not anomalies.empty:
        st.markdown("#### 🚨 Flagged Anomalies")
        st.dataframe(anomalies[["timestamp", "type", "severity", "description"]],
                     use_container_width=True, hide_index=True)

# ---------------------------------------------------------------------------
# IOCs tab
# ---------------------------------------------------------------------------
with tab_iocs:
    st.markdown("#### 🔍 Extracted Indicators of Compromise")
    if iocs.empty:
        st.caption("No IOCs extracted from this dataset.")
    else:
        types = ["All"] + sorted(iocs["type"].unique().tolist())
        picked = st.selectbox("Filter by type", types)
        shown = iocs if picked == "All" else iocs[iocs["type"] == picked]
        st.dataframe(shown, use_container_width=True, hide_index=True)
        st.download_button("⬇️ Download IOCs as CSV", shown.to_csv(index=False),
                            file_name="log_copilot_iocs.csv", mime="text/csv")

        st.markdown("#### Breakdown by type")
        type_counts = iocs.groupby("type").size().reset_index(name="count").sort_values("count", ascending=False)
        fig = px.bar(type_counts, x="type", y="count", color_discrete_sequence=["#8b5cf6"])
        fig.update_layout(template="plotly_dark", paper_bgcolor="#10162b", plot_bgcolor="#10162b", height=320)
        st.plotly_chart(fig, use_container_width=True)

# ---------------------------------------------------------------------------
# MITRE tab
# ---------------------------------------------------------------------------
with tab_mitre:
    coverage = (n_techniques / TOTAL_KNOWN_TECHNIQUES * 100) if TOTAL_KNOWN_TECHNIQUES else 0

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Techniques", n_techniques)
    m2.metric("Detections", f"{len(mitre_hits):,}")
    m3.metric("Coverage", f"{coverage:.1f}%")
    m4.metric("Tactics", tac_summary["tactic"].nunique() if not tac_summary.empty else 0)

    st.markdown("#### 🛡️ MITRE ATT&CK Coverage")
    st.caption(f"{n_techniques} of {TOTAL_KNOWN_TECHNIQUES} built-in detection rules fired on your logs "
               f"— {coverage:.1f}% coverage.")
    st.progress(min(coverage / 100, 1.0))
    st.caption("Coverage reflects Soc analyst dashboard's local rule set, not the full MITRE ATT&CK matrix.")

    st.markdown("#### 🎯 Tactics Distribution")
    if not tac_summary.empty:
        cols = st.columns(2)
        for i, (_, row) in enumerate(tac_summary.iterrows()):
            with cols[i % 2]:
                st.markdown(f"""
                <div class="lc-card"><b>{row['tactic']}</b> — {row['detections']} detections</div>
                """, unsafe_allow_html=True)
    else:
        st.caption("No tactics detected yet.")

    st.markdown("#### 📖 Detected Techniques")
    if tech_summary.empty:
        st.caption("No MITRE ATT&CK techniques matched this dataset.")
    else:
        for _, row in tech_summary.iterrows():
            sev_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}.get(row["severity"], "⚪")
            with st.expander(f"{sev_icon} **{row['technique_id']}** — {row['technique_name']}  ·  {row['detections']} detections"):
                st.write(f"**Tactic:** {row['tactic']}  |  **Severity:** {row['severity']}")
                st.write(row["description"])
                st.write("Tags: " + ", ".join(f"`{t}`" for t in row["tags"]))
                mitre_url = f"https://attack.mitre.org/techniques/{row['technique_id'].replace('.', '/')}/"
                st.markdown(f"[View on MITRE ATT&CK ↗]({mitre_url})")