from pathlib import Path
import textwrap, zipfile, json

root = Path("/mnt/data/soc_log_copilot_streamlit")
(root / "samples").mkdir(parents=True, exist_ok=True)

import base64
import csv
import hashlib
import io
import json
import math
import re
from collections import Counter
from datetime import datetime, timezone

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import plotly.express as px

# ============================================================
# SOC Log Copilot - 100% local/client-side Streamlit dashboard
# Supports: JSON, TXT, CSV, TSV, LOG
# Sources: Zeek, Sysmon, Windows Events, AWS CloudTrail
# ============================================================

st.set_page_config(
    page_title="Log Copilot | SOC Analyst Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ------------------------- Styling ---------------------------

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Space+Grotesk:wght@400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: "Space Grotesk", sans-serif;
}
code, pre, .mono {
    font-family: "JetBrains Mono", monospace !important;
}
.stApp {
    background:
      radial-gradient(circle at 15% 0%, rgba(91, 67, 190, .14), transparent 28%),
      radial-gradient(circle at 85% 5%, rgba(36, 95, 220, .10), transparent 25%),
      #020817;
    color: #eef3ff;
}
.block-container {
    padding-top: 1rem;
    padding-bottom: 2rem;
    max-width: 1500px;
}
header[data-testid="stHeader"] { background: rgba(2,8,23,.86); }
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #030b1f 0%, #020817 100%);
    border-right: 1px solid #122347;
}
section[data-testid="stSidebar"] * { color: #dbe6ff; }

.brand {
    display:flex; align-items:center; gap:14px;
    padding: 10px 0 20px 0;
}
.brand-icon {
    width:46px; height:46px; border-radius:14px;
    display:flex; align-items:center; justify-content:center;
    background: linear-gradient(135deg,#6448ff,#2b75ff);
    box-shadow: 0 0 30px rgba(92,70,255,.25);
    font-size:24px;
}
.brand-title { font-size:25px; font-weight:700; letter-spacing:-.7px; }
.brand-sub { color:#6798ff; font-family:"JetBrains Mono"; font-size:13px; }

.status-pill {
    border:1px solid #332478; color:#8da8ff;
    background:#0b0b2a; border-radius:999px; padding:7px 12px;
    font-family:"JetBrains Mono"; font-size:12px;
}
.card {
    background: linear-gradient(145deg, rgba(6,18,43,.96), rgba(2,10,28,.98));
    border:1px solid #102957;
    border-radius:16px; padding:18px;
    box-shadow: inset 0 1px 0 rgba(255,255,255,.02);
}
.metric-label { color:#7fa7ff; font-family:"JetBrains Mono"; font-size:13px; }
.metric-value { font-size:31px; font-weight:700; margin-top:3px; }
.metric-note { color:#6d83a9; font-size:12px; margin-top:3px; }
.section-title { font-size:20px; font-weight:700; margin-bottom:8px; }
.section-sub { color:#7090c9; font-family:"JetBrains Mono"; font-size:12px; }
.tag {
    display:inline-block; border:1px solid #173363; background:#07142d;
    color:#83a9ff; border-radius:999px; padding:4px 9px; margin:2px;
    font: 11px "JetBrains Mono";
}
.threat-critical { color:#ff6b70; }
.threat-high { color:#ff9f3f; }
.threat-medium { color:#ffd12a; }
.threat-low { color:#7d68ff; }
.small { font-size:12px; color:#7890b8; }
div[data-testid="stMetric"] {
    background: linear-gradient(145deg, #06132d, #030b1e);
    border:1px solid #102957; border-radius:15px; padding:12px 15px;
}
div[data-testid="stMetricLabel"] { color:#76a0f5 !important; }
div[data-testid="stMetricValue"] { color:#f4f7ff !important; }
.stTabs [data-baseweb="tab-list"] {
    gap: 8px; background:#06112b; border-radius:12px; padding:5px;
}
.stTabs [data-baseweb="tab"] {
    border-radius:9px; padding:8px 20px; color:#7fa7ff;
}
.stTabs [aria-selected="true"] {
    background:#0c1d40; color:#fff;
}
button[kind="primary"] {
    background:linear-gradient(135deg,#6548ff,#2b75ff);
    border:0;
}
</style>
""",
    unsafe_allow_html=True,
)

# ---------------------- Detection knowledge -----------------

MITRE = {
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1059.003": ("Windows Command Shell", "Execution"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1071.001": ("Web Protocols", "Command and Control"),
    "T1071.004": ("DNS", "Command and Control"),
    "T1046": ("Network Service Scanning", "Discovery"),
    "T1087": ("Account Discovery", "Discovery"),
    "T1087.002": ("Domain Account", "Discovery"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1055": ("Process Injection", "Privilege Escalation"),
    "T1548": ("Abuse Elevation Control Mechanism", "Privilege Escalation"),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    "T1562": ("Impair Defenses", "Defense Evasion"),
    "T1027": ("Obfuscated/Compressed Files and Information", "Defense Evasion"),
    "T1049": ("System Network Connections Discovery", "Discovery"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1016": ("System Network Configuration Discovery", "Discovery"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "Persistence"),
    "T1112": ("Modify Registry", "Defense Evasion"),
    "T1566": ("Phishing", "Initial Access"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1530": ("Data from Cloud Storage Object", "Collection"),
    "T1526": ("Cloud Service Dashboard", "Discovery"),
    "T1552": ("Unsecured Credentials", "Credential Access"),
    "T1555": ("Credentials from Password Stores", "Credential Access"),
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


# ------------------------- Helpers --------------------------

def flatten(obj, prefix=""):
    """Flatten nested JSON for easier rule matching."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                out.update(flatten(v, key))
            else:
                out[key] = v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                out.update(flatten(v, key))
            else:
                out[key] = v
    else:
        out[prefix] = obj
    return out


def text_of(row):
    return " ".join(
        str(v) for v in row.values()
        if v is not None and not (isinstance(v, float) and math.isnan(v))
    )


def first_value(row, names):
    lower = {str(k).lower(): v for k, v in row.items()}
    for n in names:
        if n.lower() in lower and str(lower[n.lower()]).strip():
            return lower[n.lower()]
    for k, v in lower.items():
        if any(n.lower() in k for n in names) and str(v).strip():
            return v
    return ""


def parse_uploaded_file(uploaded):
    name = uploaded.name.lower()
    raw = uploaded.getvalue()
    text = raw.decode("utf-8", errors="replace")
    records = []

    if name.endswith(".json"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # JSON Lines fallback
            for line in text.splitlines():
                if line.strip():
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        records.append({"message": line})
            data = None

        if data is not None:
            if isinstance(data, list):
                records = data
            elif isinstance(data, dict):
                # CloudTrail commonly wraps records in Records
                if isinstance(data.get("Records"), list):
                    records = data["Records"]
                elif isinstance(data.get("events"), list):
                    records = data["events"]
                else:
                    records = [data]

    elif name.endswith(".csv"):
        records = list(csv.DictReader(io.StringIO(text)))
    elif name.endswith(".tsv"):
        records = list(csv.DictReader(io.StringIO(text), delimiter="\t"))
    else:
        # Try JSONL first, then key=value, then plain text lines.
        for line in text.splitlines():
            if not line.strip():
                continue
            stripped = line.strip()
            try:
                value = json.loads(stripped)
                records.append(value if isinstance(value, dict) else {"message": value})
                continue
            except Exception:
                pass
            kv = dict(re.findall(r'([A-Za-z_][\w.-]*)=(?:"([^"]*)"|\'([^\']*)\'|(\S+))', stripped))
            if kv:
                normalized = {}
                for k, v in kv.items():
                    normalized[k] = next((x for x in v if x), "")
                records.append(normalized)
            else:
                records.append({"message": line})

    clean = []
    for i, rec in enumerate(records):
        if isinstance(rec, dict):
            flat = flatten(rec)
            flat["_row_id"] = i + 1
            flat["_raw"] = json.dumps(rec, ensure_ascii=False, default=str)
        else:
            flat = {"_row_id": i + 1, "message": str(rec), "_raw": str(rec)}
        clean.append(flat)

    return pd.DataFrame(clean), text


def detect_source(df, filename):
    fn = filename.lower()
    cols = " ".join(str(c).lower() for c in df.columns)
    sample = " ".join(df.head(min(25, len(df))).astype(str).fillna("").values.flatten()).lower()

    if "cloudtrail" in fn or "eventsource" in cols or "eventname" in cols and "useridentity" in sample:
        return "CloudTrail"
    if "sysmon" in fn or "eventid" in cols and ("image" in cols or "processguid" in cols):
        return "Sysmon"
    if "zeek" in fn or any(x in cols for x in ["uid", "id.orig_h", "id.resp_h", "query", "method", "host"]):
        return "Zeek"
    if "windows" in fn or "winlog" in cols or "provider" in cols:
        return "Windows Events"
    if any(x in cols for x in ["sourceip", "destinationip", "src_ip", "dst_ip"]):
        return "Network / Generic"
    return "Generic Security Log"


def parse_time(row):
    candidates = [
        "timestamp", "@timestamp", "event.created", "event.time", "time",
        "TimeCreated", "UtcTime", "EventTime", "ts", "date"
    ]
    value = first_value(row, candidates)
    if value == "":
        return pd.NaT
    try:
        ts = pd.to_datetime(value, utc=True, errors="coerce")
        return ts
    except Exception:
        return pd.NaT


def normalize_event(row, source):
    text = text_of(row)
    low = text.lower()
    event_id = str(first_value(row, ["eventid", "EventID", "event.code", "id", "type"]))
    process = str(first_value(row, ["image", "processname", "process", "process.executable", "exe"]))
    user = str(first_value(row, ["user", "username", "user.name", "subjectusername", "useridentity.arn"]))
    src_ip = str(first_value(row, ["id.orig_h", "src_ip", "sourceip", "source.ip", "clientip", "src"]))
    dst_ip = str(first_value(row, ["id.resp_h", "dst_ip", "destinationip", "destination.ip", "serverip", "dst"]))
    domain = str(first_value(row, ["query", "host", "hostname", "domain", "destinationhostname"]))
    method = str(first_value(row, ["method", "http_method", "requestmethod"]))

    return {
        "time": parse_time(row),
        "source": source,
        "event_id": event_id,
        "process": process,
        "user": user,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "domain": domain,
        "method": method,
        "message": text[:1500],
        "_raw": row.get("_raw", text),
    }


def severity_for(score):
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 45:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Info"


def add_finding(findings, rule_id, title, description, severity, technique, row_id, evidence):
    findings.append({
        "rule_id": rule_id,
        "title": title,
        "description": description,
        "severity": severity,
        "technique": technique,
        "row_id": row_id,
        "evidence": evidence[:500],
    })


def analyze_event(event, source):
    """Local, deterministic detection engine. No external API/network call."""
    text = event["message"]
    low = text.lower()
    findings = []

    # Authentication / brute force
    if any(x in low for x in [
        "logon failure", "login failed", "authentication failure",
        "failed password", "invalid user", "status=0xc000006d",
        "4625", "authenticationfailed"
    ]):
        add_finding(findings, "AUTH-001", "Authentication failure",
                    "A failed authentication event was identified. Repeated failures may indicate password guessing.",
                    "Medium", "T1110", event["row_id"], text)

    # PowerShell
    if "powershell" in low:
        sev = "High" if any(x in low for x in ["-enc", "encodedcommand", "downloadstring", "invoke-expression", "iex "]) else "Medium"
        tech = "T1059.001"
        add_finding(findings, "EXEC-PS", "PowerShell execution",
                    "PowerShell activity was observed in the event. Encoded or download-oriented commands receive higher severity.",
                    sev, tech, event["row_id"], text)

    # Command shell
    if re.search(r"(^|[\s\\/])(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|bash|sh)([\s.]|$)", low):
        add_finding(findings, "EXEC-001", "Command or scripting activity",
                    "A command interpreter process or command-shell indicator was found.",
                    "Medium", "T1059", event["row_id"], text)

    # Encoded/obfuscated content
    if "base64" in low or "encodedcommand" in low or re.search(r"[A-Za-z0-9+/]{80,}={0,2}", text):
        add_finding(findings, "DEF-002", "Possible encoded content",
                    "The event contains a long Base64-like or explicitly encoded command indicator.",
                    "High", "T1027", event["row_id"], text)

    # Network scanning / connection discovery
    if any(x in low for x in ["port scan", "portscan", "nmap", "masscan", "network scan", "scan detected"]):
        add_finding(findings, "NET-001", "Possible network scanning",
                    "The event contains indicators associated with network/service scanning.",
                    "High", "T1046", event["row_id"], text)

    # Zeek DNS / HTTP
    if source == "Zeek":
        if "dns" in low or "query" in low:
            if any(x in low for x in ["dyndns", "duckdns", ".top", ".xyz", "pastebin", "ngrok"]):
                add_finding(findings, "ZEEK-DNS-001", "Suspicious DNS indicator",
                            "DNS telemetry contains a domain pattern commonly worth analyst review.",
                            "Medium", "T1071.004", event["row_id"], text)
        if "http" in low or "method" in low:
            if any(x in low for x in ["powershell", "cmd.exe", "download", "user-agent: curl"]):
                add_finding(findings, "ZEEK-HTTP-001", "Suspicious HTTP activity",
                            "HTTP telemetry contains command/download-oriented indicators.",
                            "Medium", "T1071.001", event["row_id"], text)

    # Sysmon process creation / network
    if source == "Sysmon":
        if event["event_id"] in {"1", "Process Create"}:
            if any(x in low for x in ["powershell", "rundll32", "regsvr32", "mshta", "wscript", "cscript"]):
                add_finding(findings, "SYSMON-001", "Suspicious process creation",
                            "Sysmon process creation contains a commonly monitored execution utility.",
                            "High", "T1059", event["row_id"], text)
        if event["event_id"] in {"3", "Network connection"}:
            if event["dst_ip"] and event["dst_ip"] not in {"127.0.0.1", "::1"}:
                add_finding(findings, "SYSMON-003", "Process network connection",
                            "Sysmon recorded a network connection that can be correlated with process activity.",
                            "Low", "T1071", event["row_id"], text)

    # Windows events
    if source == "Windows Events":
        if event["event_id"] == "4688":
            add_finding(findings, "WIN-4688", "Windows process creation",
                        "Windows Security Event 4688 indicates a new process was created.",
                        "Low", "T1059", event["row_id"], text)
        if event["event_id"] in {"4624", "4625"}:
            if event["event_id"] == "4625":
                add_finding(findings, "WIN-4625", "Windows failed logon",
                            "Windows Security Event 4625 indicates a failed logon.",
                            "Medium", "T1110", event["row_id"], text)
        if any(x in low for x in ["audit policy changed", "security log cleared", "event id 1102", "1102"]):
            add_finding(findings, "WIN-1102", "Security log clearing indicator",
                        "The event contains an indicator associated with Windows Security log clearing.",
                        "Critical", "T1562.001", event["row_id"], text)

    # CloudTrail
    if source == "CloudTrail":
        if any(x in low for x in [
            "disabletrail", "stoplogging", "deleteaudit", "deletebucket",
            "putbucketpolicy", "createaccesskey", "updateassumeablerolepolicy"
        ]):
            add_finding(findings, "AWS-001", "Sensitive CloudTrail/IAM action",
                        "CloudTrail contains an action that can materially affect logging, access, or cloud security controls.",
                        "High", "T1562", event["row_id"], text)
        if any(x in low for x in ["consolelogin", "signin", "unauthorized", "accessdenied"]):
            add_finding(findings, "AWS-AUTH-001", "Cloud authentication/access event",
                        "CloudTrail contains authentication or authorization activity for analyst review.",
                        "Medium", "T1078", event["row_id"], text)
        if any(x in low for x in ["getobject", "listbucket", "download"]):
            add_finding(findings, "AWS-DATA-001", "Cloud data access",
                        "CloudTrail contains object or bucket access activity.",
                        "Low", "T1530", event["row_id"], text)

    # Credential access
    if any(x in low for x in ["sekurlsa", "mimikatz", "lsass", "credential dumping", "keychain", "password store"]):
        add_finding(findings, "CRED-001", "Credential-access indicator",
                    "The event contains a credential access or credential-dumping indicator.",
                    "Critical", "T1003", event["row_id"], text)

    # Persistence / registry
    if any(x in low for x in ["currentversion\\run", "runonce", "startup folder", "registry run key"]):
        add_finding(findings, "PERSIST-001", "Possible registry persistence",
                    "The event contains a startup/Run key persistence indicator.",
                    "High", "T1547.001", event["row_id"], text)

    # Defense evasion
    if any(x in low for x in ["disable defender", "set-mppreference", "disable firewall", "tamper protection", "security tool disabled"]):
        add_finding(findings, "DEF-001", "Possible security-control tampering",
                    "The event suggests an attempt to weaken or disable a security control.",
                    "Critical", "T1562.001", event["row_id"], text)

    # Discovery
    if any(x in low for x in ["whoami", "ipconfig", "systeminfo", "tasklist", "netstat", "nltest", "net user"]):
        tech = "T1082" if any(x in low for x in ["systeminfo", "hostname"]) else "T1049"
        add_finding(findings, "DISC-001", "Discovery command",
                    "A command associated with host, process, account, or network discovery was observed.",
                    "Low", tech, event["row_id"], text)

    # Score from findings
    if not findings:
        score = 0
    else:
        weights = {"Critical": 100, "High": 78, "Medium": 52, "Low": 25}
        score = max(weights.get(f["severity"], 0) for f in findings)

    return findings, score


def extract_iocs(df_events):
    patterns = {
        "IPv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        "Domain": r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|co|info|biz|xyz|top|dev|cloud|me|us|uk|ca|de|in|tech)\b",
        "URL": r"https?://[^\s\"'<>]+",
        "SHA256": r"\b[a-fA-F0-9]{64}\b",
        "SHA1": r"\b[a-fA-F0-9]{40}\b",
        "MD5": r"\b[a-fA-F0-9]{32}\b",
        "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    }
    found = []
    for _, row in df_events.iterrows():
        text = str(row.get("message", ""))
        for kind, pattern in patterns.items():
            for value in re.findall(pattern, text):
                found.append({
                    "type": kind,
                    "value": value.rstrip(".,);]"),
                    "row_id": int(row["row_id"]),
                    "source": row["source"],
                    "context": text[:220],
                })
    if not found:
        return pd.DataFrame(columns=["type", "value", "row_id", "source", "context"])
    out = pd.DataFrame(found).drop_duplicates(subset=["type", "value", "row_id"])
    return out


def build_summary(df, findings):
    total = len(df)
    alerts = len(findings)
    high = sum(x["severity"] in {"Critical", "High"} for x in findings)
    techniques = len(set(x["technique"] for x in findings))
    anomaly_rate = (alerts / total * 100) if total else 0
    return total, alerts, high, techniques, anomaly_rate


def render_metric(label, value, note=""):
    st.markdown(
        f"""<div class="card">
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
        <div class="metric-note">{note}</div>
        </div>""",
        unsafe_allow_html=True,
    )


# ----------------------- Sidebar ----------------------------

with st.sidebar:
    st.markdown(
        """
        <div class="brand">
          <div class="brand-icon">🛡️</div>
          <div>
            <div class="brand-title">Log Copilot</div>
            <div class="brand-sub">SOC Analyst Dashboard</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown('<span class="status-pill">⚡ 100% LOCAL / NO CLOUD API</span>', unsafe_allow_html=True)
    st.divider()
    st.markdown("### Upload security logs")
    uploaded = st.file_uploader(
        "JSON, TXT, CSV, TSV or LOG",
        type=["json", "txt", "csv", "tsv", "log"],
        accept_multiple_files=True,
        help="Files are parsed and analyzed by this Streamlit application. No external AI/API is required.",
    )
    auto_source = st.checkbox("Auto-detect log source", True)
    source_override = st.selectbox(
        "Source override",
        ["Auto", "Zeek", "Sysmon", "Windows Events", "CloudTrail", "Generic Security Log"],
        index=0,
    )
    max_rows = st.number_input("Maximum rows per file", min_value=100, max_value=200000, value=50000, step=1000)
    st.divider()
    st.markdown("### Detection modules")
    st.checkbox("IOC extraction", True, disabled=True)
    st.checkbox("MITRE ATT&CK mapping", True, disabled=True)
    st.checkbox("Local anomaly scoring", True, disabled=True)
    st.checkbox("Source-aware rules", True, disabled=True)
    st.divider()
    st.caption("Designed for local SOC analysis and coursework/prototyping. Validate detections before operational use.")


# ----------------------- Main header ------------------------

st.markdown(
    """
    <div style="display:flex;justify-content:space-between;align-items:center;margin:0 0 18px 0">
      <div>
        <div style="font-size:28px;font-weight:700">Log Copilot</div>
        <div style="color:#6594f7;font-family:'JetBrains Mono';font-size:13px">100% Client-Side AI-Powered Security Log Analysis</div>
      </div>
      <div class="status-pill">◉ LOCAL ANALYSIS • PRIVATE BY DEFAULT</div>
    </div>
    """,
    unsafe_allow_html=True,
)

if not uploaded:
    st.markdown(
        """
        <div class="card" style="padding:30px">
          <div class="section-title">Upload security telemetry to begin</div>
          <div class="section-sub">Supported sources</div>
          <div style="margin-top:12px">
            <span class="tag">Zeek • DNS / HTTP / Network</span>
            <span class="tag">Sysmon • Windows Endpoint</span>
            <span class="tag">Windows Events</span>
            <span class="tag">AWS CloudTrail</span>
          </div>
          <p class="small" style="margin-top:18px">
          Upload .json, .txt, .csv, .tsv or .log files from the sidebar.
          The app normalizes records, extracts IOCs, scores suspicious events,
          and maps detections to MITRE ATT&CK techniques.
          </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()


# --------------------- Parse all uploads --------------------

all_frames = []
file_info = []

for file in uploaded:
    try:
        frame, raw_text = parse_uploaded_file(file)
        if len(frame) > max_rows:
            frame = frame.head(max_rows).copy()
        if len(frame) == 0:
            continue
        source = (
            source_override
            if source_override != "Auto"
            else detect_source(frame, file.name)
        )
        frame["source"] = source
        frame["filename"] = file.name
        frame["row_id"] = range(1, len(frame) + 1)
        all_frames.append(frame)
        file_info.append((file.name, source, len(frame)))
    except Exception as exc:
        st.error(f"Could not parse {file.name}: {exc}")

if not all_frames:
    st.error("No parseable records were found in the uploaded files.")
    st.stop()

df_raw = pd.concat(all_frames, ignore_index=True)

events = []
for _, row in df_raw.iterrows():
    event = normalize_event(row.to_dict(), row["source"])
    event["row_id"] = int(row["row_id"])
    event["filename"] = row["filename"]
    events.append(event)

df_events = pd.DataFrame(events)
if "time" not in df_events:
    df_events["time"] = pd.NaT

# Deterministic local analysis
findings = []
scores = []
for _, event in df_events.iterrows():
    event_findings, score = analyze_event(event.to_dict(), event["source"])
    findings.extend(event_findings)
    scores.append(score)

df_events["anomaly_score"] = scores
df_events["severity"] = [severity_for(x) for x in scores]
df_events["anomaly"] = df_events["anomaly_score"] >= 45

iocs = extract_iocs(df_events)

# Summary
total, alert_count, high_count, technique_count, anomaly_rate = build_summary(df_events, findings)

# ---------------------- Top metrics -------------------------

m1, m2, m3, m4 = st.columns(4)
with m1:
    render_metric("TOTAL LOGS", f"{total:,}", "parsed records")
with m2:
    render_metric("ANOMALIES", f"{int(df_events['anomaly'].sum()):,}", f"{anomaly_rate:.1f}% anomaly rate")
with m3:
    render_metric("IOCs FOUND", f"{len(iocs):,}", "unique observable matches")
with m4:
    render_metric("MITRE TECHNIQUES", f"{technique_count:,}", "mapped from detections")

st.write("")

tab_analysis, tab_iocs, tab_mitre = st.tabs(["⚡ Analysis", "⌕ IOCs", "◎ MITRE ATT&CK"])

# ========================= ANALYSIS =========================

with tab_analysis:
    st.markdown('<div class="section-title">Analysis Summary</div>', unsafe_allow_html=True)
    date_min = df_events["time"].min()
    date_max = df_events["time"].max()
    if pd.isna(date_min):
        period = "Timestamp not available"
    else:
        period = f"{date_min.strftime('%Y-%m-%d %H:%M UTC')} → {date_max.strftime('%Y-%m-%d %H:%M UTC')}"

    st.markdown(
        f"""<div class="card">
        <div style="font-family:'JetBrains Mono';color:#6798ff">
        Analyzed <b>{total:,}</b> log entries from <b>{len(file_info)}</b> file(s).
        Detected <b>{alert_count:,}</b> rule-based findings and <b>{int(df_events['anomaly'].sum()):,}</b>
        medium-or-higher anomaly events. Extracted <b>{len(iocs):,}</b> IOCs and mapped
        detections to <b>{technique_count:,}</b> MITRE ATT&CK techniques.
        </div>
        <div class="small" style="margin-top:10px">◷ Analysis period: {period}</div>
        </div>""",
        unsafe_allow_html=True,
    )

    st.write("")
    st.markdown("### Source Coverage")
    source_counts = df_events["source"].value_counts().reset_index()
    source_counts.columns = ["Source", "Events"]
    st.dataframe(source_counts, use_container_width=True, hide_index=True)

    c1, c2 = st.columns(2)

    with c1:
        st.markdown("### Anomaly Timeline")
        timeline = df_events[df_events["anomaly"]].copy()
        if len(timeline) and timeline["time"].notna().any():
            timeline["hour"] = timeline["time"].dt.floor("h")
            counts = timeline.groupby("hour").size().reset_index(name="anomalies")
            fig = px.line(counts, x="hour", y="anomalies", markers=True, template="plotly_dark")
            fig.update_layout(height=350, margin=dict(l=10,r=10,t=10,b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            fig.update_traces(line=dict(width=3), marker=dict(size=7))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No medium-or-higher anomalies with usable timestamps were detected.")

    with c2:
        st.markdown("### Event / Source Types")
        counts = df_events["source"].value_counts().reset_index()
        counts.columns = ["Type", "Events"]
        fig = px.bar(counts, x="Type", y="Events", template="plotly_dark")
        fig.update_layout(height=350, margin=dict(l=10,r=10,t=10,b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        fig.update_traces(marker_line_width=0)
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Threat Level Distribution")
    if findings:
        sev_counts = pd.Series([x["severity"] for x in findings]).value_counts()
        sev_counts = sev_counts.reindex(SEVERITY_ORDER, fill_value=0).reset_index()
        sev_counts.columns = ["Severity", "Count"]
    else:
        sev_counts = pd.DataFrame({"Severity": SEVERITY_ORDER, "Count": [0]*len(SEVERITY_ORDER)})

    c1, c2 = st.columns([1, 1.8])
    with c1:
        fig = px.pie(sev_counts[sev_counts["Count"] > 0], names="Severity", values="Count", hole=.45, template="plotly_dark")
        fig.update_layout(height=320, margin=dict(l=0,r=0,t=0,b=0), paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)
    with c2:
        if findings:
            display_findings = pd.DataFrame(findings)[
                ["severity", "title", "technique", "row_id", "evidence"]
            ].sort_values("severity", key=lambda s: s.map({x:i for i,x in enumerate(SEVERITY_ORDER)}))
            st.dataframe(display_findings, use_container_width=True, hide_index=True, height=320)
        else:
            st.success("No detection rules fired on the uploaded telemetry.")

    st.markdown("### Event Explorer")
    min_score = st.slider("Minimum local anomaly score", 0, 100, 0)
    explorer = df_events[df_events["anomaly_score"] >= min_score].copy()
    explorer = explorer[["row_id", "source", "event_id", "severity", "anomaly_score", "user", "src_ip", "dst_ip", "domain", "process", "message"]]
    st.dataframe(explorer.head(5000), use_container_width=True, hide_index=True, height=420)


# =========================== IOCS ===========================

with tab_iocs:
    st.markdown("### IOC Intelligence")
    st.markdown(
        '<div class="section-sub">LOCAL EXTRACTION • IPs • DOMAINS • URLs • HASHES • EMAILS</div>',
        unsafe_allow_html=True,
    )
    st.write("")

    a, b, c, d = st.columns(4)
    for col, kind in zip([a,b,c,d], ["IPv4", "Domain", "URL", "SHA256"]):
        n = int((iocs["type"] == kind).sum()) if len(iocs) else 0
        with col:
            render_metric(kind.upper(), f"{n:,}", "matches")

    if len(iocs):
        st.write("")
        types = ["All"] + sorted(iocs["type"].unique().tolist())
        selected = st.selectbox("IOC type", types)
        view = iocs if selected == "All" else iocs[iocs["type"] == selected]
        st.dataframe(view, use_container_width=True, hide_index=True, height=500)

        # IOC frequency
        top = view["value"].value_counts().head(15).reset_index()
        top.columns = ["IOC", "Occurrences"]
        if len(top):
            fig = px.bar(top, x="Occurrences", y="IOC", orientation="h", template="plotly_dark")
            fig.update_layout(height=400, margin=dict(l=10,r=10,t=10,b=10), paper_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No IOCs were extracted from the uploaded logs.")


# =========================== MITRE ==========================

with tab_mitre:
    st.markdown("### MITRE ATT&CK Mapping")
    st.markdown(
        '<div class="section-sub">DETECTION → TECHNIQUE → TACTIC • SOURCE-AWARE MAPPING</div>',
        unsafe_allow_html=True,
    )

    tech_counts = Counter(x["technique"] for x in findings)
    techniques = []
    for tid, count in tech_counts.items():
        name, tactic = MITRE.get(tid, ("Technique " + tid, "Uncategorized"))
        techniques.append({
            "Technique": tid,
            "Name": name,
            "Tactic": tactic,
            "Detections": count,
        })

    tech_df = pd.DataFrame(techniques)
    if len(tech_df):
        # For this prototype, coverage is against the technique IDs defined in MITRE above.
        coverage = min(100.0, len(tech_df) / max(1, len(MITRE)) * 100)
    else:
        coverage = 0.0

    a,b,c,d = st.columns(4)
    with a: render_metric("TECHNIQUES", len(tech_df), "unique mapped IDs")
    with b: render_metric("DETECTIONS", len(findings), "mapped findings")
    with c: render_metric("COVERAGE", f"{coverage:.1f}%", "prototype rule coverage")
    with d:
        tactics = tech_df["Tactic"].nunique() if len(tech_df) else 0
        render_metric("TACTICS", tactics, "represented in findings")

    st.write("")
    st.markdown(
        f"""<div class="card">
        <div class="section-title">MITRE ATT&CK Coverage</div>
        <div style="display:flex;justify-content:space-between">
          <span class="section-sub">{len(tech_df)} of {len(MITRE)} configured techniques detected</span>
          <span>{coverage:.1f}%</span>
        </div>
        <div style="height:9px;background:#06132e;border-radius:10px;margin-top:12px">
          <div style="width:{coverage}%;height:9px;background:linear-gradient(90deg,#386fff,#7a4dff);border-radius:10px"></div>
        </div>
        <div class="small" style="margin-top:10px">Coverage here means coverage of the techniques represented by this application's local detection catalog, not enterprise-wide ATT&CK coverage.</div>
        </div>""",
        unsafe_allow_html=True,
    )

    st.write("")
    if len(tech_df):
        c1, c2 = st.columns(2)
        with c1:
            tactic_counts = tech_df.groupby("Tactic")["Detections"].sum().reset_index()
            fig = px.bar(tactic_counts, x="Tactic", y="Detections", template="plotly_dark")
            fig.update_layout(height=330, margin=dict(l=10,r=10,t=10,b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)
        with c2:
            fig = px.bar(tech_df.sort_values("Detections"), x="Detections", y="Name", orientation="h", hover_data=["Technique","Tactic"], template="plotly_dark")
            fig.update_layout(height=330, margin=dict(l=10,r=10,t=10,b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)

        st.markdown("### Detected Techniques")
        for _, r in tech_df.sort_values("Detections", ascending=False).iterrows():
            st.markdown(
                f"""<div class="card" style="margin-bottom:10px">
                <div style="display:flex;justify-content:space-between;gap:20px">
                  <div>
                    <span class="tag">{r['Technique']}</span>
                    <b style="font-size:18px">{r['Name']}</b>
                    <span class="tag">{r['Tactic']}</span>
                    <div class="small" style="margin-top:8px">Mapped from {int(r['Detections'])} detection(s) in the uploaded telemetry.</div>
                  </div>
                  <div style="font-size:28px;font-weight:700">{int(r['Detections'])}</div>
                </div>
                </div>""",
                unsafe_allow_html=True,
            )
    else:
        st.info("No MITRE ATT&CK mappings were triggered by the current telemetry.")

    with st.expander("Configured local MITRE catalog"):
        catalog = pd.DataFrame(
            [{"Technique": k, "Name": v[0], "Tactic": v[1]} for k, v in MITRE.items()]
        )
        st.dataframe(catalog, use_container_width=True, hide_index=True)


# ------------------------ Footer ----------------------------

st.divider()
f1, f2, f3 = st.columns(3)
with f1:
    st.markdown("**🔒 Privacy First**")
    st.caption("Uploaded telemetry is processed by this Streamlit application. No external AI provider is called by the detection engine.")
with f2:
    st.markdown("**◎ MITRE ATT&CK**")
    st.caption("Mappings are local rule-based associations for analyst triage and coursework.")
with f3:
    st.markdown("**⚡ Log Copilot**")
    st.caption("Zeek • Sysmon • Windows Events • AWS CloudTrail")

st.caption("Prototype notice: detections are heuristics and should be validated against your environment before operational use.")


