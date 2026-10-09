"""
MITRE ATT&CK technique mapping - local rule-based detection engine.
Rules run against normalized log rows. No external calls; technique
knowledge (ID, name, tactic, description) is bundled locally.
"""
import re

import pandas as pd


def _s(v):
    return "" if v is None else str(v)


def _low(v):
    return _s(v).lower()


RULES = [
    dict(id="T1059.001", name="PowerShell", tactic="Execution", severity="High",
         desc="Adversaries may abuse PowerShell for execution of malicious commands and scripts.",
         tags=["powershell", "script execution"],
         match=lambda r: "powershell" in _low(r.get("command_line")) or "powershell" in _low(r.get("process"))),

    dict(id="T1059.003", name="Windows Command Shell", tactic="Execution", severity="Medium",
         desc="Adversaries may abuse the Windows command shell (cmd.exe) for execution.",
         tags=["cmd.exe", "shell"],
         match=lambda r: _low(r.get("process")).endswith("cmd.exe") and bool(r.get("command_line"))),

    dict(id="T1053.005", name="Scheduled Task", tactic="Persistence", severity="High",
         desc="Adversaries may abuse the Windows Task Scheduler to execute code for persistence or escalation.",
         tags=["schtasks", "scheduled task"],
         match=lambda r: "schtasks" in _low(r.get("command_line"))),

    dict(id="T1547.001", name="Registry Run Keys / Startup Folder", tactic="Persistence", severity="High",
         desc="Adversaries may add a program to a startup folder or Registry Run key to persist across reboots.",
         tags=["registry", "run key", "autostart"],
         match=lambda r: _s(r.get("event_id")) in ("12", "13") and "\\run\\" in _low(r.get("file_path"))),

    dict(id="T1562.001", name="Disable or Modify Tools", tactic="Defense Evasion", severity="Critical",
         desc="Adversaries may disable security tools (e.g. AV/EDR) to avoid detection.",
         tags=["disable defender", "amsi bypass", "stop av"],
         match=lambda r: any(t in _low(r.get("command_line")) for t in
                              ["disablerealtimemonitoring", "set-mppreference", "amsienable", "stop-service windefend"])),

    dict(id="T1070.001", name="Clear Windows Event Logs", tactic="Defense Evasion", severity="Critical",
         desc="Adversaries may clear Windows event logs to hide evidence of their activity.",
         tags=["wevtutil", "clear log"],
         match=lambda r: "wevtutil cl" in _low(r.get("command_line")) or "clear-eventlog" in _low(r.get("command_line"))),

    dict(id="T1110", name="Brute Force", tactic="Credential Access", severity="High",
         desc="Adversaries may attempt repeated logons to guess or crack valid credentials.",
         tags=["failed logon", "4625"],
         match=lambda r: _s(r.get("event_id")) == "4625" or r.get("status") == "failure"),

    dict(id="T1021.001", name="Remote Desktop Protocol", tactic="Lateral Movement", severity="Medium",
         desc="Adversaries may use RDP to log into and move laterally between systems.",
         tags=["rdp", "logon type 10"],
         match=lambda r: _s(r.get("event_id")) == "4624" and "10" in _s(r.get("message"))),

    dict(id="T1082", name="System Information Discovery", tactic="Discovery", severity="Low",
         desc="Adversaries may enumerate detailed OS and hardware information about a system.",
         tags=["systeminfo"],
         match=lambda r: "systeminfo" in _low(r.get("command_line"))),

    dict(id="T1087", name="Account Discovery", tactic="Discovery", severity="Low",
         desc="Adversaries may enumerate local or domain accounts and groups.",
         tags=["net user", "net group"],
         match=lambda r: re.search(r"\bnet\s+(user|group)\b", _low(r.get("command_line"))) is not None),

    dict(id="T1046", name="Network Service Discovery", tactic="Discovery", severity="Medium",
         desc="Adversaries may probe for services running on remote hosts, e.g. via port scanning.",
         tags=["port scan", "nmap"],
         match=lambda r: "nmap" in _low(r.get("command_line")) or "nmap" in _low(r.get("message"))),

    dict(id="T1071.001", name="Web Protocols (C2)", tactic="Command and Control", severity="Medium",
         desc="Adversaries may communicate over HTTP/HTTPS to blend in with normal web traffic.",
         tags=["http", "web traffic", "c2 communication"],
         match=lambda r: r.get("log_type") == "zeek" and r.get("action") == "http"),

    dict(id="T1071.004", name="DNS (C2 / Tunneling)", tactic="Command and Control", severity="Medium",
         desc="Adversaries may use DNS for command and control, including possible DNS tunneling.",
         tags=["dns", "dns tunneling", "c2 communication"],
         match=lambda r: r.get("log_type") == "zeek" and r.get("action") == "dns"),

    dict(id="T1204.002", name="Malicious File Execution", tactic="Execution", severity="High",
         desc="A user may be tricked into executing a malicious file, e.g. launched from Downloads/Temp.",
         tags=["user execution", "downloads", "temp"],
         match=lambda r: _s(r.get("event_id")) == "1" and any(
             p in _low(r.get("process")) for p in ["\\downloads\\", "\\temp\\", "\\appdata\\"])),

    dict(id="T1098", name="Account Manipulation", tactic="Persistence", severity="High",
         desc="Adversaries may add credentials or permissions to cloud accounts to maintain access.",
         tags=["iam", "createaccesskey", "attachuserpolicy"],
         match=lambda r: r.get("log_type") == "cloudtrail" and _s(r.get("action")) in
                         ("CreateAccessKey", "AttachUserPolicy", "CreateLoginProfile", "AddUserToGroup")),

    dict(id="T1078", name="Valid Accounts (Cloud)", tactic="Initial Access", severity="Medium",
         desc="Adversaries may use valid cloud credentials to log in, sometimes from an unusual location.",
         tags=["consolelogin", "valid accounts"],
         match=lambda r: r.get("log_type") == "cloudtrail" and _s(r.get("action")) == "ConsoleLogin"),

    dict(id="T1530", name="Data from Cloud Storage", tactic="Collection", severity="Medium",
         desc="Adversaries may access data from cloud storage such as S3 buckets.",
         tags=["s3", "getobject"],
         match=lambda r: r.get("log_type") == "cloudtrail" and _s(r.get("action")) in ("GetObject", "ListBucket")),

    dict(id="T1485", name="Data Destruction", tactic="Impact", severity="Critical",
         desc="Adversaries may delete data or resources to interrupt availability.",
         tags=["deleteobject", "deletebucket", "delete"],
         match=lambda r: r.get("log_type") == "cloudtrail" and "delete" in _low(r.get("action"))),
]

TOTAL_KNOWN_TECHNIQUES = len(RULES)
_DESC_MAP = {r["id"]: r["desc"] for r in RULES}
_TAGS_MAP = {r["id"]: r["tags"] for r in RULES}


def map_techniques(df: pd.DataFrame) -> pd.DataFrame:
    """Return one row per (rule, matched event) - the events that tripped a MITRE rule."""
    if df.empty:
        return pd.DataFrame(columns=["technique_id", "technique_name", "tactic", "severity",
                                      "description", "tags", "timestamp", "message"])
    hits = []
    for rule in RULES:
        try:
            mask = df.apply(rule["match"], axis=1)
        except Exception:
            continue
        matched = df[mask]
        if matched.empty:
            continue
        for _, row in matched.iterrows():
            hits.append({
                "technique_id": rule["id"], "technique_name": rule["name"], "tactic": rule["tactic"],
                "severity": rule["severity"], "description": rule["desc"], "tags": rule["tags"],
                "timestamp": row.get("timestamp"), "message": row.get("message"),
            })
    if not hits:
        return pd.DataFrame(columns=["technique_id", "technique_name", "tactic", "severity",
                                      "description", "tags", "timestamp", "message"])
    return pd.DataFrame(hits)


def technique_summary(hits_df: pd.DataFrame) -> pd.DataFrame:
    if hits_df.empty:
        return pd.DataFrame(columns=["technique_id", "technique_name", "tactic", "severity",
                                      "description", "tags", "detections"])
    grouped = hits_df.groupby(["technique_id", "technique_name", "tactic", "severity"]).agg(
        detections=("technique_id", "count"),
    ).reset_index()
    grouped["description"] = grouped["technique_id"].map(_DESC_MAP)
    grouped["tags"] = grouped["technique_id"].map(_TAGS_MAP)
    return grouped.sort_values("detections", ascending=False).reset_index(drop=True)


def tactic_summary(hits_df: pd.DataFrame) -> pd.DataFrame:
    if hits_df.empty:
        return pd.DataFrame(columns=["tactic", "detections"])
    return (hits_df.groupby("tactic").size().reset_index(name="detections")
            .sort_values("detections", ascending=False).reset_index(drop=True))