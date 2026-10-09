"""
Local statistical anomaly detection - no external calls.
Flags volume spikes, brute-force bursts, rare/suspicious process
executions, and simple periodic beaconing.
"""
import pandas as pd


def detect_anomalies(df: pd.DataFrame, sensitivity: float = 2.5) -> pd.DataFrame:
    anomalies = []
    ts = df["timestamp"].dropna()

    # 1) Volume spikes per hour (z-score over hourly event counts)
    if not ts.empty:
        hourly = ts.dt.floor("h").value_counts().sort_index()
        if len(hourly) >= 3:
            mean, std = hourly.mean(), hourly.std()
            if std and std > 0:
                for hour, count in hourly.items():
                    z = (count - mean) / std
                    if z >= sensitivity:
                        anomalies.append({
                            "timestamp": hour, "type": "Volume Spike",
                            "severity": "High" if z >= sensitivity * 1.5 else "Medium",
                            "description": f"Unusual spike of {int(count)} events (z-score {z:.1f}) around {hour}.",
                        })

    # 2) Repeated failed logons (brute-force burst)
    if "status" in df.columns:
        failed = df[df["status"] == "failure"]
        if not failed.empty and "user" in failed.columns:
            for user, grp in failed.groupby("user"):
                if user and len(grp) >= 5:
                    anomalies.append({
                        "timestamp": grp["timestamp"].max(), "type": "Brute Force Attempt",
                        "severity": "Critical",
                        "description": f"{len(grp)} failed logon attempts for user '{user}'.",
                    })

    # 3) Rare / one-off execution of commonly abused binaries (LOLBins)
    if "process" in df.columns:
        procs = df["process"].dropna()
        if not procs.empty:
            counts = procs.value_counts()
            rare = counts[counts == 1]
            suspicious_names = ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil"]
            for proc in rare.index:
                if any(s in str(proc).lower() for s in suspicious_names):
                    row = df[df["process"] == proc].iloc[0]
                    anomalies.append({
                        "timestamp": row.get("timestamp"), "type": "Rare Process Execution",
                        "severity": "Medium",
                        "description": f"One-off execution of a commonly abused binary: {proc}",
                    })

    # 4) Simple beaconing: regular-interval connections from src -> dst
    if {"src_ip", "dst_ip"} <= set(df.columns):
        conns = df.dropna(subset=["src_ip", "dst_ip", "timestamp"])
        if not conns.empty:
            for (src, dst), grp in conns.groupby(["src_ip", "dst_ip"]):
                if len(grp) >= 6:
                    times = grp["timestamp"].sort_values()
                    deltas = times.diff().dropna().dt.total_seconds()
                    if len(deltas) >= 5 and deltas.mean() > 0:
                        cv = deltas.std() / deltas.mean()
                        if cv < 0.15:
                            anomalies.append({
                                "timestamp": times.max(), "type": "Possible Beaconing",
                                "severity": "High",
                                "description": f"{src} -> {dst}: {len(grp)} connections at a regular "
                                                f"~{deltas.mean():.0f}s interval.",
                            })

    if not anomalies:
        return pd.DataFrame(columns=["timestamp", "type", "severity", "description"])
    out = pd.DataFrame(anomalies)
    return out.sort_values("timestamp", ascending=False).reset_index(drop=True)


def threat_level_distribution(mitre_hits: pd.DataFrame, anomalies: pd.DataFrame) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for frame in (mitre_hits, anomalies):
        if frame is not None and not frame.empty and "severity" in frame.columns:
            for sev, n in frame["severity"].value_counts().items():
                if sev in counts:
                    counts[sev] += int(n)
    return counts