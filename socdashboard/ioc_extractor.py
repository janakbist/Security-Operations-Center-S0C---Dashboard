"""IOC extraction - ully local.regex-based, f No data leaves the machine."""
import re
from collections import defaultdict

import pandas as pd

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
URL_RE = re.compile(r"\bhttps?://[^\s\"'>]+")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")

PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.")


def _is_private_ip(ip: str) -> bool:
    if ip.startswith(PRIVATE_PREFIXES):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (IndexError, ValueError):
            return False
    return False


def extract_iocs(df: pd.DataFrame) -> pd.DataFrame:
    """Scan normalized fields for indicators of compromise (IPs, domains, URLs, hashes, emails)."""
    found = defaultdict(lambda: {"type": None, "count": 0, "first_seen": pd.NaT, "last_seen": pd.NaT})

    text_cols = ["message", "command_line", "file_path", "dns_query", "http_host", "http_uri", "raw"]
    ip_cols = ["src_ip", "dst_ip"]

    def register(value, ioc_type, ts):
        if not value:
            return
        rec = found[(ioc_type, value)]
        rec["type"] = ioc_type
        rec["count"] += 1
        if pd.notna(ts):
            if pd.isna(rec["first_seen"]) or ts < rec["first_seen"]:
                rec["first_seen"] = ts
            if pd.isna(rec["last_seen"]) or ts > rec["last_seen"]:
                rec["last_seen"] = ts

    for _, row in df.iterrows():
        ts = row.get("timestamp")

        for col in ip_cols:
            val = row.get(col)
            if val and IP_RE.fullmatch(str(val).strip()):
                ip = str(val).strip()
                register(ip, "Internal IP" if _is_private_ip(ip) else "External IP", ts)

        blob = " ".join(str(row.get(c)) for c in text_cols if row.get(c))
        if not blob:
            continue
        for ip in IP_RE.findall(blob):
            register(ip, "Internal IP" if _is_private_ip(ip) else "External IP", ts)
        for url in URL_RE.findall(blob):
            register(url, "URL", ts)
        for h in SHA256_RE.findall(blob):
            register(h, "SHA256", ts)
        for h in SHA1_RE.findall(blob):
            register(h, "SHA1", ts)
        for h in MD5_RE.findall(blob):
            register(h, "MD5", ts)
        for email in EMAIL_RE.findall(blob):
            register(email, "Email", ts)

        if row.get("dns_query"):
            q = str(row["dns_query"]).strip(". ")
            if DOMAIN_RE.match(q):
                register(q, "Domain", ts)
        if row.get("http_host") and DOMAIN_RE.match(str(row["http_host"])):
            register(str(row["http_host"]), "Domain", ts)

    if not found:
        return pd.DataFrame(columns=["value", "type", "count", "first_seen", "last_seen"])

    out = pd.DataFrame([
        {"value": k[1], "type": v["type"], "count": v["count"],
         "first_seen": v["first_seen"], "last_seen": v["last_seen"]}
        for k, v in found.items()
    ])
    return out.sort_values("count", ascending=False).reset_index(drop=True)