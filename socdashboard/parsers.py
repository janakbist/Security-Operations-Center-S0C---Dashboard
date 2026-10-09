"""
Log Copilot - Parsers
Detects and normalizes security log formats: Zeek, Sysmon, Windows Events,
CloudTrail, and generic logs. Supports .json, .txt, .csv, .tsv, .log files.
Everything here runs in-memory/locally - no data is sent anywhere.
"""
import csv
import io
import json
import re
from datetime import datetime, timezone

import pandas as pd

# ---------------------------------------------------------------------------
# Raw ingestion
# ---------------------------------------------------------------------------

def load_raw_records(file_bytes: bytes, filename: str):
    """Read an uploaded file's bytes and return (list_of_raw_record_dicts, container_format)."""
    text = file_bytes.decode("utf-8", errors="replace")
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""

    # Zeek TSV logs start with a comment header block (#separator, #fields...)
    if text.lstrip().startswith("#separator") or "#fields" in text[:2000]:
        return _parse_zeek_tsv(text), "zeek-tsv"

    # Try JSON (single object, array, or JSON-lines)
    if ext == "json" or text.strip()[:1] in ("{", "["):
        records = _try_parse_json(text)
        if records is not None:
            return records, "json"

    if ext in ("csv", "tsv"):
        delim = "\t" if ext == "tsv" else _sniff_delimiter(text)
        return _parse_delimited(text, delim), "delimited"

    # .log / .txt: try JSON-lines first, then delimited, then raw text lines
    records = _try_parse_json(text)
    if records is not None:
        return records, "json-lines"

    first_line = text.splitlines()[0] if text.splitlines() else ""
    if first_line.count("\t") >= 2:
        return _parse_delimited(text, "\t"), "delimited"

    return _parse_generic_lines(text), "text-lines"


def _try_parse_json(text: str):
    text = text.strip()
    if not text:
        return None
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            for key in ("Records", "records", "events", "Events", "logs", "Entries"):
                if key in data and isinstance(data[key], list):
                    return data[key]
            return [data]
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass
    # JSON-lines fallback
    records = []
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            return None
    return records or None


def _sniff_delimiter(text: str) -> str:
    first_line = text.splitlines()[0] if text.splitlines() else ""
    return "\t" if first_line.count("\t") >= first_line.count(",") else ","


def _parse_delimited(text: str, delim: str):
    reader = csv.DictReader(io.StringIO(text), delimiter=delim)
    return [dict(row) for row in reader]


def _parse_zeek_tsv(text: str):
    fields = []
    rows = []
    for line in text.splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif line.startswith("#") or not line.strip():
            continue
        else:
            values = line.split("\t")
            if fields and len(values) == len(fields):
                rows.append(dict(zip(fields, values)))
    return rows


_SYSLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-.\/]+)(\[\d+\])?:\s*(?P<msg>.*)$"
)


def _parse_generic_lines(text: str):
    records = []
    for line in text.splitlines():
        if not line.strip():
            continue
        m = _SYSLOG_RE.match(line)
        if m:
            d = m.groupdict()
            records.append({
                "timestamp_raw": d["ts"], "host": d["host"], "process": d["proc"],
                "message": d["msg"], "raw": line,
            })
        else:
            records.append({"message": line, "raw": line})
    return records


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def detect_log_type(records: list, filename: str = "") -> str:
    fname = filename.lower()
    if not records:
        return "generic"
    sample = [r for r in records[: min(len(records), 25)] if isinstance(r, dict)]
    all_keys = set().union(*(set(r.keys()) for r in sample)) if sample else set()

    if {"eventSource", "eventName"} <= all_keys or "awsRegion" in all_keys or "cloudtrail" in fname:
        return "cloudtrail"

    if "EventID" in all_keys and ({"Image", "CommandLine", "Hashes", "ParentImage"} & all_keys):
        return "sysmon"
    if "sysmon" in fname:
        return "sysmon"

    if "EventID" in all_keys and ({"Channel", "ProviderName", "Computer"} & all_keys):
        return "windows_event"
    if any(k in fname for k in ("winevent", "windows_event", "evtx")):
        return "windows_event"

    zeek_markers = {"id.orig_h", "id.resp_h", "id.orig_p", "id.resp_p", "proto", "query", "method"}
    if zeek_markers & all_keys:
        return "zeek"
    if any(k in fname for k in ("conn.log", "dns.log", "http.log", "zeek", "bro")):
        return "zeek"

    return "generic"


# ---------------------------------------------------------------------------
# Normalization -> common schema
# ---------------------------------------------------------------------------

COMMON_COLS = [
    "timestamp", "log_type", "event_id", "action", "src_ip", "dst_ip",
    "src_port", "dst_port", "protocol", "user", "host", "process",
    "command_line", "file_path", "file_hash", "dns_query", "http_host",
    "http_uri", "status", "bytes", "message", "raw",
]


def _parse_ts(value):
    if value is None or value == "" or value == "-":
        return pd.NaT
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return pd.NaT
    value = str(value)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        val = float(value)
        return datetime.fromtimestamp(val, tz=timezone.utc)
    except ValueError:
        pass
    try:
        return pd.to_datetime(value, utc=True, errors="coerce")
    except Exception:
        return pd.NaT


def normalize(records: list, log_type: str) -> pd.DataFrame:
    rows = []
    for r in records:
        if not isinstance(r, dict):
            r = {"message": str(r)}
        row = {c: None for c in COMMON_COLS}
        try:
            row["raw"] = json.dumps(r, default=str)
        except TypeError:
            row["raw"] = str(r)
        row["log_type"] = log_type

        if log_type == "cloudtrail":
            row["timestamp"] = _parse_ts(r.get("eventTime"))
            row["event_id"] = r.get("eventID")
            row["action"] = r.get("eventName")
            row["src_ip"] = r.get("sourceIPAddress")
            ui = r.get("userIdentity") or {}
            row["user"] = ui.get("userName") or ui.get("arn") or ui.get("principalId")
            row["status"] = "failure" if r.get("errorCode") else "success"
            row["message"] = f"{r.get('eventSource', '')} {r.get('eventName', '')}".strip()

        elif log_type == "sysmon":
            row["timestamp"] = _parse_ts(r.get("UtcTime") or r.get("TimeCreated"))
            row["event_id"] = r.get("EventID")
            row["process"] = r.get("Image") or r.get("TargetImage")
            row["command_line"] = r.get("CommandLine")
            row["user"] = r.get("User")
            row["host"] = r.get("Computer")
            row["file_path"] = r.get("TargetFilename") or r.get("TargetObject")
            row["file_hash"] = r.get("Hashes")
            row["src_ip"] = r.get("SourceIp")
            row["dst_ip"] = r.get("DestinationIp")
            row["dst_port"] = r.get("DestinationPort")
            row["action"] = {
                "1": "Process Create", "3": "Network Connect", "7": "Image Load",
                "11": "File Create", "12": "Registry Add/Delete", "13": "Registry Set Value",
                "22": "DNS Query",
            }.get(str(r.get("EventID")), r.get("EventID"))
            row["message"] = row["command_line"] or row["action"]

        elif log_type == "windows_event":
            row["timestamp"] = _parse_ts(r.get("TimeCreated") or r.get("SystemTime"))
            row["event_id"] = r.get("EventID")
            row["host"] = r.get("Computer")
            row["user"] = r.get("TargetUserName") or r.get("SubjectUserName")
            row["action"] = (str(r.get("Message", ""))[:80] if r.get("Message") else str(r.get("EventID")))
            eid = str(r.get("EventID"))
            row["status"] = "failure" if eid == "4625" else ("success" if eid == "4624" else None)
            row["src_ip"] = r.get("IpAddress")
            row["message"] = r.get("Message") or eid

        elif log_type == "zeek":
            row["timestamp"] = _parse_ts(r.get("ts"))
            row["src_ip"] = r.get("id.orig_h")
            row["dst_ip"] = r.get("id.resp_h")
            row["src_port"] = r.get("id.orig_p")
            row["dst_port"] = r.get("id.resp_p")
            row["protocol"] = r.get("proto")
            row["dns_query"] = r.get("query")
            row["http_host"] = r.get("host")
            row["http_uri"] = r.get("uri")
            row["bytes"] = r.get("orig_bytes") or r.get("resp_bytes")
            if r.get("query") and r.get("query") != "-":
                row["action"] = "dns"
            elif r.get("method") and r.get("method") != "-":
                row["action"] = "http"
            else:
                row["action"] = "conn"
            if row["action"] == "dns":
                row["message"] = r.get("query")
            elif row["action"] == "http":
                row["message"] = f"{r.get('method', '')} {r.get('host', '')}{r.get('uri', '')}"
            else:
                row["message"] = f"{row['src_ip']}:{row['src_port']} -> {row['dst_ip']}:{row['dst_port']}"

        else:  # generic
            row["timestamp"] = _parse_ts(
                r.get("timestamp") or r.get("time") or r.get("ts") or r.get("timestamp_raw") or r.get("@timestamp")
            )
            row["message"] = r.get("message") or r.get("msg") or str(r)
            row["host"] = r.get("host")
            row["process"] = r.get("process")
            for k in ("src_ip", "source_ip", "ip", "srcip"):
                if r.get(k):
                    row["src_ip"] = r.get(k)
                    break

        rows.append(row)

    return pd.DataFrame(rows, columns=COMMON_COLS)