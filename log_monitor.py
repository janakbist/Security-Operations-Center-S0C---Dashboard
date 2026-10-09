import subprocess
import re
from datetime import datetime

FAILED_LOGIN_PATTERNS = [
    "Failed password",
    "authentication failure",
    "Failed to authenticate",
    "Invalid user"
]

def stream_system_logs():
    process = subprocess.Popen(
        ["log", "stream", "--info"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    for line in process.stdout:
        yield line


def parse_log(line):
    for pattern in FAILED_LOGIN_PATTERNS:
        if pattern.lower() in line.lower():
            return {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "event_type": "FAILED_LOGIN",
                "raw_log": line.strip(),
                "ip": extract_ip(line),
                "username": extract_user(line),
                "threat_score": 70,
                "threat_level": "HIGH"
            }
    return None


def extract_ip(text):
    match = re.search(r'\b\d{1,3}(\.\d{1,3}){3}\b', text)
    return match.group() if match else "LOCAL"


def extract_user(text):
    match = re.search(r'user\s+\w+|invalid user\s+\w+', text, re.IGNORECASE)
    return match.group().split()[-1] if match else "unknown"