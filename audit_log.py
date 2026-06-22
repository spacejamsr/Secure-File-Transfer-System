import json
import os
from datetime import datetime, timezone

LOG_FILE = "audit_log.json"

def write_log(event_type, username=None, details=None, severity="info"):
    try:
        # Load existing logs
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
        else:
            logs = []

        # Create log entry
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "username": username or "anonymous",
            "severity": severity,
            "details": details or {}
        }

        # Append and save
        logs.append(log_entry)
        with open(LOG_FILE, "w") as f:
            json.dump(logs, f, indent=4)
    except Exception:
        pass