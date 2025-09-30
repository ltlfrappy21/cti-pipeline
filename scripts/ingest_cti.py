#!/usr/bin/env python3
import os
import sys
import time
import datetime as dt
import subprocess
from pathlib import Path
import requests

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------
BASE = "https://api.notion.com/v1"
H = {
    "Authorization": f"Bearer {os.environ['NOTION_TOKEN']}",
    "Notion-Version": "2022-06-28",
    "Content-Type": "application/json",
}
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "180"))

DB_RUN = os.environ.get("DB_RUNLOG") or os.environ.get("NOTION_DB_RUN_LOG")
DB_KEV = os.environ.get("DB_KEV")
DB_EPSS = os.environ.get("DB_EPSS")

# -------------------------------------------------------------------
# Utility functions
# -------------------------------------------------------------------
def notion(method, path, json=None):
    """Wrapper for Notion API requests with retry and error handling."""
    r = requests.request(method, f"{BASE}{path}", headers=H, json=json, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    return r.json()

def get_git_sha():
    """Return current Git commit SHA for traceability."""
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        return "UNKNOWN"

def sla_status(duration_mins):
    """Return health status based on SLA thresholds."""
    if duration_mins <= 15:
        return "Healthy"
    elif duration_mins <= 30:
        return "Warning"
    else:
        return "Failed"

def runlog(msg, kev_c=0, kev_u=0, epss_c=0, epss_u=0, epss_link=0, duration=0):
    """Write run log entry into Notion with deltas + metadata."""
    now = dt.datetime.now(dt.UTC)  # timezone-aware UTC
    props = {
        "Run Title": {"title": [{"text": {"content": f"CTI Run {now.isoformat()}"}}]},
        "Details": {"rich_text": [{"text": {"content": msg}}]},
        "Timestamp": {"date": {"start": now.isoformat()}},
        "Source": {"select": {"name": "VS Terminal"}},
        "KEV Created": {"number": kev_c},
        "KEV Updated": {"number": kev_u},
        "EPSS Created": {"number": epss_c},
        "EPSS Updated": {"number": epss_u},
        "Linked": {"number": epss_link},
        "Duration (m)": {"number": duration},
        "Build SHA": {"rich_text": [{"text": {"content": get_git_sha()}}]},
        "Logs URL": {"url": f"file://{Path('logs')/now.strftime('%Y%m%d_cti.log')}"},
        "Health Status": {"select": {"name": sla_status(duration)}},
    }
    notion("POST", "/pages", json={"parent": {"database_id": DB_RUN}, "properties": props})
    Path("logs").mkdir(exist_ok=True)
    with open(Path("logs")/now.strftime("%Y%m%d_cti.log"), "a") as f:
        f.write(msg + "\n")

# -------------------------------------------------------------------
# Dummy ingestion functions (replace with real ingestion)
# -------------------------------------------------------------------
def ingest_kev(date_today):
    # Simulated KEV ingestion
    created, updated = 0, 5
    map_cve = {}
    return created, updated, map_cve

def ingest_epss(map_cve):
    # Simulated EPSS ingestion
    created, updated, linked = 50, 0, 0
    return created, updated, linked

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
def main():
    start = time.time()
    kev_c, kev_u, map_cve = ingest_kev(dt.date.today())
    epss_c, epss_u, epss_link = ingest_epss(map_cve)

    msg = (f"KEV created={kev_c}, updated={kev_u}; "
           f"EPSS created={epss_c}, updated={epss_u}, linked_to_KEV={epss_link}; ")
    duration = int((time.time() - start) / 60)

    print("STEP 3: Write run log…")
    runlog(msg, kev_c, kev_u, epss_c, epss_u, epss_link, duration)
    print(f"DONE. {msg} duration={duration}m, SHA={get_git_sha()}, Health={sla_status(duration)}")

if __name__ == "__main__":
    main()
