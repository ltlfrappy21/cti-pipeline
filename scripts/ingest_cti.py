#!/usr/bin/env python3
import os
import sys
import time
import datetime as dt
import subprocess
from pathlib import Path
import traceback
import requests

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

def notion(method, path, json=None):
    r = requests.request(method, f"{BASE}{path}", headers=H, json=json, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    return r.json()

def notion_query_cve(database_id, cve_id):
    """Query Notion database for existing CVE entry."""
    try:
        result = notion("POST", f"/databases/{database_id}/query", json={
            "filter": {
                "property": "CVE ID",
                "rich_text": {
                    "equals": cve_id
                }
            },
            "page_size": 1
        })
        results = result.get("results", [])
        return results[0] if results else None
    except Exception as e:
        if os.getenv("VERBOSE"):
            print(f"    Query error for {cve_id}: {e}")
        return None

def create_kev_entry(vuln, date_today):
    """Create a new KEV entry in Notion."""
    if not DB_KEV:
        return None
    
    try:
        cve_id = vuln.get("cveID", "")
        props = {
            "CVE ID": {"title": [{"text": {"content": cve_id}}]},
            "Vendor/Project": {"rich_text": [{"text": {"content": vuln.get("vendorProject", "")[:2000]}}]},
            "Product": {"rich_text": [{"text": {"content": vuln.get("product", "")[:2000]}}]},
            "Vulnerability Name": {"rich_text": [{"text": {"content": vuln.get("vulnerabilityName", "")[:2000]}}]},
            "Date Added": {"date": {"start": vuln.get("dateAdded", str(date_today))}},
            "Short Description": {"rich_text": [{"text": {"content": vuln.get("shortDescription", "")[:2000]}}]},
            "Required Action": {"rich_text": [{"text": {"content": vuln.get("requiredAction", "")[:2000]}}]},
        }
        
        # Add due date only if present
        if vuln.get("dueDate"):
            props["Due Date"] = {"date": {"start": vuln["dueDate"]}}
        
        # Add known ransomware campaign usage if available
        if "knownRansomwareCampaignUse" in vuln:
            props["Known Ransomware"] = {"checkbox": vuln["knownRansomwareCampaignUse"] == "Known"}
        
        # Add notes if available
        if vuln.get("notes"):
            props["Notes"] = {"rich_text": [{"text": {"content": vuln["notes"][:2000]}}]}
        
        result = notion("POST", "/pages", json={
            "parent": {"database_id": DB_KEV},
            "properties": props
        })
        
        if os.getenv("VERBOSE"):
            print(f"    Created KEV: {cve_id}")
        
        return result.get("id")
        
    except Exception as e:
        print(f"    ERROR creating KEV entry for {vuln.get('cveID')}: {e}")
        return None

def update_kev_entry(page_id, vuln, date_today):
    """Update an existing KEV entry in Notion."""
    try:
        # Build update props - only update fields that might change
        props = {
            "Short Description": {"rich_text": [{"text": {"content": vuln.get("shortDescription", "")[:2000]}}]},
            "Required Action": {"rich_text": [{"text": {"content": vuln.get("requiredAction", "")[:2000]}}]},
        }
        
        # Add due date only if present
        if vuln.get("dueDate"):
            props["Due Date"] = {"date": {"start": vuln["dueDate"]}}
        
        if "knownRansomwareCampaignUse" in vuln:
            props["Known Ransomware"] = {"checkbox": vuln["knownRansomwareCampaignUse"] == "Known"}
        
        if vuln.get("notes"):
            props["Notes"] = {"rich_text": [{"text": {"content": vuln["notes"][:2000]}}]}
        
        notion("PATCH", f"/pages/{page_id}", json={"properties": props})
        
        if os.getenv("VERBOSE"):
            print(f"    Updated KEV: {vuln.get('cveID')}")
        
        return True
        
    except Exception as e:
        if os.getenv("VERBOSE"):
            print(f"    ERROR updating KEV entry: {e}")
        return False

def create_epss_entry(score_data, kev_page_id=None):
    """Create a new EPSS entry in Notion."""
    if not DB_EPSS:
        return None
    
    try:
        cve_id = score_data.get("cve", "")
        props = {
            "CVE ID": {"title": [{"text": {"content": cve_id}}]},
            "EPSS Score": {"number": float(score_data.get("epss", 0))},
            "Percentile": {"number": float(score_data.get("percentile", 0))},
            "Date": {"date": {"start": score_data.get("date", dt.date.today().isoformat())}},
        }
        
        # Link to KEV entry if available
        if kev_page_id:
            props["KEV Reference"] = {"relation": [{"id": kev_page_id}]}
        
        result = notion("POST", "/pages", json={
            "parent": {"database_id": DB_EPSS},
            "properties": props
        })
        
        if os.getenv("VERBOSE"):
            print(f"    Created EPSS: {cve_id} (score={score_data.get('epss')})")
        
        return result.get("id")
        
    except Exception as e:
        print(f"    ERROR creating EPSS entry for {score_data.get('cve')}: {e}")
        return None

def update_epss_entry(page_id, score_data):
    """Update an existing EPSS entry in Notion."""
    try:
        props = {
            "EPSS Score": {"number": float(score_data.get("epss", 0))},
            "Percentile": {"number": float(score_data.get("percentile", 0))},
            "Date": {"date": {"start": score_data.get("date", dt.date.today().isoformat())}},
        }
        
        notion("PATCH", f"/pages/{page_id}", json={"properties": props})
        
        if os.getenv("VERBOSE"):
            print(f"    Updated EPSS: {score_data.get('cve')}")
        
        return True
        
    except Exception as e:
        if os.getenv("VERBOSE"):
            print(f"    ERROR updating EPSS entry: {e}")
        return False

def get_git_sha():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        return "UNKNOWN"

def sla_status(duration_mins):
    if duration_mins <= 15:
        return "Healthy"
    elif duration_mins <= 30:
        return "Warning"
    else:
        return "Failed"

def runlog(msg, kev_c=0, kev_u=0, epss_c=0, epss_u=0, epss_link=0, duration=0, error=None):
    now = dt.datetime.now(dt.UTC)
    props = {
        "Run Title": {"title": [{"text": {"content": f"CTI Run {now.isoformat()}"}}]},
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
    if error:
        props["Errors"] = {"rich_text": [{"text": {"content": error}}]}
    else:
        props["Details"] = {"rich_text": [{"text": {"content": msg}}]}
    notion("POST", "/pages", json={"parent": {"database_id": DB_RUN}, "properties": props})
    Path("logs").mkdir(exist_ok=True)
    with open(Path("logs")/now.strftime("%Y%m%d_cti.log"), "a") as f:
        f.write((error if error else msg) + "\n")

def ingest_kev(date_today):
    """
    Ingest Known Exploited Vulnerabilities from CISA.
    Returns: (created_count, updated_count, cve_mapping_dict)
    """
    print("STEP 1: Ingesting KEV data from CISA...")
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    try:
        response = requests.get(kev_url, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        kev_data = response.json()
        
        vulnerabilities = kev_data.get("vulnerabilities", [])
        print(f"  Retrieved {len(vulnerabilities)} KEV entries from CISA")
        
        created, updated = 0, 0
        map_cve = {}
        
        max_kev = int(os.getenv("MAX_KEV", "0"))  # 0 means process all
        process_count = len(vulnerabilities) if max_kev == 0 else min(max_kev, len(vulnerabilities))
        
        for vuln in vulnerabilities[:process_count]:
            cve_id = vuln.get("cveID")
            if not cve_id:
                continue
                
            # Check if this CVE already exists in Notion
            if DB_KEV:
                existing = notion_query_cve(DB_KEV, cve_id)
                if existing:
                    # Update existing entry if needed
                    if update_kev_entry(existing["id"], vuln, date_today):
                        updated += 1
                    map_cve[cve_id] = existing["id"]
                else:
                    # Create new entry
                    page_id = create_kev_entry(vuln, date_today)
                    if page_id:
                        created += 1
                        map_cve[cve_id] = page_id
            else:
                # No DB configured, just track CVEs
                map_cve[cve_id] = cve_id
                created += 1
        
        print(f"  KEV: created={created}, updated={updated}, total_mapped={len(map_cve)}")
        return created, updated, map_cve
        
    except Exception as e:
        print(f"  ERROR ingesting KEV: {e}")
        raise

def ingest_epss(map_cve):
    """
    Ingest EPSS (Exploit Prediction Scoring System) data.
    Returns: (created_count, updated_count, linked_to_kev_count)
    """
    print("STEP 2: Ingesting EPSS data from FIRST.org...")
    
    try:
        # Get list of CVEs to query from KEV mapping
        cve_list = list(map_cve.keys())
        if not cve_list:
            print("  No CVEs from KEV to query EPSS for")
            return 0, 0, 0
        
        max_epss = int(os.getenv("MAX_EPSS", "0"))  # 0 means process all
        if max_epss > 0:
            cve_list = cve_list[:max_epss]
        
        print(f"  Querying EPSS scores for {len(cve_list)} CVEs...")
        
        created, updated, linked = 0, 0, 0
        batch_size = 100  # API limit per request
        
        for i in range(0, len(cve_list), batch_size):
            batch = cve_list[i:i+batch_size]
            cve_param = ",".join(batch)
            
            try:
                epss_url = f"https://api.first.org/data/v1/epss?cve={cve_param}"
                response = requests.get(epss_url, timeout=HTTP_TIMEOUT)
                response.raise_for_status()
                epss_data = response.json()
                
                epss_scores = epss_data.get("data", [])
                
                for score_data in epss_scores:
                    cve_id = score_data.get("cve")
                    
                    if not cve_id:
                        continue
                    
                    # Check if EPSS entry exists in Notion
                    if DB_EPSS:
                        existing = notion_query_cve(DB_EPSS, cve_id)
                        if existing:
                            # Update existing entry
                            if update_epss_entry(existing["id"], score_data):
                                updated += 1
                        else:
                            # Create new entry and link to KEV if available
                            kev_page_id = map_cve.get(cve_id)
                            page_id = create_epss_entry(score_data, kev_page_id)
                            if page_id:
                                created += 1
                                if kev_page_id:
                                    linked += 1
                    else:
                        # No DB configured, just count
                        created += 1
                        if cve_id in map_cve:
                            linked += 1
            
            except Exception as e:
                print(f"  WARNING: Batch {i//batch_size + 1} failed: {e}")
                # Continue processing remaining batches
                continue
        
        print(f"  EPSS: created={created}, updated={updated}, linked_to_KEV={linked}")
        return created, updated, linked
        
    except Exception as e:
        print(f"  ERROR ingesting EPSS: {e}")
        raise

def main():
    start = time.time()
    try:
        kev_c, kev_u, map_cve = ingest_kev(dt.date.today())
        epss_c, epss_u, epss_link = ingest_epss(map_cve)
        msg = (f"KEV created={kev_c}, updated={kev_u}; "
               f"EPSS created={epss_c}, updated={epss_u}, linked_to_KEV={epss_link}; ")
        duration = int((time.time() - start) / 60)
        print("STEP 3: Write run log…")
        runlog(msg, kev_c, kev_u, epss_c, epss_u, epss_link, duration)
        print(f"DONE. {msg} duration={duration}m, SHA={get_git_sha()}, Health={sla_status(duration)}")
    except Exception:
        duration = int((time.time() - start) / 60)
        error_msg = traceback.format_exc()
        print("ERROR during run:\n", error_msg)
        runlog("Run failed", duration=duration, error=error_msg)
        sys.exit(1)

if __name__ == "__main__":
    main()
