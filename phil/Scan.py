import argparse
import sys
import os
import time
import html
from datetime import datetime
import requests

FORTIFY_SSC_URL = "https://fortify.ssc.your-company.com/ssc"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_CERT = os.path.join(BASE_DIR, "certificate.pem")
CA_BUNDLE = os.path.join(BASE_DIR, "ca-bundle.crt")


def get_session(api_key):
    session = requests.Session()
    session.cert = CLIENT_CERT
    if os.path.isfile(CA_BUNDLE):
        session.verify = CA_BUNDLE
    else:
        session.verify = True
    session.headers.update({
        "Authorization": f"FortifyToken {api_key}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    })
    return session


def get_all_project_versions(session):
    versions = []
    start = 0
    limit = 200
    while True:
        resp = session.get(
            f"{FORTIFY_SSC_URL}/api/v1/projectVersions",
            params={"start": start, "limit": limit}
        )
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("data", [])
        if not batch:
            break
        versions.extend(batch)
        if len(batch) < limit:
            break
        start += limit
    return versions


def get_cloudscan_token(session):
    resp = session.post(
        f"{FORTIFY_SSC_URL}/api/v1/cloudjobs/token",
        json={"type": "SCAN"}
    )
    resp.raise_for_status()
    return resp.json()["data"]["token"]


def trigger_scan(session, version_id, version_name, project_name):
    payload = {
        "projectVersionId": version_id,
        "scanType": "SAST",
        "technology": "AUTO_DETECT"
    }
    resp = session.post(
        f"{FORTIFY_SSC_URL}/api/v1/cloudjobs",
        json=payload
    )
    if resp.status_code in (200, 201, 202):
        job_id = resp.json().get("data", {}).get("jobToken", "N/A")
        print(f"  [OK] Scan triggered -> job: {job_id}")
        return job_id
    else:
        print(f"  [FAIL] {resp.status_code}: {resp.text[:200]}")
        return None


def poll_job_status(session, job_ids):
    if not job_ids:
        return
    print(f"\nPolling {len(job_ids)} scan job(s)...")
    pending = set(job_ids)
    while pending:
        time.sleep(30)
        for job_id in list(pending):
            resp = session.get(f"{FORTIFY_SSC_URL}/api/v1/cloudjobs/{job_id}")
            if resp.status_code != 200:
                continue
            state = resp.json().get("data", {}).get("jobState", "UNKNOWN")
            if state in ("COMPLETED", "FAILED", "CANCELLED"):
                print(f"  Job {job_id}: {state}")
                pending.discard(job_id)
            else:
                print(f"  Job {job_id}: {state} (waiting...)")
    print("All jobs finished.")


def fetch_issues(session, version_id):
    issues = []
    start = 0
    limit = 200
    while True:
        resp = session.get(
            f"{FORTIFY_SSC_URL}/api/v1/projectVersions/{version_id}/issues",
            params={"start": start, "limit": limit, "orderby": "friority"}
        )
        if resp.status_code != 200:
            break
        batch = resp.json().get("data", [])
        if not batch:
            break
        issues.extend(batch)
        if len(batch) < limit:
            break
        start += limit
    return issues


def generate_report(session, versions, report_path):
    print(f"\nGenerating report...")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

    project_data = []
    total_issues = 0

    for v in versions:
        project_name = v.get("project", {}).get("name", "unknown")
        version_name = v.get("name", "unknown")
        version_id = v["id"]
        print(f"  Fetching issues for [{project_name}] {version_name}...")

        issues = fetch_issues(session, version_id)
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        issue_details = []

        for iss in issues:
            sev = iss.get("friority", "Low")
            if sev not in counts:
                sev = "Low"
            counts[sev] += 1
            issue_details.append({
                "category": iss.get("issueName", "N/A"),
                "severity": sev,
                "file": iss.get("primaryLocation", "N/A"),
                "line": iss.get("lineNumber", "N/A"),
                "analyzer": iss.get("analyzer", "N/A"),
                "status": iss.get("issueStatus", "N/A"),
            })

        issue_details.sort(key=lambda x: severity_order.get(x["severity"], 99))
        total_issues += len(issues)
        project_data.append({
            "project": project_name,
            "version": version_name,
            "counts": counts,
            "total": len(issues),
            "issues": issue_details
        })

    project_data.sort(key=lambda x: x["total"], reverse=True)

    h = html.escape
    rows_summary = ""
    for p in project_data:
        rows_summary += f"""<tr>
            <td>{h(p['project'])}</td><td>{h(p['version'])}</td>
            <td class="crit">{p['counts']['Critical']}</td>
            <td class="high">{p['counts']['High']}</td>
            <td class="med">{p['counts']['Medium']}</td>
            <td class="low">{p['counts']['Low']}</td>
            <td><b>{p['total']}</b></td></tr>\n"""

    detail_sections = ""
    for p in project_data:
        if not p["issues"]:
            continue
        issue_rows = ""
        for iss in p["issues"]:
            sev_class = iss["severity"].lower()[:4]
            issue_rows += f"""<tr>
                <td class="{sev_class}">{h(iss['severity'])}</td>
                <td>{h(iss['category'])}</td>
                <td>{h(iss['file'])}</td>
                <td>{iss['line']}</td>
                <td>{h(iss['analyzer'])}</td>
                <td>{h(iss['status'])}</td></tr>\n"""
        detail_sections += f"""
        <h2>{h(p['project'])} - {h(p['version'])} ({p['total']} issues)</h2>
        <table>
            <tr><th>Severity</th><th>Category</th><th>File</th><th>Line</th><th>Analyzer</th><th>Status</th></tr>
            {issue_rows}
        </table>\n"""

    report_html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Fortify SAST Scan Report</title>
<style>
    body {{ font-family: Arial, sans-serif; margin: 30px; background: #f5f5f5; }}
    h1 {{ color: #1a1a2e; }}
    h2 {{ color: #16213e; margin-top: 40px; border-bottom: 2px solid #0f3460; padding-bottom: 5px; }}
    table {{ border-collapse: collapse; width: 100%; margin: 10px 0 30px 0; background: #fff; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 13px; }}
    th {{ background: #16213e; color: #fff; }}
    tr:nth-child(even) {{ background: #f9f9f9; }}
    .crit {{ color: #9b0000; font-weight: bold; }}
    .high {{ color: #d35400; font-weight: bold; }}
    .med {{ color: #b8860b; }}
    .low {{ color: #2e7d32; }}
    .meta {{ color: #555; font-size: 14px; }}
</style></head><body>
<h1>Fortify SAST Scan Report</h1>
<p class="meta">Generated: {timestamp} | Target: {h(FORTIFY_SSC_URL)} | Projects scanned: {len(project_data)} | Total issues: {total_issues}</p>

<h2>Summary</h2>
<table>
    <tr><th>Project</th><th>Version</th><th class="crit">Critical</th><th class="high">High</th><th class="med">Medium</th><th class="low">Low</th><th>Total</th></tr>
    {rows_summary}
</table>

<h1>Detailed Findings</h1>
{detail_sections}
</body></html>"""

    with open(report_path, "w") as f:
        f.write(report_html)
    print(f"\nReport saved to: {report_path}")


def main():
    parser = argparse.ArgumentParser(description="Fortify SSC full-environment SAST scanner")
    parser.add_argument("--api-key", required=True, help="Fortify SSC API token")
    parser.add_argument("--poll", action="store_true", help="Poll scan jobs until completion")
    parser.add_argument("--dry-run", action="store_true", help="List projects without triggering scans")
    parser.add_argument("--report", action="store_true", help="Generate HTML report after scans complete")
    args = parser.parse_args()

    if not os.path.isfile(CLIENT_CERT):
        print(f"Client certificate not found: {CLIENT_CERT}")
        sys.exit(1)

    session = get_session(args.api_key)

    print(f"Connecting to {FORTIFY_SSC_URL}")
    versions = get_all_project_versions(session)
    print(f"Found {len(versions)} project version(s)\n")

    if not versions:
        print("No project versions found.")
        sys.exit(0)

    job_ids = []
    for v in versions:
        project_name = v.get("project", {}).get("name", "unknown")
        version_name = v.get("name", "unknown")
        version_id = v["id"]
        print(f"[{project_name}] {version_name} (id={version_id})")

        if args.dry_run:
            continue

        job_id = trigger_scan(session, version_id, version_name, project_name)
        if job_id:
            job_ids.append(job_id)

    if args.dry_run:
        print("\nDry run complete. No scans triggered.")
        return

    print(f"\nTriggered {len(job_ids)} scan(s) across {len(versions)} project version(s).")

    if args.poll and job_ids:
        poll_job_status(session, job_ids)

    if args.report:
        report_name = f"fortify_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), report_name)
        generate_report(session, versions, report_path)


if __name__ == "__main__":
    main()