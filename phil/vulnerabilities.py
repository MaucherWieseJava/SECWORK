import os
from datetime import datetime, timezone

from http_client import get_session


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_nvd_cves(date: datetime, max_results: int = 50) -> list[dict]:
    """Fetch CVEs published on a specific date from the NVD API, sorted by CVSS score."""
    start = date.strftime("%Y-%m-%dT00:00:00.000")
    end = date.strftime("%Y-%m-%dT23:59:59.999")

    params = {
        "pubStartDate": start,
        "pubEndDate": end,
        "resultsPerPage": max_results,
    }

    # Use NVD API key if available (higher rate limit)
    api_key = os.environ.get("NVD_API_KEY")
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    session = get_session()
    try:
        response = session.get(NVD_API_URL, params=params, headers=headers, timeout=60)
        response.raise_for_status()
        data = response.json()
        vulnerabilities = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")

            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available."
            )

            metrics = cve.get("metrics", {})
            cvss_score = None
            severity = "N/A"

            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss_data = metrics[key][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity", "N/A")
                    break

            if severity.upper() != "CRITICAL":
                continue

            nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            extra_refs = [
                ref.get("url") for ref in cve.get("references", [])
                if ref.get("url") and "github.com" not in ref.get("url", "")
            ][:2]
            references = [nvd_url] + extra_refs

            vulnerabilities.append({
                "id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "severity": severity.upper(),
                "references": references,
                "published": cve.get("published", ""),
            })

        # Sort by CVSS score descending (Critical first, then High)
        vulnerabilities.sort(key=lambda v: v["cvss_score"] or 0, reverse=True)

        return vulnerabilities

    except Exception as e:
        print(f"[vulnerabilities] NVD API error: {e}")
        return []


def fetch_cisa_kev_recent(date: datetime) -> list[dict]:
    """Fetch CISA Known Exploited Vulnerabilities added on a specific date, sorted by due date."""
    session = get_session()
    try:
        response = session.get(CISA_KEV_URL, timeout=60)
        response.raise_for_status()
        data = response.json()

        target_date = date.strftime("%Y-%m-%d")
        results = []

        for vuln in data.get("vulnerabilities", []):
            if vuln.get("dateAdded", "").startswith(target_date):
                results.append({
                    "id": vuln.get("cveID", "N/A"),
                    "product": vuln.get("product", "N/A"),
                    "vendor": vuln.get("vendorProject", "N/A"),
                    "description": vuln.get("shortDescription", "No description."),
                    "due_date": vuln.get("dueDate", "N/A"),
                    "action": vuln.get("requiredAction", "N/A"),
                })

        # Sort by due date ascending (most urgent first)
        results.sort(key=lambda v: v["due_date"])

        return results

    except Exception as e:
        print(f"[vulnerabilities] CISA KEV error: {e}")
        return []
