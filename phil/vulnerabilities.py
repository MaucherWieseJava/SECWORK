import requests
from datetime import datetime, timezone


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_nvd_cves(date: datetime, max_results: int = 20) -> list[dict]:
    """Fetch CVEs published on a specific date from the NVD API."""
    start = date.strftime("%Y-%m-%dT00:00:00.000")
    end = date.strftime("%Y-%m-%dT23:59:59.999")

    params = {
        "pubStartDate": start,
        "pubEndDate": end,
        "resultsPerPage": max_results,
    }

    try:
        response = requests.get(NVD_API_URL, params=params, timeout=15)
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

            references = [
                ref.get("url") for ref in cve.get("references", [])[:3]
            ]

            if severity.upper() not in ("HIGH", "CRITICAL"):
                continue

            vulnerabilities.append({
                "id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "severity": severity,
                "references": references,
                "published": cve.get("published", ""),
            })

        return vulnerabilities

    except requests.RequestException as e:
        print(f"[vulnerabilities] NVD API error: {e}")
        return []


def fetch_cisa_kev_recent(date: datetime) -> list[dict]:
    """Fetch CISA Known Exploited Vulnerabilities added on a specific date."""
    try:
        response = requests.get(CISA_KEV_URL, timeout=15)
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

        return results

    except requests.RequestException as e:
        print(f"[vulnerabilities] CISA KEV error: {e}")
        return []