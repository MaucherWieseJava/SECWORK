from datetime import datetime

from http_client import get_session


RANSOMWARE_LIVE_URL = "https://api.ransomware.live/v1/recentvictims"


def fetch_ransomware_victims(date: datetime) -> list[dict]:
    """Fetch ransomware victims posted on a specific date from ransomware.live."""
    target_date = date.strftime("%Y-%m-%d")

    session = get_session()
    try:
        response = session.get(RANSOMWARE_LIVE_URL, timeout=60)
        response.raise_for_status()
        data = response.json()

        victims = []
        for entry in data:
            discovered = entry.get("discovered", "")
            if not discovered.startswith(target_date):
                continue

            victim_name = entry.get("post_title", "").strip()
            group_name = entry.get("group_name", "").strip()
            country = entry.get("country", "").strip()
            sector = entry.get("activity", "").strip()
            description = entry.get("description", "").strip()
            website = entry.get("website", "").strip()

            # Format discovered date (drop microseconds)
            disc_short = discovered.split(".")[0] if "." in discovered else discovered

            victims.append({
                "victim": victim_name or "Unknown",
                "group": group_name or "Unknown",
                "country": country if country and country != "N/A" else "",
                "sector": sector if sector and sector != "N/A" else "",
                "discovered": disc_short,
                "description": description if description and description != "N/A" else "",
                "website": website,
            })

        # Sort by group name so related attacks are grouped together
        victims.sort(key=lambda v: v["group"].lower())

        return victims

    except Exception as e:
        print(f"[ransomware] ransomware.live API error: {e}")
        return []
