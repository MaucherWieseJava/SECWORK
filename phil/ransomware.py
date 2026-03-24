import requests
from datetime import datetime


RANSOMWARE_LIVE_URL = "https://api.ransomware.live/recentvictims"


def fetch_ransomware_victims(date: datetime) -> list[dict]:
    """Fetch ransomware victims posted on a specific date from ransomware.live."""
    target_date = date.strftime("%Y-%m-%d")

    try:
        response = requests.get(RANSOMWARE_LIVE_URL, timeout=15)
        response.raise_for_status()
        data = response.json()

        victims = []
        for entry in data:
            discovered = entry.get("discovered", "")
            if discovered.startswith(target_date):
                victims.append({
                    "victim": entry.get("victim", "N/A"),
                    "group": entry.get("group", "N/A"),
                    "country": entry.get("country", "N/A"),
                    "sector": entry.get("activity", "N/A"),
                    "discovered": discovered,
                    "description": entry.get("description", ""),
                    "url": entry.get("url", ""),
                })

        return victims

    except requests.RequestException as e:
        print(f"[ransomware] ransomware.live API error: {e}")
        return []