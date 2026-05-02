#!/usr/bin/env python3
"""
SonarQube Findings Exporter
============================
Exportiert Issues/Findings aus SonarQube via REST API als CSV oder JSON.
Unterstützt Filterung nach Status, Typ, Schweregrad und Projekt.

Verwendung:
    python sonarqube_export.py --help
    python sonarqube_export.py --url https://sonar.example.com --token <TOKEN>
    python sonarqube_export.py --url https://sonar.example.com --token <TOKEN> --project myProjectKey
    python sonarqube_export.py --url https://sonar.example.com --token <TOKEN> --statuses ACCEPTED,WONTFIX --format csv

Abhängigkeiten:
    pip install requests
"""

import argparse
import csv
import json
import sys
import os
from datetime import datetime
from typing import Optional

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    print("ERROR: 'requests' ist nicht installiert. Bitte ausführen: pip install requests")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

DEFAULT_PAGE_SIZE = 500  # Max. von SonarQube API erlaubt
MAX_RESULTS = 10_000     # SonarQube API-Limit (deep pagination nötig danach)

SEVERITIES   = ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]
TYPES        = ["BUG", "VULNERABILITY", "CODE_SMELL", "SECURITY_HOTSPOT"]
STATUSES     = ["OPEN", "CONFIRMED", "REOPENED", "RESOLVED", "CLOSED", "ACCEPTED", "WONTFIX", "FALSE-POSITIVE"]

CSV_FIELDS = [
    "key",
    "rule",
    "severity",
    "type",
    "status",
    "resolution",
    "project",
    "component",
    "line",
    "message",
    "author",
    "assignee",
    "effort",
    "debt",
    "tags",
    "creationDate",
    "updateDate",
    "closeDate",
    "hash",
    "textRange_startLine",
    "textRange_endLine",
    "comments",
]


# ---------------------------------------------------------------------------
# API-Client
# ---------------------------------------------------------------------------

class SonarQubeClient:
    def __init__(self, base_url: str, token: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.auth     = HTTPBasicAuth(token, "")  # SonarQube: Token als Username, leeres PW
        self.verify   = verify_ssl
        self.session  = requests.Session()
        self.session.auth   = self.auth
        self.session.verify = self.verify

    def get(self, path: str, params: dict = None) -> dict:
        url = f"{self.base_url}{path}"
        resp = self.session.get(url, params=params, timeout=30)
        if resp.status_code == 401:
            print("ERROR: Authentifizierung fehlgeschlagen. Token prüfen.")
            sys.exit(1)
        if resp.status_code == 403:
            print("ERROR: Keine Berechtigung. Benötigte Rolle: Browse auf dem Projekt.")
            sys.exit(1)
        resp.raise_for_status()
        return resp.json()

    def test_connection(self) -> bool:
        try:
            data = self.get("/api/system/status")
            status = data.get("status", "UNKNOWN")
            version = data.get("version", "?")
            print(f"✅ Verbunden mit SonarQube {version} (Status: {status})")
            return True
        except Exception as e:
            print(f"❌ Verbindungsfehler: {e}")
            return False

    def get_projects(self) -> list[dict]:
        """Alle zugänglichen Projekte abrufen."""
        projects = []
        page = 1
        while True:
            data = self.get("/api/projects/search", params={"ps": 500, "p": page})
            projects.extend(data.get("components", []))
            total = data.get("paging", {}).get("total", 0)
            if len(projects) >= total:
                break
            page += 1
        return projects

    def get_issues(
        self,
        project_keys:  Optional[list[str]] = None,
        severities:    Optional[list[str]] = None,
        types:         Optional[list[str]] = None,
        statuses:      Optional[list[str]] = None,
        rules:         Optional[list[str]] = None,
        tags:          Optional[list[str]] = None,
        created_after: Optional[str] = None,
        created_before: Optional[str] = None,
    ) -> list[dict]:
        """Issues seitenweise abrufen und zusammenführen."""
        params = {
            "ps":               DEFAULT_PAGE_SIZE,
            "additionalFields": "comments,rules,transitions,actions",
            "resolved":         "false",  # wird ggf. überschrieben wenn Status angegeben
        }

        if project_keys:
            params["componentKeys"] = ",".join(project_keys)
        if severities:
            params["severities"]    = ",".join(severities)
        if types:
            params["types"]         = ",".join(types)
        if statuses:
            params["statuses"]      = ",".join(statuses)
            # bei explizitem Status auch resolved issues holen
            if any(s in statuses for s in ["RESOLVED", "CLOSED", "ACCEPTED", "WONTFIX", "FALSE-POSITIVE"]):
                params.pop("resolved", None)
        if rules:
            params["rules"]         = ",".join(rules)
        if tags:
            params["tags"]          = ",".join(tags)
        if created_after:
            params["createdAfter"]  = created_after
        if created_before:
            params["createdBefore"] = created_before

        issues = []
        page   = 1
        total  = None

        while True:
            params["p"] = page
            try:
                data = self.get("/api/issues/search", params=params)
            except requests.HTTPError as e:
                print(f"ERROR beim Abrufen von Seite {page}: {e}")
                break

            batch  = data.get("issues", [])
            issues.extend(batch)

            paging = data.get("paging", {})
            total  = paging.get("total", 0)
            fetched = paging.get("pageIndex", page) * paging.get("pageSize", DEFAULT_PAGE_SIZE)

            print(f"  Seite {page}: {len(batch)} Issues abgerufen (gesamt: {len(issues)}/{total})")

            # SonarQube erlaubt max. 10.000 Ergebnisse über paging
            if len(issues) >= total or len(issues) >= MAX_RESULTS or not batch:
                if total and len(issues) < total:
                    print(f"⚠️  SonarQube API-Limit: Nur {MAX_RESULTS} von {total} Issues exportiert.")
                    print("   Tipp: Filter (Projekt, Severity, Typ) verwenden für vollständigen Export.")
                break
            page += 1

        return issues


# ---------------------------------------------------------------------------
# Datenaufbereitung
# ---------------------------------------------------------------------------

def flatten_issue(issue: dict) -> dict:
    """Issue-Dict in flaches CSV-kompatibles Dict umwandeln."""
    comments = issue.get("comments", [])
    comment_texts = " | ".join(
        f"[{c.get('login','?')} @ {c.get('createdAt','')}]: {c.get('htmlText','')}"
        for c in comments
    )

    text_range = issue.get("textRange", {})

    return {
        "key":                  issue.get("key", ""),
        "rule":                 issue.get("rule", ""),
        "severity":             issue.get("severity", ""),
        "type":                 issue.get("type", ""),
        "status":               issue.get("status", ""),
        "resolution":           issue.get("resolution", ""),
        "project":              issue.get("project", ""),
        "component":            issue.get("component", ""),
        "line":                 issue.get("line", ""),
        "message":              issue.get("message", ""),
        "author":               issue.get("author", ""),
        "assignee":             issue.get("assignee", ""),
        "effort":               issue.get("effort", ""),
        "debt":                 issue.get("debt", ""),
        "tags":                 ", ".join(issue.get("tags", [])),
        "creationDate":         issue.get("creationDate", ""),
        "updateDate":           issue.get("updateDate", ""),
        "closeDate":            issue.get("closeDate", ""),
        "hash":                 issue.get("hash", ""),
        "textRange_startLine":  text_range.get("startLine", ""),
        "textRange_endLine":    text_range.get("endLine", ""),
        "comments":             comment_texts,
    }


# ---------------------------------------------------------------------------
# Export-Funktionen
# ---------------------------------------------------------------------------

def export_csv(issues: list[dict], output_path: str):
    flat = [flatten_issue(i) for i in issues]
    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(flat)
    print(f"✅ CSV exportiert: {output_path} ({len(flat)} Zeilen)")


def export_json(issues: list[dict], output_path: str):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(issues, f, indent=2, ensure_ascii=False)
    print(f"✅ JSON exportiert: {output_path} ({len(issues)} Issues)")


def export_both(issues: list[dict], base_path: str):
    export_csv(issues, base_path + ".csv")
    export_json(issues, base_path + ".json")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="SonarQube Findings Exporter – exportiert Issues als CSV/JSON",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  # Alle Issues exportieren
  python sonarqube_export.py --url https://sonar.example.com --token squ_xxx

  # Nur ein Projekt, nur Vulnerabilities, nur ACCEPTED
  python sonarqube_export.py --url https://sonar.example.com --token squ_xxx \\
      --project my-app --types VULNERABILITY --statuses ACCEPTED

  # Mehrere Projekte, CSV + JSON
  python sonarqube_export.py --url https://sonar.example.com --token squ_xxx \\
      --project proj1,proj2 --format both

  # Gefunden nach Datum, alle kritischen Findings
  python sonarqube_export.py --url https://sonar.example.com --token squ_xxx \\
      --severities CRITICAL,BLOCKER --created-after 2024-01-01

  # Nur Won't Fix / False Positives (für ServiceNow Risk Cards)
  python sonarqube_export.py --url https://sonar.example.com --token squ_xxx \\
      --statuses WONTFIX,FALSE-POSITIVE,ACCEPTED --output accepted_risks
        """,
    )

    # Verbindung
    conn = parser.add_argument_group("Verbindung")
    conn.add_argument("--url",   required=True,  help="SonarQube Base-URL (z.B. https://sonar.example.com)")
    conn.add_argument("--token", required=True,  help="SonarQube User/Service Account Token")
    conn.add_argument("--no-ssl-verify", action="store_true", help="SSL-Zertifikatsprüfung deaktivieren")

    # Filter
    flt = parser.add_argument_group("Filter")
    flt.add_argument("--project",       help="Projektschlüssel (kommagetrennt für mehrere)")
    flt.add_argument("--severities",    help=f"Schweregrade: {', '.join(SEVERITIES)}")
    flt.add_argument("--types",         help=f"Issue-Typen: {', '.join(TYPES)}")
    flt.add_argument("--statuses",      help=f"Status-Filter: {', '.join(STATUSES)}")
    flt.add_argument("--rules",         help="Regelschlüssel (kommagetrennt, z.B. java:S3649)")
    flt.add_argument("--tags",          help="Tags (kommagetrennt)")
    flt.add_argument("--created-after", help="Erstellt nach (YYYY-MM-DD)")
    flt.add_argument("--created-before",help="Erstellt vor (YYYY-MM-DD)")

    # Output
    out = parser.add_argument_group("Output")
    out.add_argument("--format",  choices=["csv", "json", "both"], default="csv",
                     help="Ausgabeformat (Standard: csv)")
    out.add_argument("--output",  help="Ausgabedatei ohne Endung (Standard: sonar_export_DATUM)")

    # Sonstiges
    parser.add_argument("--list-projects", action="store_true",
                        help="Alle verfügbaren Projekte auflisten und beenden")

    return parser.parse_args()


def csv_list(value: Optional[str]) -> Optional[list[str]]:
    if not value:
        return None
    return [v.strip().upper() for v in value.split(",") if v.strip()]


def csv_list_raw(value: Optional[str]) -> Optional[list[str]]:
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args   = parse_args()
    client = SonarQubeClient(
        base_url   = args.url,
        token      = args.token,
        verify_ssl = not args.no_ssl_verify,
    )

    print("\n🔍 SonarQube Findings Exporter")
    print("=" * 40)

    if not client.test_connection():
        sys.exit(1)

    # Projektliste anzeigen
    if args.list_projects:
        print("\n📁 Verfügbare Projekte:")
        projects = client.get_projects()
        for p in projects:
            print(f"  {p['key']:<40} {p.get('name','')}")
        print(f"\nGesamt: {len(projects)} Projekte")
        sys.exit(0)

    # Filter vorbereiten
    project_keys  = csv_list_raw(args.project)
    severities    = csv_list(args.severities)
    types_filter  = csv_list(args.types)
    statuses      = csv_list(args.statuses) if args.statuses else None
    rules         = csv_list_raw(args.rules)
    tags          = csv_list_raw(args.tags)

    # Filter-Zusammenfassung
    print("\n📋 Filter:")
    print(f"  Projekte:       {project_keys or 'alle'}")
    print(f"  Schweregrade:   {severities or 'alle'}")
    print(f"  Typen:          {types_filter or 'alle'}")
    print(f"  Status:         {statuses or 'nur offene'}")
    print(f"  Regeln:         {rules or 'alle'}")
    print(f"  Tags:           {tags or 'alle'}")
    print(f"  Erstellt nach:  {args.created_after or '-'}")
    print(f"  Erstellt vor:   {args.created_before or '-'}")
    print()

    # Issues abrufen
    print("⬇️  Lade Issues...")
    issues = client.get_issues(
        project_keys   = project_keys,
        severities     = severities,
        types          = types_filter,
        statuses       = statuses,
        rules          = rules,
        tags           = tags,
        created_after  = args.created_after,
        created_before = args.created_before,
    )

    if not issues:
        print("ℹ️  Keine Issues gefunden. Filter überprüfen.")
        sys.exit(0)

    print(f"\n📊 {len(issues)} Issues gefunden.\n")

    # Ausgabepfad
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_base = args.output or f"sonar_export_{timestamp}"

    # Exportieren
    fmt = args.format
    if fmt == "csv":
        export_csv(issues, output_base + ".csv")
    elif fmt == "json":
        export_json(issues, output_base + ".json")
    elif fmt == "both":
        export_both(issues, output_base)

    print("\n✅ Export abgeschlossen.")


if __name__ == "__main__":
    main()
