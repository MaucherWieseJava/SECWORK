#!/usr/bin/env python3
"""
Fortify SSC – Repo scannen und Security-Report erzeugen.

Ablauf:
  1. Lokaler SAST-Scan des kompletten Repos mit Fortify SCA (sourceanalyzer)
     -> erzeugt eine .fpr-Datei.
  2. Login an Fortify SSC per Token (Authorization: FortifyToken <token>).
  3. Upload der .fpr auf die Projektversion (Projekt "ratanet").
  4. Warten, bis SSC die Artefakt-Verarbeitung abgeschlossen hat.
  5. Issues abfragen und als Report (Konsole + CSV) ausgeben.

Voraussetzungen:
  - Fortify SCA lokal installiert (sourceanalyzer im PATH) – nur fuer Schritt 1.
  - Ein SSC-Token mit passendem Scope (z. B. "UnifiedLoginToken"
    oder ein CI-Token).  Wird per Umgebungsvariable uebergeben.
  - certificate.pem (das SSC-Serverzertifikat) liegt neben diesem Skript.
"""

import os
import sys
import csv
import time
import base64
import argparse
import subprocess

import requests
from requests.adapters import HTTPAdapter, Retry

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------
# Basis-URL der SSC-Instanz (Port 8443, /ssc/ Kontextpfad).
SSC_BASE_URL = os.environ.get("SSC_URL", "https://fortify.example.com:8443/ssc/")
API_URL = SSC_BASE_URL.rstrip("/") + "/api/v1"

# Token NICHT im Code hartkodieren -> aus der Umgebung lesen.
#   export FORTIFY_TOKEN="dein-token"
SSC_TOKEN = os.environ.get("FORTIFY_TOKEN")

# Projekt / Projektversion in SSC.
PROJECT_NAME = os.environ.get("FORTIFY_PROJECT", "ratanet")
PROJECT_VERSION = os.environ.get("FORTIFY_VERSION", "main")

# Serverzertifikat fuer die TLS-Verifizierung (liegt neben dem Skript).
CERT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certificate.pem")

# Verify-Wert fuer requests: Pfad zum Zertifikat, sonst True (System-CAs).
VERIFY = CERT_PATH if os.path.exists(CERT_PATH) else True


# ---------------------------------------------------------------------------
# HTTP-Session mit Token-Auth
# ---------------------------------------------------------------------------
def make_session() -> requests.Session:
    if not SSC_TOKEN:
        sys.exit("FEHLER: Umgebungsvariable FORTIFY_TOKEN ist nicht gesetzt.")

    session = requests.Session()
    session.verify = VERIFY
    # SSC erwartet den Header  "Authorization: FortifyToken <base64-token>".
    # Manche Token-Typen sind bereits base64, manche nicht -> wir kodieren,
    # falls noetig (SSC akzeptiert den base64-kodierten Wert).
    token = SSC_TOKEN
    try:
        base64.b64decode(token, validate=True)
        encoded = token  # schon base64
    except Exception:
        encoded = base64.b64encode(token.encode()).decode()

    session.headers.update({
        "Authorization": f"FortifyToken {encoded}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    })

    # Robuste Retries bei kurzzeitigen Serverfehlern.
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    return session


# ---------------------------------------------------------------------------
# 1) Lokaler SCA-Scan des Repos -> .fpr
# ---------------------------------------------------------------------------
def run_sca_scan(repo_path: str, build_id: str, fpr_out: str) -> str:
    """Scannt das komplette Repo mit Fortify SCA und schreibt eine .fpr."""
    if not _tool_exists("sourceanalyzer"):
        sys.exit("FEHLER: 'sourceanalyzer' (Fortify SCA) ist nicht im PATH installiert.")

    print(f"[SCA] Bereinige alte Build-Session '{build_id}' ...")
    subprocess.run(["sourceanalyzer", "-b", build_id, "-clean"], check=True)

    print(f"[SCA] Translate: scanne komplettes Repo unter {repo_path} ...")
    subprocess.run(["sourceanalyzer", "-b", build_id, repo_path], check=True)

    print("[SCA] Scan laeuft – das kann je nach Repo-Groesse dauern ...")
    subprocess.run(
        ["sourceanalyzer", "-b", build_id, "-scan", "-f", fpr_out],
        check=True,
    )
    print(f"[SCA] Fertig. Ergebnis: {fpr_out}")
    return fpr_out


def _tool_exists(name: str) -> bool:
    from shutil import which
    return which(name) is not None


# ---------------------------------------------------------------------------
# 2/3) Projektversion finden + .fpr hochladen
# ---------------------------------------------------------------------------
def get_project_version_id(session: requests.Session, project: str, version: str) -> int:
    """Sucht die projectVersionId fuer Projekt/Version."""
    resp = session.get(
        f"{API_URL}/projectVersions",
        params={"q": f'project.name:"{project}" and name:"{version}"', "limit": 1},
    )
    resp.raise_for_status()
    data = resp.json().get("data", [])
    if not data:
        sys.exit(f"FEHLER: Projektversion '{project}:{version}' in SSC nicht gefunden.")
    pv_id = data[0]["id"]
    print(f"[SSC] Projektversion gefunden: {project}:{version} (id={pv_id})")
    return pv_id


def upload_fpr(session: requests.Session, pv_id: int, fpr_path: str) -> None:
    """Laedt die .fpr auf die Projektversion hoch (Multipart-Upload mit fileToken)."""
    if not os.path.exists(fpr_path):
        sys.exit(f"FEHLER: FPR-Datei nicht gefunden: {fpr_path}")

    # SSC verlangt fuer File-Uploads einen kurzlebigen Upload-Token.
    tok = session.post(
        f"{API_URL}/fileTokens",
        json={"fileTokenType": "UPLOAD"},
    )
    tok.raise_for_status()
    file_token = tok.json()["data"]["token"]

    print(f"[SSC] Lade {os.path.basename(fpr_path)} hoch ...")
    # Der Upload-Endpunkt liegt ausserhalb von /api/v1 und ist form-/multipart-basiert.
    upload_url = SSC_BASE_URL.rstrip("/") + "/upload/resultFileUpload.html"
    with open(fpr_path, "rb") as fh:
        # Eigener Header ohne JSON-Content-Type fuer den Multipart-Request.
        resp = requests.post(
            upload_url,
            params={"mat": file_token, "engineType": "SCA"},
            data={"entityId": pv_id},
            files={"file": (os.path.basename(fpr_path), fh, "application/octet-stream")},
            verify=VERIFY,
        )
    resp.raise_for_status()
    print("[SSC] Upload akzeptiert.")


# ---------------------------------------------------------------------------
# 4) Auf Verarbeitung warten
# ---------------------------------------------------------------------------
def wait_for_processing(session: requests.Session, pv_id: int, timeout: int = 1800) -> None:
    """Pollt die Artefaktliste, bis der Upload den Status PROCESS_COMPLETE hat."""
    print("[SSC] Warte auf Verarbeitung des Artefakts ...")
    start = time.time()
    while time.time() - start < timeout:
        resp = session.get(
            f"{API_URL}/projectVersions/{pv_id}/artifacts",
            params={"limit": 1},
        )
        resp.raise_for_status()
        artifacts = resp.json().get("data", [])
        if artifacts:
            status = artifacts[0].get("status")
            print(f"    Status: {status}")
            if status == "PROCESS_COMPLETE":
                print("[SSC] Verarbeitung abgeschlossen.")
                return
            if status in ("ERROR_PROCESSING", "REQUIRE_AUTH"):
                sys.exit(f"FEHLER: Artefakt-Verarbeitung fehlgeschlagen (Status {status}).")
        time.sleep(10)
    sys.exit("FEHLER: Timeout beim Warten auf die Artefakt-Verarbeitung.")


# ---------------------------------------------------------------------------
# 5) Issues abfragen + Report erzeugen
# ---------------------------------------------------------------------------
def fetch_issues(session: requests.Session, pv_id: int) -> list:
    """Holt alle Issues der Projektversion (paginiert)."""
    issues, start, page = [], 0, 200
    while True:
        resp = session.get(
            f"{API_URL}/projectVersions/{pv_id}/issues",
            params={"start": start, "limit": page, "showhidden": "false",
                    "showremoved": "false", "showsuppressed": "false"},
        )
        resp.raise_for_status()
        batch = resp.json().get("data", [])
        issues.extend(batch)
        if len(batch) < page:
            break
        start += page
    return issues


def write_report(issues: list, csv_path: str) -> None:
    """Gibt eine Severity-Zusammenfassung aus und schreibt alle Issues als CSV."""
    severities = {}
    for it in issues:
        sev = it.get("friority") or it.get("severity") or "Unbekannt"
        severities[sev] = severities.get(sev, 0) + 1

    print("\n================ SECURITY REPORT: ratanet ================")
    print(f"Gefundene Issues gesamt: {len(issues)}")
    for sev in ("Critical", "High", "Medium", "Low"):
        if sev in severities:
            print(f"  {sev:<8}: {severities[sev]}")
    for sev, n in severities.items():
        if sev not in ("Critical", "High", "Medium", "Low"):
            print(f"  {sev:<8}: {n}")
    print("==========================================================\n")

    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["Severity", "Kategorie", "Datei", "Zeile", "Analyzer", "issueInstanceId"])
        for it in issues:
            writer.writerow([
                it.get("friority", ""),
                it.get("issueName", ""),
                it.get("fullFileName", it.get("primaryLocation", "")),
                it.get("lineNumber", ""),
                it.get("analyzer", ""),
                it.get("issueInstanceId", ""),
            ])
    print(f"[Report] Detaillierter CSV-Report: {csv_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Fortify SSC Repo-Scan + Report")
    parser.add_argument("--repo", default=".", help="Pfad zum Repository (Default: aktuelles Verzeichnis)")
    parser.add_argument("--build-id", default="ratanet", help="SCA Build-ID")
    parser.add_argument("--fpr", default="ratanet.fpr", help="Ausgabedatei fuer den Scan")
    parser.add_argument("--csv", default="ratanet_security_report.csv", help="CSV-Report-Pfad")
    parser.add_argument("--skip-scan", action="store_true",
                        help="Vorhandene .fpr nutzen, lokalen SCA-Scan ueberspringen")
    args = parser.parse_args()

    session = make_session()

    # 1) Lokaler Scan (optional ueberspringbar)
    if not args.skip_scan:
        run_sca_scan(args.repo, args.build_id, args.fpr)

    # 2) Projektversion ermitteln
    pv_id = get_project_version_id(session, PROJECT_NAME, PROJECT_VERSION)

    # 3) Upload + 4) Warten
    upload_fpr(session, pv_id, args.fpr)
    wait_for_processing(session, pv_id)

    # 5) Issues -> Report
    issues = fetch_issues(session, pv_id)
    write_report(issues, args.csv)


if __name__ == "__main__":
    main()
