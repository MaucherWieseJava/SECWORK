import os
import smtplib
import argparse
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from vulnerabilities import fetch_nvd_cves, fetch_cisa_kev_recent
from ransomware import fetch_ransomware_victims
from formatter import build_html_report


def send_email(html: str, subject: str, recipients: list[str]) -> None:
    """Send the HTML report via SMTP. Configure via environment variables."""
    smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", 587))
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASS", "")
    sender = os.environ.get("SMTP_FROM", smtp_user)

    if not smtp_user or not smtp_pass:
        print("[mail] SMTP_USER / SMTP_PASS not set — skipping email delivery.")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.ehlo()
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(sender, recipients, msg.as_string())

    print(f"[mail] Report sent to: {', '.join(recipients)}")


def save_html(html: str, date: datetime) -> str:
    """Save the HTML report to a file and return the path."""
    filename = f"phil_briefing_{date.strftime('%Y-%m-%d')}.html"
    output_path = os.path.join(os.path.dirname(__file__), filename)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phil — Daily Cybersecurity Briefing Generator"
    )
    parser.add_argument(
        "--date",
        type=str,
        default=None,
        help="Target date in YYYY-MM-DD format (default: today)",
    )
    parser.add_argument(
        "--send",
        nargs="+",
        metavar="EMAIL",
        default=[],
        help="Send the report to one or more email addresses",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not save the HTML report to disk",
    )
    parser.add_argument(
        "--max-cves",
        type=int,
        default=20,
        help="Maximum number of CVEs to fetch from NVD (default: 20)",
    )
    args = parser.parse_args()

    # Resolve target date
    if args.date:
        target_date = datetime.strptime(args.date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    else:
        target_date = datetime.now(tz=timezone.utc)

    date_str = target_date.strftime("%Y-%m-%d")
    print(f"[phil] Generating briefing for {date_str} ...")

    # Fetch data
    print("[phil] Fetching NVD CVEs ...")
    nvd_cves = fetch_nvd_cves(target_date, max_results=args.max_cves)
    print(f"       {len(nvd_cves)} CVE(s) found.")

    print("[phil] Fetching CISA KEV additions ...")
    kev_vulns = fetch_cisa_kev_recent(target_date)
    print(f"       {len(kev_vulns)} KEV addition(s) found.")

    print("[phil] Fetching ransomware victims ...")
    victims = fetch_ransomware_victims(target_date)
    print(f"       {len(victims)} victim(s) found.")

    # Build HTML
    html = build_html_report(target_date, nvd_cves, kev_vulns, victims)

    # Save to disk
    if not args.no_save:
        path = save_html(html, target_date)
        print(f"[phil] Report saved to: {path}")

    # Send email
    if args.send:
        subject = f"Phil Cybersecurity Briefing — {date_str}"
        send_email(html, subject, args.send)

    print("[phil] Done.")


if __name__ == "__main__":
    main()