from datetime import datetime


SEVERITY_COLORS = {
    "CRITICAL": "#d32f2f",
    "HIGH":     "#f57c00",
    "MEDIUM":   "#f9a825",
    "LOW":      "#388e3c",
    "N/A":      "#757575",
}


def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity.upper(), SEVERITY_COLORS["N/A"])
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:11px;font-weight:bold;">'
        f'{severity.upper()}</span>'
    )


def _section(title: str, content: str) -> str:
    return f"""
    <div style="margin-bottom:32px;">
        <h2 style="color:#1a237e;border-bottom:2px solid #1a237e;
                   padding-bottom:6px;font-size:20px;">{title}</h2>
        {content}
    </div>
    """


def _cve_card(vuln: dict) -> str:
    score_text = f"CVSS: <strong>{vuln['cvss_score']}</strong>" if vuln["cvss_score"] else "CVSS: N/A"
    refs_html = ""
    if vuln.get("references"):
        links = " | ".join(
            f'<a href="{r}" style="color:#1565c0;">{r[:60]}{"..." if len(r) > 60 else ""}</a>'
            for r in vuln["references"]
        )
        refs_html = f'<div style="margin-top:6px;font-size:12px;">Refs: {links}</div>'

    return f"""
    <div style="background:#f5f5f5;border-left:4px solid #1a237e;
                padding:12px 16px;margin-bottom:12px;border-radius:4px;">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
            <strong style="font-size:14px;color:#1a237e;">{vuln['id']}</strong>
            {_severity_badge(vuln['severity'])}
            <span style="font-size:12px;color:#555;">{score_text}</span>
        </div>
        <div style="font-size:13px;color:#333;">{vuln['description']}</div>
        {refs_html}
    </div>
    """


def _kev_card(vuln: dict) -> str:
    return f"""
    <div style="background:#fff3e0;border-left:4px solid #e65100;
                padding:12px 16px;margin-bottom:12px;border-radius:4px;">
        <div style="margin-bottom:4px;">
            <strong style="color:#e65100;">{vuln['id']}</strong>
            &nbsp;|&nbsp;
            <span style="font-size:13px;">{vuln['vendor']} &mdash; {vuln['product']}</span>
        </div>
        <div style="font-size:13px;color:#333;margin-bottom:4px;">{vuln['description']}</div>
        <div style="font-size:12px;color:#555;">
            Required action: {vuln['action']} &nbsp;&bull;&nbsp; Due: {vuln['due_date']}
        </div>
    </div>
    """


def _victim_card(victim: dict) -> str:
    url_html = ""
    if victim.get("url"):
        url_html = f'<a href="{victim["url"]}" style="color:#b71c1c;font-size:12px;">Source</a>'

    desc_html = ""
    if victim.get("description"):
        desc_html = f'<div style="font-size:12px;color:#555;margin-top:4px;">{victim["description"][:200]}{"..." if len(victim["description"]) > 200 else ""}</div>'

    return f"""
    <div style="background:#fce4ec;border-left:4px solid #b71c1c;
                padding:12px 16px;margin-bottom:12px;border-radius:4px;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;">
            <div>
                <strong style="font-size:14px;color:#b71c1c;">{victim['victim']}</strong>
                &nbsp;
                <span style="font-size:12px;background:#b71c1c;color:#fff;
                             padding:1px 6px;border-radius:3px;">{victim['group']}</span>
            </div>
            {url_html}
        </div>
        <div style="font-size:12px;color:#555;margin-top:4px;">
            Country: <strong>{victim['country']}</strong>
            &nbsp;&bull;&nbsp; Sector: <strong>{victim['sector']}</strong>
            &nbsp;&bull;&nbsp; Discovered: {victim['discovered']}
        </div>
        {desc_html}
    </div>
    """


def build_html_report(
    date: datetime,
    nvd_cves: list[dict],
    kev_vulns: list[dict],
    ransomware_victims: list[dict],
) -> str:
    date_str = date.strftime("%B %d, %Y")

    # --- NVD CVEs section ---
    if nvd_cves:
        cve_cards = "".join(_cve_card(v) for v in nvd_cves)
    else:
        cve_cards = '<p style="color:#888;">No new CVEs found for this date.</p>'

    # --- CISA KEV section ---
    if kev_vulns:
        kev_cards = "".join(_kev_card(v) for v in kev_vulns)
    else:
        kev_cards = '<p style="color:#888;">No new CISA KEV entries for this date.</p>'

    # --- Ransomware section ---
    if ransomware_victims:
        victim_cards = "".join(_victim_card(v) for v in ransomware_victims)
        victim_summary = f"{len(ransomware_victims)} victim(s) reported"
    else:
        victim_cards = '<p style="color:#888;">No ransomware victims reported for this date.</p>'
        victim_summary = "No victims reported"

    stats_bar = f"""
    <div style="display:flex;gap:16px;margin-bottom:32px;flex-wrap:wrap;">
        <div style="flex:1;min-width:140px;background:#e8eaf6;border-radius:8px;
                    padding:16px;text-align:center;">
            <div style="font-size:28px;font-weight:bold;color:#1a237e;">{len(nvd_cves)}</div>
            <div style="font-size:12px;color:#555;">New CVEs (NVD)</div>
        </div>
        <div style="flex:1;min-width:140px;background:#fff3e0;border-radius:8px;
                    padding:16px;text-align:center;">
            <div style="font-size:28px;font-weight:bold;color:#e65100;">{len(kev_vulns)}</div>
            <div style="font-size:12px;color:#555;">CISA KEV Additions</div>
        </div>
        <div style="flex:1;min-width:140px;background:#fce4ec;border-radius:8px;
                    padding:16px;text-align:center;">
            <div style="font-size:28px;font-weight:bold;color:#b71c1c;">{len(ransomware_victims)}</div>
            <div style="font-size:12px;color:#555;">Ransomware Victims</div>
        </div>
    </div>
    """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phil - Daily Cybersecurity Briefing | {date_str}</title>
</head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:Arial,Helvetica,sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f2f5;">
        <tr><td align="center" style="padding:24px 16px;">
            <table width="680" cellpadding="0" cellspacing="0"
                   style="max-width:680px;width:100%;background:#ffffff;
                          border-radius:8px;overflow:hidden;
                          box-shadow:0 2px 8px rgba(0,0,0,0.1);">

                <!-- Header -->
                <tr>
                    <td style="background:linear-gradient(135deg,#1a237e,#283593);
                               padding:28px 32px;text-align:center;">
                        <div style="font-size:28px;font-weight:bold;color:#ffffff;
                                    letter-spacing:2px;">PHIL</div>
                        <div style="font-size:14px;color:#9fa8da;margin-top:4px;">
                            Daily Cybersecurity Briefing
                        </div>
                        <div style="font-size:18px;color:#ffffff;margin-top:8px;
                                    font-weight:bold;">{date_str}</div>
                    </td>
                </tr>

                <!-- Body -->
                <tr>
                    <td style="padding:32px;">
                        {stats_bar}
                        {_section("New Vulnerabilities (NVD)", cve_cards)}
                        {_section("CISA Known Exploited Vulnerabilities", kev_cards)}
                        {_section(f"Ransomware Victims &mdash; {victim_summary}", victim_cards)}
                    </td>
                </tr>

                <!-- Footer -->
                <tr>
                    <td style="background:#1a237e;padding:16px 32px;text-align:center;">
                        <div style="font-size:11px;color:#9fa8da;">
                            Generated by Phil &bull; {date_str} &bull;
                            Sources: NVD, CISA KEV, ransomware.live
                        </div>
                    </td>
                </tr>

            </table>
        </td></tr>
    </table>
</body>
</html>"""

    return html