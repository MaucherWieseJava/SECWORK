from collections import Counter
from datetime import datetime


SEVERITY_COLORS = {
    "CRITICAL": "#d32f2f",
    "HIGH":     "#f57c00",
    "MEDIUM":   "#f9a825",
    "LOW":      "#388e3c",
    "N/A":      "#757575",
}

MAX_DESC_LENGTH = 300


def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity.upper(), SEVERITY_COLORS["N/A"])
    return (
        f'<span style="background:{color};color:#fff;padding:4px 12px;'
        f'border-radius:4px;font-size:13px;font-weight:bold;display:inline-block;">'
        f'{severity.upper()}</span>'
    )


def _truncate(text: str, max_len: int = MAX_DESC_LENGTH) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len].rsplit(" ", 1)[0] + " ..."


def _section(title: str, content: str, subtitle: str = "") -> str:
    subtitle_html = ""
    if subtitle:
        subtitle_html = f'<div style="font-size:13px;color:#888;margin-top:4px;">{subtitle}</div>'
    return f"""
    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:40px;">
        <tr>
            <td style="padding-bottom:10px;border-bottom:3px solid #1a237e;">
                <h2 style="margin:0;color:#1a237e;font-size:22px;font-weight:bold;">{title}</h2>
                {subtitle_html}
            </td>
        </tr>
        <tr>
            <td style="padding-top:16px;">
                {content}
            </td>
        </tr>
    </table>
    """


def _cve_card(vuln: dict, is_in_kev: bool = False) -> str:
    score_text = f"CVSS: <strong>{vuln['cvss_score']}</strong>" if vuln["cvss_score"] else "CVSS: N/A"

    kev_badge = ""
    if is_in_kev:
        kev_badge = ('&nbsp;&nbsp;<span style="background:#e65100;color:#fff;padding:4px 10px;'
                     'border-radius:4px;font-size:11px;font-weight:bold;display:inline-block;">'
                     'ACTIVELY EXPLOITED</span>')

    refs_html = ""
    if vuln.get("references"):
        links = " &nbsp;|&nbsp; ".join(
            f'<a href="{r}" style="color:#1565c0;text-decoration:none;">{r[:70]}{"..." if len(r) > 70 else ""}</a>'
            for r in vuln["references"]
        )
        refs_html = f"""
        <tr>
            <td style="padding-top:8px;font-size:13px;color:#666;">
                {links}
            </td>
        </tr>"""

    border_color = "#d32f2f" if vuln["severity"] == "CRITICAL" else "#1a237e"

    return f"""
    <table width="100%" cellpadding="0" cellspacing="0"
           style="background:#f5f5f5;border-left:5px solid {border_color};margin-bottom:14px;">
        <tr>
            <td style="padding:16px 20px;">
                <table width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                        <td style="font-size:16px;font-weight:bold;color:#1a237e;padding-bottom:8px;">
                            {vuln['id']}
                            &nbsp;&nbsp;{_severity_badge(vuln['severity'])}
                            &nbsp;&nbsp;<span style="font-size:14px;color:#555;">{score_text}</span>
                            {kev_badge}
                        </td>
                    </tr>
                    <tr>
                        <td style="font-size:15px;color:#333;line-height:1.5;">
                            {_truncate(vuln['description'])}
                        </td>
                    </tr>
                    {refs_html}
                </table>
            </td>
        </tr>
    </table>
    """


def _kev_card(vuln: dict) -> str:
    return f"""
    <table width="100%" cellpadding="0" cellspacing="0"
           style="background:#fff3e0;border-left:5px solid #e65100;margin-bottom:14px;">
        <tr>
            <td style="padding:16px 20px;">
                <table width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                        <td style="font-size:16px;font-weight:bold;color:#e65100;padding-bottom:6px;">
                            {vuln['id']}
                            &nbsp;&nbsp;<span style="font-size:15px;font-weight:normal;color:#333;">{vuln['vendor']} &mdash; {vuln['product']}</span>
                        </td>
                    </tr>
                    <tr>
                        <td style="font-size:15px;color:#333;line-height:1.5;padding-bottom:8px;">
                            {_truncate(vuln['description'])}
                        </td>
                    </tr>
                    <tr>
                        <td style="font-size:14px;color:#666;">
                            Required action: <strong>{vuln['action']}</strong> &nbsp;&bull;&nbsp; Due: <strong>{vuln['due_date']}</strong>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
    """


def _victim_card(victim: dict) -> str:
    url_html = ""
    if victim.get("website"):
        url_html = f'<a href="https://{victim["website"]}" style="color:#b71c1c;font-size:13px;text-decoration:none;">{victim["website"]} &rarr;</a>'

    desc_html = ""
    if victim.get("description"):
        desc_html = f"""
                    <tr>
                        <td colspan="2" style="font-size:14px;color:#555;padding-top:6px;line-height:1.4;">
                            {_truncate(victim["description"], 200)}
                        </td>
                    </tr>"""

    group_html = ""
    if victim.get("group"):
        group_html = f'&nbsp;&nbsp;<span style="font-size:13px;background:#b71c1c;color:#fff;padding:3px 10px;display:inline-block;">{victim["group"]}</span>'

    meta_parts = []
    if victim.get("country"):
        meta_parts.append(f'Country: <strong>{victim["country"]}</strong>')
    if victim.get("sector"):
        meta_parts.append(f'Sector: <strong>{victim["sector"]}</strong>')
    meta_parts.append(f'Discovered: {victim["discovered"]}')
    meta_html = " &nbsp;&bull;&nbsp; ".join(meta_parts)

    return f"""
    <table width="100%" cellpadding="0" cellspacing="0"
           style="background:#fce4ec;border-left:5px solid #b71c1c;margin-bottom:14px;">
        <tr>
            <td style="padding:16px 20px;">
                <table width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                        <td style="font-size:16px;font-weight:bold;color:#b71c1c;">
                            {victim['victim']}{group_html}
                        </td>
                        <td align="right" style="vertical-align:top;">{url_html}</td>
                    </tr>
                    <tr>
                        <td colspan="2" style="font-size:14px;color:#555;padding-top:6px;">
                            {meta_html}
                        </td>
                    </tr>
                    {desc_html}
                </table>
            </td>
        </tr>
    </table>
    """


def _group_header(group_name: str, count: int) -> str:
    return f"""
    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:10px;margin-top:20px;">
        <tr>
            <td style="padding:8px 14px;background:#b71c1c;">
                <span style="color:#fff;font-size:15px;font-weight:bold;letter-spacing:1px;">
                    {group_name.upper()}
                </span>
                <span style="color:#ffcdd2;font-size:13px;margin-left:8px;">
                    &mdash; {count} victim(s)
                </span>
            </td>
        </tr>
    </table>
    """


def build_html_report(
    date: datetime,
    nvd_cves: list[dict],
    kev_vulns: list[dict],
    ransomware_victims: list[dict],
) -> str:
    date_str = date.strftime("%B %d, %Y")

    # Cross-reference: which CVE IDs are also in KEV
    kev_ids = {v["id"] for v in kev_vulns}

    # --- Severity breakdown for stats ---
    crit_count = len(nvd_cves)
    highest_score = max((v["cvss_score"] or 0 for v in nvd_cves), default=0)

    # --- NVD CVEs section ---
    if nvd_cves:
        cve_cards = "".join(_cve_card(v, is_in_kev=v["id"] in kev_ids) for v in nvd_cves)
        cve_subtitle = f"Sorted by CVSS score &nbsp;&bull;&nbsp; {crit_count} Critical &nbsp;&bull;&nbsp; Highest: {highest_score}"
    else:
        cve_cards = '<p style="color:#888;font-size:15px;">No new critical CVEs found for this date.</p>'
        cve_subtitle = ""

    # --- CISA KEV section ---
    if kev_vulns:
        kev_cards = "".join(_kev_card(v) for v in kev_vulns)
        kev_subtitle = "Sorted by due date (most urgent first)"
    else:
        kev_cards = '<p style="color:#888;font-size:15px;">No new CISA KEV entries for this date.</p>'
        kev_subtitle = ""

    # --- Ransomware section (grouped by threat actor) ---
    if ransomware_victims:
        group_counts = Counter(v["group"] for v in ransomware_victims)
        country_counts = Counter(v["country"] for v in ransomware_victims if v.get("country"))
        top_countries = ", ".join(f'{c} ({n})' for c, n in country_counts.most_common(5))

        victim_html_parts = []
        current_group = None
        for v in ransomware_victims:
            if v["group"] != current_group:
                current_group = v["group"]
                victim_html_parts.append(_group_header(current_group, group_counts[current_group]))
            victim_html_parts.append(_victim_card(v))
        victim_cards = "".join(victim_html_parts)

        num_groups = len(group_counts)
        victim_summary = f"{len(ransomware_victims)} victim(s) reported"
        victim_subtitle = f"{num_groups} active group(s) &nbsp;&bull;&nbsp; Top targets: {top_countries}"
    else:
        victim_cards = '<p style="color:#888;font-size:15px;">No ransomware victims reported for this date.</p>'
        victim_summary = "No victims reported"
        victim_subtitle = ""

    # --- Stats bar ---
    stats_bar = f"""
    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:36px;">
        <tr>
            <td width="32%" style="background:#e8eaf6;padding:20px 16px;text-align:center;">
                <div style="font-size:36px;font-weight:bold;color:#1a237e;">{len(nvd_cves)}</div>
                <div style="font-size:14px;color:#555;margin-top:4px;">New CVEs</div>
                <div style="font-size:12px;color:#888;margin-top:2px;">{crit_count} Critical</div>
            </td>
            <td width="2%"></td>
            <td width="32%" style="background:#fff3e0;padding:20px 16px;text-align:center;">
                <div style="font-size:36px;font-weight:bold;color:#e65100;">{len(kev_vulns)}</div>
                <div style="font-size:14px;color:#555;margin-top:4px;">CISA KEV Additions</div>
                <div style="font-size:12px;color:#888;margin-top:2px;">Actively Exploited</div>
            </td>
            <td width="2%"></td>
            <td width="32%" style="background:#fce4ec;padding:20px 16px;text-align:center;">
                <div style="font-size:36px;font-weight:bold;color:#b71c1c;">{len(ransomware_victims)}</div>
                <div style="font-size:14px;color:#555;margin-top:4px;">Ransomware Victims</div>
                <div style="font-size:12px;color:#888;margin-top:2px;">{num_groups if ransomware_victims else 0} Active Group(s)</div>
            </td>
        </tr>
    </table>
    """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CISO TEAM - Daily Cybersecurity Briefing | {date_str}</title>
</head>
<body style="margin:0;padding:0;background:#e8eaed;font-family:Arial,Helvetica,sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#e8eaed;">
        <tr><td align="center" style="padding:32px 16px;">
            <table width="900" cellpadding="0" cellspacing="0"
                   style="max-width:900px;width:100%;background:#ffffff;">

                <!-- Header -->
                <tr>
                    <td style="background:#1a237e;padding:36px 40px;text-align:center;">
                        <div style="font-size:32px;font-weight:bold;color:#ffffff;
                                    letter-spacing:3px;">CISO TEAM</div>
                        <div style="font-size:16px;color:#9fa8da;margin-top:6px;">
                            Daily Cybersecurity Briefing
                        </div>
                        <div style="font-size:20px;color:#ffffff;margin-top:10px;
                                    font-weight:bold;">{date_str}</div>
                    </td>
                </tr>

                <!-- Body -->
                <tr>
                    <td style="padding:40px;">
                        {stats_bar}
                        {_section("New Vulnerabilities (NVD)", cve_cards, cve_subtitle)}
                        {_section("CISA Known Exploited Vulnerabilities", kev_cards, kev_subtitle)}
                        {_section(f"Ransomware Victims &mdash; {victim_summary}", victim_cards, victim_subtitle)}
                    </td>
                </tr>

                <!-- Footer -->
                <tr>
                    <td style="background:#1a237e;padding:20px 40px;text-align:center;">
                        <div style="font-size:13px;color:#9fa8da;">
                            Generated by Adrian St&ouml;tzler &bull; {date_str} &bull;
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
