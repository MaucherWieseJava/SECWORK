import argparse
import sys
import os
from datetime import datetime, timezone
import requests
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import seaborn as sns
import pandas as pd

NEXUS_IQ_URL = "https://nexusiq.your-company.com"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_CERT = os.path.join(BASE_DIR, "certificate.pem")
CA_BUNDLE = os.path.join(BASE_DIR, "ca-bundle.crt")
SLA_DAYS = 90
THREAT_MIN = 7
STAGES = ["build", "stage-release", "operate"]
OUTPUT_DIR = os.path.join(BASE_DIR, "nexus_reports")


def get_session(api_key):
    session = requests.Session()
    session.cert = CLIENT_CERT
    if os.path.isfile(CA_BUNDLE):
        session.verify = CA_BUNDLE
    else:
        session.verify = True
    session.headers.update({
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json"
    })
    return session


def get_organizations(session):
    resp = session.get(f"{NEXUS_IQ_URL}/api/v2/organizations")
    resp.raise_for_status()
    return resp.json().get("organizations", [])


def get_applications(session):
    resp = session.get(f"{NEXUS_IQ_URL}/api/v2/applications")
    resp.raise_for_status()
    return resp.json().get("applications", [])


def get_policy_violations(session, app_public_id, stage):
    resp = session.get(
        f"{NEXUS_IQ_URL}/api/v2/reports/applications/{app_public_id}/policy",
        params={"stage": stage}
    )
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    data = resp.json()
    violations = []
    for component in data.get("components", []):
        for violation in component.get("violations", []):
            if violation.get("policyThreatCategory") != "SECURITY":
                continue
            threat_level = violation.get("policyThreatLevel", 0)
            if threat_level < THREAT_MIN:
                continue
            waived = violation.get("waived", False)
            waiver_info = violation.get("grandfathered", False) or waived
            first_found = violation.get("openTime")
            if first_found:
                found_dt = datetime.fromisoformat(first_found.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - found_dt).days
            else:
                found_dt = None
                age_days = 0

            comp_id = component.get("componentIdentifier", {}).get("coordinates", {})
            comp_name = comp_id.get("artifactId", component.get("displayName", "unknown"))
            comp_version = comp_id.get("version", "N/A")
            comp_group = comp_id.get("groupId", "N/A")

            violations.append({
                "app": app_public_id,
                "stage": stage,
                "component": comp_name,
                "group": comp_group,
                "version": comp_version,
                "policy": violation.get("policyName", "N/A"),
                "threat_level": threat_level,
                "waived": waiver_info,
                "first_found": first_found,
                "age_days": age_days,
                "out_of_sla": age_days > SLA_DAYS,
                "constraint": violation.get("constraintName", "N/A"),
            })
    return violations


def collect_all_violations(session):
    apps = get_applications(session)
    print(f"Found {len(apps)} application(s)")
    all_violations = []
    for app in apps:
        pub_id = app.get("publicId", "")
        app_name = app.get("name", pub_id)
        for stage in ["build", "operate"]:
            print(f"  [{app_name}] stage={stage}...")
            violations = get_policy_violations(session, pub_id, stage)
            for v in violations:
                v["app_name"] = app_name
            all_violations.extend(violations)
    print(f"\nTotal security violations (threat >= {THREAT_MIN}): {len(all_violations)}")
    return all_violations


def setup_style():
    sns.set_theme(style="whitegrid", palette="muted")
    plt.rcParams.update({"figure.dpi": 150, "savefig.bbox": "tight"})


def plot_violations_by_stage(df, stage, output_dir):
    stage_df = df[df["stage"] == stage]
    if stage_df.empty:
        print(f"  No data for stage '{stage}', skipping chart.")
        return
    counts = stage_df.groupby("app_name").size().sort_values(ascending=True)
    if len(counts) > 30:
        counts = counts.tail(30)

    fig, ax = plt.subplots(figsize=(12, max(4, len(counts) * 0.4)))
    colors = sns.color_palette("Reds_r", n_colors=len(counts))
    counts.plot.barh(ax=ax, color=colors)
    ax.set_title(f"Security Violations by Application - {stage.upper()} Stage\n(Threat Level {THREAT_MIN}-10)", fontsize=13)
    ax.set_xlabel("Number of Violations")
    ax.set_ylabel("")
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    plt.savefig(os.path.join(output_dir, f"violations_{stage}.png"))
    plt.close()
    print(f"  Saved: violations_{stage}.png")


def plot_threat_distribution(df, stage, output_dir):
    stage_df = df[df["stage"] == stage]
    if stage_df.empty:
        return
    fig, ax = plt.subplots(figsize=(8, 5))
    threat_counts = stage_df["threat_level"].value_counts().sort_index()
    palette = {7: "#f39c12", 8: "#e67e22", 9: "#e74c3c", 10: "#8e0000"}
    colors = [palette.get(t, "#999") for t in threat_counts.index]
    threat_counts.plot.bar(ax=ax, color=colors)
    ax.set_title(f"Threat Level Distribution - {stage.upper()} Stage", fontsize=13)
    ax.set_xlabel("Threat Level")
    ax.set_ylabel("Count")
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    plt.savefig(os.path.join(output_dir, f"threat_dist_{stage}.png"))
    plt.close()
    print(f"  Saved: threat_dist_{stage}.png")


def plot_out_of_sla(df, output_dir):
    sla_df = df[df["out_of_sla"]]
    if sla_df.empty:
        print("  No out-of-SLA violations found, skipping chart.")
        return
    counts = sla_df.groupby(["app_name", "stage"]).size().unstack(fill_value=0)
    if len(counts) > 30:
        counts = counts.loc[counts.sum(axis=1).nlargest(30).index]
    counts = counts.sort_values(by=counts.columns.tolist(), ascending=True)

    fig, ax = plt.subplots(figsize=(12, max(4, len(counts) * 0.4)))
    counts.plot.barh(ax=ax, stacked=True, color={"build": "#e74c3c", "operate": "#2c3e50"})
    ax.set_title(f"Violations Out of SLA (>{SLA_DAYS} days)\nby Application and Stage", fontsize=13)
    ax.set_xlabel("Number of Violations")
    ax.set_ylabel("")
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.legend(title="Stage")
    plt.savefig(os.path.join(output_dir, "out_of_sla.png"))
    plt.close()
    print("  Saved: out_of_sla.png")


def plot_out_of_sla_not_waived(df, output_dir):
    filtered = df[(df["out_of_sla"]) & (~df["waived"])]
    if filtered.empty:
        print("  No out-of-SLA + not-waived violations found, skipping chart.")
        return
    counts = filtered.groupby(["app_name", "stage"]).size().unstack(fill_value=0)
    if len(counts) > 30:
        counts = counts.loc[counts.sum(axis=1).nlargest(30).index]
    counts = counts.sort_values(by=counts.columns.tolist(), ascending=True)

    fig, ax = plt.subplots(figsize=(12, max(4, len(counts) * 0.4)))
    counts.plot.barh(ax=ax, stacked=True, color={"build": "#c0392b", "operate": "#1a252f"})
    ax.set_title(f"Out of SLA (>{SLA_DAYS} days) & NOT Waived\nby Application and Stage", fontsize=13)
    ax.set_xlabel("Number of Violations")
    ax.set_ylabel("")
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.legend(title="Stage")
    plt.savefig(os.path.join(output_dir, "out_of_sla_not_waived.png"))
    plt.close()
    print("  Saved: out_of_sla_not_waived.png")


def export_csv(df, output_dir):
    path = os.path.join(output_dir, "violations.csv")
    df.to_csv(path, index=False)
    print(f"  Saved: violations.csv")


def main():
    parser = argparse.ArgumentParser(description="Sonatype Nexus IQ SCA violation extractor")
    parser.add_argument("--api-key", required=True, help="Nexus IQ API token")
    args = parser.parse_args()

    if not os.path.isfile(CLIENT_CERT):
        print(f"Client certificate not found: {CLIENT_CERT}")
        sys.exit(1)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    session = get_session(args.api_key)

    print(f"Connecting to {NEXUS_IQ_URL}")
    violations = collect_all_violations(session)

    if not violations:
        print("No violations matched the criteria.")
        sys.exit(0)

    df = pd.DataFrame(violations)

    total = len(df)
    out_sla = df["out_of_sla"].sum()
    waived = df["waived"].sum()
    out_sla_not_waived = len(df[(df["out_of_sla"]) & (~df["waived"])])

    print(f"\n{'='*50}")
    print(f"  Total violations (threat {THREAT_MIN}-10):  {total}")
    print(f"  Build stage:                       {len(df[df['stage']=='build'])}")
    print(f"  Operate stage:                     {len(df[df['stage']=='operate'])}")
    print(f"  Out of SLA (>{SLA_DAYS} days):             {out_sla}")
    print(f"  Waived:                            {waived}")
    print(f"  Out of SLA & NOT waived:           {out_sla_not_waived}")
    print(f"{'='*50}\n")

    print("Generating visualizations...")
    setup_style()
    plot_violations_by_stage(df, "build", OUTPUT_DIR)
    plot_violations_by_stage(df, "operate", OUTPUT_DIR)
    plot_threat_distribution(df, "build", OUTPUT_DIR)
    plot_threat_distribution(df, "operate", OUTPUT_DIR)
    plot_out_of_sla(df, OUTPUT_DIR)
    plot_out_of_sla_not_waived(df, OUTPUT_DIR)
    export_csv(df, OUTPUT_DIR)

    print(f"\nAll outputs saved to: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()