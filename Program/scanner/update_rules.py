"""
update_rules.py — Enriches rules.yaml with latest CVE data from NVD.
Run manually or on a schedule to keep your rule set current.

Usage:
    python -m scanner.update_rules
    python -m scanner.main --update-rules
"""

import sys
import time
from pathlib import Path

import yaml

from .config import load_config
from .nvd_client import NVDClient


def update_rules(config_path: str = "scanner_config.yaml") -> None:
    config = load_config(config_path)
    rules_path = Path(config.get("rules_path", "rules/rules.yaml"))

    if not rules_path.exists():
        print(f"❌ Rules file not found: {rules_path}")
        sys.exit(1)

    nvd_cfg = config.get("nvd", {})
    if not nvd_cfg.get("enabled", True):
        print("ℹ: NVD integration is disabled in config. Skipping update.")
        return

    client = NVDClient(
        api_key=nvd_cfg.get("api_key"),
        max_results=nvd_cfg.get("max_cves_per_finding", 3),
        min_score=nvd_cfg.get("min_cvss_score", 7.0),
    )

    with open(rules_path) as f:
        data = yaml.safe_load(f)

    rules = data.get("rules", [])
    print(f"\n Updating {len(rules)} rules with NVD data...\n")

    updated = 0
    for rule in rules:
        cwe = rule.get("cwe")
        if not cwe:
            continue

        print(f"  Fetching CVEs for {rule['id']} ({cwe})...", end=" ", flush=True)
        cves = client.get_cves_for_cwe(cwe)

        if cves:
            rule["example_cves"] = [
                {
                    "id": c["id"],
                    "score": c["score"],
                    "severity": c["severity"],
                    "published": c["published"],
                    "description": c["description"][:120],
                }
                for c in cves
            ]
            print(f" {len(cves)} CVE(s) found.")
            updated += 1
        else:
            print("— none found above threshold.")

        time.sleep(0.5)  # Extra buffer between rules

    # Write enriched rules back
    with open(rules_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    print(f"\n Rules updated: {updated}/{len(rules)} enriched with CVE data.")
    print(f" Saved to: {rules_path}\n")


if __name__ == "__main__":
    update_rules()
