#!/usr/bin/env python3
"""
Pre-Commit Security Scanner — Main Entry Point

Usage:
  python -m scanner.main                          # Scan staged files (normal pre-commit run)
  python -m scanner.main --files src/app.py       # Scan specific files
  python -m scanner.main --report                 # Show all open findings from DB
  python -m scanner.main --report --severity HIGH # Filter by severity
  python -m scanner.main --dep-report             # Show dependency vulnerability report
  python -m scanner.main --history                # Show recent scan history
  python -m scanner.main --history --limit 20     # Show last 20 scans
  python -m scanner.main --stats                  # Show vulnerability stats dashboard
  python -m scanner.main --detail 42              # Show full detail for finding #42
  python -m scanner.main --resolve 42             # Mark finding #42 as resolved
  python -m scanner.main --ignore 42              # Mark finding #42 as ignored
  python -m scanner.main --fp 42                  # Mark as false positive
  python -m scanner.main --search "config.py"     # Search findings by keyword
  python -m scanner.main --update-rules           # Enrich rules.yaml with NVD CVE data
"""

import sys
import argparse
from pathlib import Path

from .git_utils import get_staged_files, get_repo_root, get_current_branch, get_latest_commit_hash
from .rule_engine import RuleEngine
from .parser import CodeParser
from .nvd_client import NVDClient
from .cache import CVECache
from .reporter import Reporter
from .config import load_config
from .dep_scanner import DependencyScanner, DepNVDClient
from .db import (
    init_db, create_scan, finish_scan, save_finding, save_dep_finding,
    get_open_findings, get_all_findings, get_scan_history, get_dep_findings,
    get_finding_by_id, get_stats, update_finding_status, search_findings,
    update_dep_finding_status,
)
from .db_reporter import (
    print_stats, print_findings_report, print_finding_detail,
    print_scan_history,
)


#  Scan

def run_scan(config_path: str = "scanner_config.yaml", files: list = None) -> int:
    """
    Run the full security scan:
      1. Code pattern scan (CWE-based) against all staged source files
      2. Dependency scan (CVE-based) against any staged requirements/package files
    Saves all findings to the database.
    Returns exit code: 0 = clean, 1 = blocking issues found.
    """
    config = load_config(config_path)

    # Get files to scan
    if files:
        staged_files = [Path(f) for f in files]
    else:
        staged_files = get_staged_files()

    if not staged_files:
        print("✅ No staged files to scan.")
        return 0

    # Initialize DB and create scan record
    init_db()
    repo   = str(get_repo_root() or Path.cwd())
    branch = get_current_branch()
    commit = get_latest_commit_hash()
    scan_id = create_scan(repo, branch, commit)

    # Shared cache (used by both code scanner and dep scanner)
    cache = CVECache(ttl_hours=config.get("nvd", {}).get("cache_ttl_hours", 24))

    nvd_cfg     = config.get("nvd", {})
    nvd_enabled = nvd_cfg.get("enabled", True)
    api_key     = nvd_cfg.get("api_key")

    # 1. Code pattern scan (CWE-based) 
    rule_engine = RuleEngine(config.get("rules_path", "rules/rules.yaml"))
    parser      = CodeParser()
    reporter    = Reporter(config)

    nvd_client = None
    if nvd_enabled:
        nvd_client = NVDClient(
            api_key=api_key,
            max_results=nvd_cfg.get("max_cves_per_finding", 3),
            min_score=nvd_cfg.get("min_cvss_score", 7.0),
        )

    all_findings = []
    ignore_files = config.get("ignore", {}).get("files", [])
    ignore_rules = set(config.get("ignore", {}).get("rules", []))

    for file_path in staged_files:
        if any(file_path.match(pat) for pat in ignore_files):
            continue
        if not file_path.exists():
            continue

        language = parser.detect_language(file_path)
        if not language:
            continue

        try:
            source_code = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        matches = rule_engine.scan(source_code, language, str(file_path))

        for match in matches:
            if match.get("rule_id") in ignore_rules:
                continue
            cve_data = []
            if nvd_client and match.get("cwe"):
                cve_data = cache.get_or_fetch(match["cwe"], nvd_client)
            match["cves"] = cve_data
            all_findings.append(match)

    # 2. Dependency scan (CVE-based) 
    dep_findings = []
    dep_cfg = config.get("dep_scan", {})

    if dep_cfg.get("enabled", True):
        dep_nvd = DepNVDClient(
            api_key=api_key,
            min_score=dep_cfg.get("min_cvss_score", 5.0),
            max_results=dep_cfg.get("max_cves_per_package", 3),
        )
        dep_scanner = DependencyScanner(dep_nvd, cache, config)
        dep_findings = dep_scanner.scan(staged_files)

    #  Report
    reporter.print_report(staged_files, all_findings, dep_findings)

    #  Persist to DB 
    for finding in all_findings:
        save_finding(scan_id, finding)
    for dep in dep_findings:
        save_dep_finding(scan_id, dep)

    total_saved = len(all_findings) + len(dep_findings)
    if total_saved:
        print(
            f"  {len(all_findings)} code + {len(dep_findings)} dependency "
            f"finding(s) saved to database (scan #{scan_id}).\n"
        )

    # Exit code 
    severity_order  = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    threshold       = config.get("severity_threshold", "HIGH")
    threshold_index = severity_order.index(threshold)

    blocking = [
        f for f in (all_findings + dep_findings)
        if severity_order.index(f.get("severity", "INFO")) >= threshold_index
    ]

    status = "blocked" if blocking else "passed"
    finish_scan(scan_id, status, len(all_findings), len(staged_files))

    return 1 if blocking else 0


# DB Commands 

def cmd_report(severity: str = None) -> None:
    init_db()
    findings = get_open_findings(severity=severity)
    title = f"Open Code Findings{f' — {severity}+' if severity else ''}"
    print_findings_report(findings, title=title)


def cmd_dep_report() -> None:
    init_db()
    deps = get_dep_findings(status="open")
    if not deps:
        print("\n  ✅ No open dependency findings.\n")
        return
    print(f"\n  Open Dependency Findings ({len(deps)})\n")
    print(f"  {'ID':<5}  {'Sev':<9}  {'Package':<22}  {'Version':<12}  {'CVEs':<30}  {'File'}")
    print(f"  {'─'*5}  {'─'*9}  {'─'*22}  {'─'*12}  {'─'*30}  {'─'*20}")
    import json
    for d in deps:
        sev   = d.get("severity", "?")
        cve_ids = json.loads(d.get("cve_ids") or "[]")
        cve_str = ", ".join(cve_ids[:2]) + ("..." if len(cve_ids) > 2 else "")
        print(
            f"  {str(d['id']):<5}  "
            f"{sev:<9}  "
            f"{(d.get('package_name') or '?')[:22]:<22}  "
            f"{(d.get('package_version') or 'unpinned')[:12]:<12}  "
            f"{cve_str[:30]:<30}  "
            f"{Path(d.get('file_path','?')).name}"
        )
    print()


def cmd_history(limit: int = 10) -> None:
    init_db()
    scans = get_scan_history(limit=limit)
    print_scan_history(scans)


def cmd_stats() -> None:
    init_db()
    stats = get_stats()
    print_stats(stats)


def cmd_detail(finding_id: int) -> None:
    init_db()
    finding = get_finding_by_id(finding_id)
    if not finding:
        print(f"❌ Finding #{finding_id} not found.")
        return
    print_finding_detail(finding)


def cmd_update_status(finding_id: int, status: str, note: str = None) -> None:
    init_db()
    finding = get_finding_by_id(finding_id)
    if not finding:
        print(f"❌ Finding #{finding_id} not found.")
        return
    try:
        updated = update_finding_status(finding_id, status, notes=note)
    except ValueError as e:
        print(f"❌ {e}"); return

    if updated:
        icons = {"resolved": "✅", "ignored": "⏭️ ", "false_positive": "🚫", "open": "🔴"}
        print(f"\n  {icons.get(status,'')} Finding #{finding_id} marked as {status}.")
        if note:
            print(f"  📝 Note: {note}")
        print()
    else:
        print(f"⚠️  Could not update finding #{finding_id}.")


def cmd_search(keyword: str) -> None:
    init_db()
    findings = search_findings(keyword)
    print_findings_report(findings, title=f"Search results for '{keyword}'")


#  CLI 

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Pre-Commit Security Scanner — Code patterns (CWE) + Dependencies (CVE)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--config", default="scanner_config.yaml", help="Path to config file")

    scan_group = p.add_argument_group("Scan")
    scan_group.add_argument("--files", nargs="*", help="Scan specific files instead of staged files")

    db_group = p.add_argument_group("Database — Read")
    db_group.add_argument("--stats",      action="store_true", help="Show full vulnerability dashboard")
    db_group.add_argument("--report",     action="store_true", help="Show open code findings")
    db_group.add_argument("--dep-report", action="store_true", help="Show open dependency findings")
    db_group.add_argument("--history",    action="store_true", help="Show scan history")
    db_group.add_argument("--detail",     type=int, metavar="ID", help="Full detail for a finding ID")
    db_group.add_argument("--search",     type=str, metavar="KEYWORD", help="Search findings by keyword")
    db_group.add_argument("--severity",   type=str, metavar="LEVEL", help="Filter by severity (with --report)")
    db_group.add_argument("--limit",      type=int, default=10, help="Limit rows (with --history)")

    write_group = p.add_argument_group("Database — Update")
    write_group.add_argument("--resolve", type=int, metavar="ID", help="Mark finding as resolved")
    write_group.add_argument("--ignore",  type=int, metavar="ID", help="Mark finding as ignored")
    write_group.add_argument("--fp",      type=int, metavar="ID", help="Mark as false positive")
    write_group.add_argument("--reopen",  type=int, metavar="ID", help="Re-open a finding")
    write_group.add_argument("--note",    type=str, help="Note when updating a finding status")

    p.add_argument("--update-rules", action="store_true", help="Enrich rules.yaml with NVD CVE data")
    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.stats:          cmd_stats(); return
    if args.report:         cmd_report(severity=args.severity); return
    if args.dep_report:     cmd_dep_report(); return
    if args.history:        cmd_history(limit=args.limit); return
    if args.detail:         cmd_detail(args.detail); return
    if args.search:         cmd_search(args.search); return
    if args.resolve:        cmd_update_status(args.resolve, "resolved",      note=args.note); return
    if args.ignore:         cmd_update_status(args.ignore,  "ignored",       note=args.note); return
    if args.fp:             cmd_update_status(args.fp,      "false_positive", note=args.note); return
    if args.reopen:         cmd_update_status(args.reopen,  "open",          note=args.note); return
    if args.update_rules:
        from .update_rules import update_rules
        update_rules(args.config); return

    exit_code = run_scan(config_path=args.config, files=args.files)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
