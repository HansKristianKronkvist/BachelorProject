"""
db_reporter.py — Terminal display for database queries: reports, history, stats.
"""

from datetime import datetime


SEVERITY_ICONS = {
    "CRITICAL": "🚨",
    "HIGH":     "❌",
    "MEDIUM":   "⚠️ ",
    "LOW":      "ℹ️ ",
    "INFO":     "💡",
}

SEVERITY_COLORS = {
    "CRITICAL": "\033[95m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[94m",
    "INFO":     "\033[96m",
}

STATUS_ICONS = {
    "open":          "🔴",
    "resolved":      "✅",
    "ignored":       "⏭️ ",
    "false_positive": "🚫",
    "passed":        "✅",
    "blocked":       "⛔",
    "running":       "⏳",
}

RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
GREEN = "\033[92m"
RED   = "\033[91m"


def _c(text, code): return f"{code}{text}{RESET}"
def _bold(t): return _c(t, BOLD)
def _dim(t):  return _c(t, DIM)
def _sev(text, severity): return _c(text, SEVERITY_COLORS.get(severity, ""))


def _short_date(iso: str) -> str:
    """Trim ISO timestamp to YYYY-MM-DD."""
    return iso[:10] if iso else "—"


def _truncate(text: str, width: int) -> str:
    if not text:
        return "—"
    return text if len(text) <= width else text[:width - 1] + "…"


# Stats Dashboard 

def print_stats(stats: dict) -> None:
    print()
    print(_bold("📊 Vulnerability Database — Summary"))
    print(_dim("━" * 62))

    # Totals
    print(f"\n  {'Total scans run':<22}: {_bold(str(stats['total_scans']))}")
    print(f"  {'Total findings':<22}: {_bold(str(stats['total_findings']))}")

    # By status
    by_status = stats.get("by_status", {})
    open_count     = by_status.get("open", 0)
    resolved_count = by_status.get("resolved", 0)
    ignored_count  = by_status.get("ignored", 0)
    fp_count       = by_status.get("false_positive", 0)

    print(f"\n  {'Status breakdown':<22}:")
    print(f"    {STATUS_ICONS['open']}  Open           : {_c(str(open_count), RED)}")
    print(f"    {STATUS_ICONS['resolved']}  Resolved       : {_c(str(resolved_count), GREEN)}")
    print(f"    {STATUS_ICONS['ignored']}  Ignored        : {str(ignored_count)}")
    print(f"    {STATUS_ICONS['false_positive']}  False positive : {str(fp_count)}")

    # Open by severity
    open_sev = stats.get("open_by_severity", {})
    if open_sev:
        print(f"\n  {'Open by severity':<22}:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = open_sev.get(sev, 0)
            if count:
                icon = SEVERITY_ICONS.get(sev, "")
                print(f"    {icon}  {sev:<10} : {_sev(str(count), sev)}")

    # Top rules
    top_rules = stats.get("top_vulnerable_rules", [])
    if top_rules:
        print(f"\n  {'Top open rules':<22}:")
        for r in top_rules:
            print(f"    • {_truncate(r['rule_id'], 30):<32} {r['count']} finding(s)")

    # Top files
    top_files = stats.get("top_vulnerable_files", [])
    if top_files:
        print(f"\n  {'Most affected files':<22}:")
        for f in top_files:
            print(f"    • {_truncate(f['file_path'], 40):<42} {f['count']} finding(s)")

    # Last scan
    last = stats.get("last_scan")
    if last:
        status_icon = STATUS_ICONS.get(last.get("status", ""), "")
        print(f"\n  {'Last scan':<22}: {_short_date(last.get('started_at'))}  "
              f"{status_icon} {last.get('status', '?')}  "
              f"({last.get('total_found', 0)} finding(s) in {last.get('files_scanned', 0)} file(s))")

    print(_dim("\n" + "━" * 62))


# Open Findings Report 

def print_findings_report(findings: list[dict], title: str = "Open Findings") -> None:
    print()
    print(_bold(f"🔍 {title}"))
    print(_dim("━" * 80))

    if not findings:
        print(f"\n  {_c('✅ No findings to display.', GREEN)}\n")
        print(_dim("━" * 80))
        return

    # Table header
    print(
        f"\n  {'ID':<5}  {'Sev':<9}  {'Rule':<26}  {'File':<28}  {'Line':<5}  {'Date':<11}  {'Status'}"
    )
    print(_dim(f"  {'─'*5}  {'─'*9}  {'─'*26}  {'─'*28}  {'─'*5}  {'─'*11}  {'─'*15}"))

    for f in findings:
        sev   = f.get("severity", "?")
        icon  = SEVERITY_ICONS.get(sev, " ")
        status_icon = STATUS_ICONS.get(f.get("status", "open"), "")
        print(
            f"  {str(f['id']):<5}  "
            f"{_sev(f'{icon} {sev:<7}', sev)}  "
            f"{_truncate(f.get('rule_id','?'), 26):<26}  "
            f"{_truncate(f.get('file_path','?'), 28):<28}  "
            f"{str(f.get('line_number','?')):<5}  "
            f"{_short_date(f.get('first_seen')):<11}  "
            f"{status_icon} {f.get('status','?')}"
        )

    print(_dim("\n" + "━" * 80))
    print(f"  {_bold(str(len(findings)))} finding(s) shown.\n")


# Single Finding Detail 

def print_finding_detail(finding: dict) -> None:
    sev = finding.get("severity", "UNKNOWN")
    icon = SEVERITY_ICONS.get(sev, "")
    status_icon = STATUS_ICONS.get(finding.get("status", "open"), "")

    print()
    print(_bold(f"🔎 Finding #{finding['id']} — {finding.get('rule_name', '?')}"))
    print(_dim("━" * 62))
    print(f"  {'Severity':<14}: {_sev(f'{icon} {sev}', sev)}")
    print(f"  {'Status':<14}: {status_icon} {finding.get('status', '?')}")
    print(f"  {'Rule ID':<14}: {finding.get('rule_id', '?')}")
    print(f"  {'File':<14}: {finding.get('file_path', '?')}")
    print(f"  {'Line':<14}: {finding.get('line_number', '?')}")

    if finding.get("line_content"):
        print(f"  {'Code':<14}: {_c(finding['line_content'][:70], SEVERITY_COLORS.get(sev,''))}")

    print(f"  {'Description':<14}: {finding.get('description', '—')}")
    print(f"  {'Remediation':<14}: {finding.get('remediation', '—')}")

    if finding.get("cwe"):
        cwe_line = finding["cwe"]
        if finding.get("cwe_url"):
            cwe_line += f"  →  {finding['cwe_url']}"
        print(f"  {'CWE':<14}: {cwe_line}")

    print(f"  {'First seen':<14}: {_short_date(finding.get('first_seen'))}")

    if finding.get("resolved_at"):
        print(f"  {'Resolved':<14}: {_short_date(finding.get('resolved_at'))}")

    if finding.get("notes"):
        print(f"  {'Notes':<14}: {finding['notes']}")

    cves = finding.get("cves", [])
    if cves:
        print(f"\n  {_bold('📡 Linked CVEs:')}")
        for i, cve in enumerate(cves):
            prefix = "  └──" if i == len(cves) - 1 else "  ├──"
            score = f"[{cve.get('severity','?')}, {cve.get('score','?')}]"
            print(f"{prefix} {_c(cve.get('cve_id','?'), RED)}  {_dim(score)}")
            desc = (cve.get("description") or "")[:70]
            print(f"  {'   ' if i == len(cves)-1 else '│  '}    {desc}...")
            print(f"  {'   ' if i == len(cves)-1 else '│  '}    {_dim('🔗 ' + (cve.get('url') or ''))}")

    print(_dim("━" * 62) + "\n")


# Scan History 

def print_scan_history(scans: list[dict]) -> None:
    print()
    print(_bold("📋 Scan History"))
    print(_dim("━" * 80))

    if not scans:
        print(f"\n  No scans recorded yet.\n")
        print(_dim("━" * 80))
        return

    print(
        f"\n  {'ID':<5}  {'Date':<12}  {'Branch':<18}  {'Commit':<8}  "
        f"{'Status':<10}  {'Found':<6}  {'Files'}"
    )
    print(_dim(f"  {'─'*5}  {'─'*12}  {'─'*18}  {'─'*8}  {'─'*10}  {'─'*6}  {'─'*5}"))

    for s in scans:
        status = s.get("status", "?")
        status_icon = STATUS_ICONS.get(status, "")
        found = s.get("total_found", 0)
        found_str = _c(str(found), RED) if found > 0 else _c("0", GREEN)

        print(
            f"  {str(s['id']):<5}  "
            f"{_short_date(s.get('started_at')):<12}  "
            f"{_truncate(s.get('branch','?'), 18):<18}  "
            f"{(s.get('commit_hash') or '?')[:8]:<8}  "
            f"{status_icon} {status:<8}  "
            f"{found_str:<6}  "
            f"{s.get('files_scanned', '?')}"
        )

    print(_dim("\n" + "━" * 80) + "\n")
