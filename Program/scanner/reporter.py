"""
reporter.py — Formats and prints the scan report to the terminal.
Handles both code-pattern findings (CWE-based) and dependency findings (CVE-based).
Also supports JSON output for CI/CD pipelines.
"""

import json
from pathlib import Path
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

RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"


class Reporter:
    def __init__(self, config: dict):
        self.config = config
        self.use_color = config.get("color_output", True)
        self.json_output_path = config.get("json_output_path")

    def _color(self, text: str, color_code: str) -> str:
        if not self.use_color:
            return text
        return f"{color_code}{text}{RESET}"

    def _bold(self, text: str) -> str:
        return self._color(text, BOLD)

    def _dim(self, text: str) -> str:
        return self._color(text, DIM)

    def _sev(self, text: str, severity: str) -> str:
        return self._color(text, SEVERITY_COLORS.get(severity, ""))

    def print_report(
        self,
        scanned_files: list[Path],
        findings: list[dict],
        dep_findings: list[dict] = None,
    ) -> None:
        """Print the full scan report — code findings then dependency findings."""
        dep_findings = dep_findings or []
        all_findings = findings + dep_findings

        self._print_header(scanned_files)

        if not all_findings:
            print(f"\n  {self._color('✅ No vulnerabilities found!', chr(27) + '[92m')}\n")
            self._print_footer([], [])
            return

        # ── Code pattern findings (CWE-based) ──
        if findings:
            by_file: dict[str, list] = {}
            for f in findings:
                by_file.setdefault(f["file_path"], []).append(f)
            for file_path, file_findings in by_file.items():
                self._print_file_section(file_path, file_findings)

        # ── Dependency findings (CVE-based) ──
        if dep_findings:
            self._print_dep_section(dep_findings)

        self._print_footer(findings, dep_findings)

        if self.json_output_path:
            self._write_json(findings, dep_findings)

    def _print_header(self, scanned_files: list[Path]) -> None:
        print()
        print(self._bold("🔍 Pre-Commit Security Scanner"))
        print(self._dim("━" * 62))
        print(self._dim(f"  Scanning {len(scanned_files)} staged file(s)..."))
        print(self._dim("━" * 62))

    # Code findings 

    def _print_file_section(self, file_path: str, findings: list[dict]) -> None:
        print(f"\n  📄 {self._bold(file_path)}")
        print(self._dim("  " + "─" * 58))
        for finding in findings:
            self._print_finding(finding)

    def _print_finding(self, finding: dict) -> None:
        severity = finding.get("severity", "MEDIUM")
        icon = SEVERITY_ICONS.get(severity, "⚠️ ")
        color = SEVERITY_COLORS.get(severity, "")

        print()
        print(f"  {icon}  {self._color(severity, color)}  —  {self._bold(finding['rule_name'])}")
        print(f"     {self._dim('Rule ID:')}  {finding['rule_id']}")
        print(f"     {self._dim('Location:')} Line {finding['line_number']}")

        if finding.get("line_content"):
            snippet = finding["line_content"][:80]
            print(f"     {self._dim('Code:')}     {self._color(snippet, chr(27) + '[33m')}")

        if finding.get("description"):
            print(f"     {self._dim('Detail:')}   {finding['description']}")

        if finding.get("remediation"):
            print(f"     {self._dim('Fix:')}      {finding['remediation']}")

        if finding.get("cwe"):
            cwe_line = finding["cwe"]
            if finding.get("cwe_url"):
                cwe_line += f"  →  {self._dim(finding['cwe_url'])}"
            print(f"     {self._dim('CWE:')}      {cwe_line}")

        cves = finding.get("cves", [])
        if cves:
            print(f"\n     {self._bold('📡 Related CVEs from NVD:')}")
            for i, cve in enumerate(cves):
                prefix = "     └──" if i == len(cves) - 1 else "     ├──"
                score_str = f"[{cve['severity']}, {cve['score']}]" if cve.get("score") else ""
                print(f"{prefix} {self._color(cve['id'], chr(27) + '[91m')}  {self._dim(score_str)}")
                desc = (cve.get("description") or "")[:70]
                cont = "   " if i == len(cves) - 1 else "│  "
                print(f"     {cont}    {desc}...")
                print(f"     {cont}    {self._dim('🔗 ' + cve['url'])}")

    # Dependency findings 

    def _print_dep_section(self, dep_findings: list[dict]) -> None:
        print(f"\n  📦 {self._bold('Dependency Vulnerabilities (CVE-based)')}")
        print(self._dim("  " + "─" * 58))

        for dep in dep_findings:
            severity = dep.get("severity", "MEDIUM")
            icon = SEVERITY_ICONS.get(severity, "⚠️ ")
            color = SEVERITY_COLORS.get(severity, "")
            pkg = dep.get("package_name", "?")
            ver = dep.get("package_version", "unpinned")

            print()
            print(
                f"  {icon}  {self._color(severity, color)}  —  "
                f"{self._bold(pkg)} {self._dim(f'v{ver}')}"
            )
            print(f"     {self._dim('File:')}     {dep.get('file_path', '?')}")
            print(f"     {self._dim('Entry:')}    {dep.get('line_content', '?')}")
            print(f"     {self._dim('Detail:')}   {dep.get('description', '')}")
            print(f"     {self._dim('Fix:')}      {dep.get('remediation', '')}")

            cves = dep.get("cves", [])
            if cves:
                print(f"\n     {self._bold('📡 CVEs affecting this package:')}")
                for i, cve in enumerate(cves):
                    prefix = "     └──" if i == len(cves) - 1 else "     ├──"
                    score_str = f"[{cve.get('severity','?')}, {cve.get('score','?')}]"
                    print(
                        f"{prefix} {self._color(cve['id'], chr(27) + '[91m')}  "
                        f"{self._dim(score_str)}"
                    )
                    cont = "   " if i == len(cves) - 1 else "│  "
                    desc = (cve.get("description") or "")[:70]
                    print(f"     {cont}    {desc}...")

                    # Show affected version ranges if available
                    ranges = cve.get("version_ranges", [])
                    if ranges:
                        print(f"     {cont}    {self._dim('Affects: ' + ', '.join(ranges[:2]))}")

                    print(f"     {cont}    {self._dim('🔗 ' + cve['url'])}")

    # Footer 

    def _print_footer(self, findings: list[dict], dep_findings: list[dict]) -> None:
        all_findings = findings + dep_findings
        print()
        print(self._dim("━" * 62))

        if not all_findings:
            print(f"  {self._bold('Result:')} Clean — commit may proceed.\n")
            return

        # Count by severity across both finding types
        counts: dict[str, int] = {}
        for f in all_findings:
            s = f.get("severity", "MEDIUM")
            counts[s] = counts.get(s, 0) + 1

        summary_parts = [
            f"{self._color(sev, SEVERITY_COLORS.get(sev, ''))} × {count}"
            for sev, count in sorted(
                counts.items(),
                key=lambda x: list(SEVERITY_COLORS).index(x[0]) if x[0] in SEVERITY_COLORS else 0,
                reverse=True,
            )
        ]

        code_count = len(findings)
        dep_count = len(dep_findings)
        breakdown = []
        if code_count: breakdown.append(f"{code_count} code")
        if dep_count:  breakdown.append(f"{dep_count} dependency")
        breakdown_str = " + ".join(breakdown)

        print(
            f"  {self._bold('Found:')}  {len(all_findings)} issue(s) "
            f"({breakdown_str})  —  {',  '.join(summary_parts)}"
        )

        threshold = self.config.get("severity_threshold", "HIGH")
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        threshold_idx = severity_order.index(threshold)
        blocking = [
            f for f in all_findings
            if severity_order.index(f.get("severity", "INFO")) >= threshold_idx
        ]

        if blocking:
            print(
                f"  {self._color(self._bold('⛔ Commit BLOCKED.'), chr(27) + '[91m')} "
                f"Resolve {self._bold(threshold)}+ findings first.\n"
            )
        else:
            print(
                f"  {self._color('✅ Commit allowed', chr(27) + '[92m')} "
                f"(no findings at or above {threshold} threshold).\n"
            )

    def _write_json(self, findings: list[dict], dep_findings: list[dict]) -> None:
        output = {
            "scanned_at": datetime.now().isoformat(),
            "total_findings": len(findings) + len(dep_findings),
            "code_findings": len(findings),
            "dependency_findings": len(dep_findings),
            "findings": findings,
            "dependency_findings_detail": dep_findings,
        }
        Path(self.json_output_path).write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(f" JSON report written to: {self.json_output_path}\n")
