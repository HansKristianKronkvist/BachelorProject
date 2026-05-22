"""
rule_engine.py — Loads vulnerability rules from YAML and runs them against source code.
"""

import re
from pathlib import Path

import yaml

from .parser import CodeParser


class RuleEngine:
    def __init__(self, rules_path: str = "rules/rules.yaml"):
        self.rules_path = Path(rules_path)
        self.rules = self._load_rules()
        self.parser = CodeParser()

    def _load_rules(self) -> list[dict]:
        """Load rules from the YAML file."""
        if not self.rules_path.exists():
            print(f"⚠️  Warning: Rules file not found at {self.rules_path}")
            return []
        with open(self.rules_path, "r") as f:
            data = yaml.safe_load(f)
        return data.get("rules", [])

    def scan(self, source: str, language: str, file_path: str) -> list[dict]:
        """
        Scan source code against all applicable rules.
        Returns a list of finding dicts.
        """
        findings = []

        for rule in self.rules:
            # Skip rules not applicable to this language
            rule_languages = rule.get("languages", [])
            if rule_languages and language not in rule_languages:
                continue

            # Skip disabled rules
            if not rule.get("enabled", True):
                continue

            # Use AST check if available and language is Python
            if rule.get("ast_check") and language == "python":
                matches = self.parser.find_ast_matches(source, rule)
            else:
                pattern = rule.get("pattern")
                if not pattern:
                    continue
                flags = re.IGNORECASE if rule.get("case_insensitive", True) else 0
                matches = self.parser.find_pattern_matches(source, pattern, flags)

            for match in matches:
                findings.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule.get("severity", "MEDIUM"),
                    "description": rule.get("description", ""),
                    "remediation": rule.get("remediation", ""),
                    "cwe": rule.get("cwe"),
                    "cwe_url": rule.get("cwe_url"),
                    "file_path": file_path,
                    "line_number": match["line_number"],
                    "line_content": match["line_content"],
                    "match_text": match.get("match_text", ""),
                })

        return findings
