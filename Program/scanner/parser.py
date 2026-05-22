"""
parser.py — Language detection and source code parsing.
Uses Python AST for .py files, regex fallback for other languages.
"""

import ast
import re
from pathlib import Path


LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".sh": "shell",
    ".bash": "shell",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".env": "env",
    ".tf": "terraform",
}


class CodeParser:
    def detect_language(self, file_path: Path) -> str | None:
        """Detect programming language from file extension."""
        return LANGUAGE_MAP.get(file_path.suffix.lower())

    def parse_python_ast(self, source: str) -> ast.AST | None:
        """Parse Python source into an AST. Returns None on failure."""
        try:
            return ast.parse(source)
        except SyntaxError:
            return None

    def extract_lines(self, source: str) -> list[str]:
        """Split source into lines (1-indexed via enumerate offset)."""
        return source.splitlines()

    def find_pattern_matches(
        self, source: str, pattern: str, flags: int = re.IGNORECASE
    ) -> list[dict]:
        """
        Find all regex pattern matches in source code.
        Returns list of dicts with line_number, line_content, match.
        """
        matches = []
        lines = self.extract_lines(source)
        compiled = re.compile(pattern, flags)

        for line_no, line in enumerate(lines, start=1):
            for match in compiled.finditer(line):
                matches.append({
                    "line_number": line_no,
                    "line_content": line.strip(),
                    "match_text": match.group(0),
                    "col_start": match.start(),
                })
        return matches

    def find_ast_matches(self, source: str, rule: dict) -> list[dict]:
        """
        Use Python AST to find dangerous function calls or patterns.
        Only applies to Python source files.
        Supported ast_check types: 'call', 'import', 'attribute'
        """
        tree = self.parse_python_ast(source)
        if not tree:
            return self.find_pattern_matches(source, rule["pattern"])

        matches = []
        ast_check = rule.get("ast_check")

        if ast_check == "call":
            # Look for dangerous function calls e.g. eval(), exec()
            target_names = rule.get("ast_targets", [])
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = None
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr

                    if func_name in target_names:
                        lines = self.extract_lines(source)
                        line_content = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                        matches.append({
                            "line_number": node.lineno,
                            "line_content": line_content.strip(),
                            "match_text": func_name,
                            "col_start": node.col_offset,
                        })

        elif ast_check == "import":
            # Look for dangerous imports e.g. import pickle
            target_modules = rule.get("ast_targets", [])
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = []
                    if isinstance(node, ast.Import):
                        names = [alias.name for alias in node.names]
                    elif isinstance(node, ast.ImportFrom):
                        names = [node.module] if node.module else []

                    for name in names:
                        if any(t in name for t in target_modules):
                            lines = self.extract_lines(source)
                            line_content = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                            matches.append({
                                "line_number": node.lineno,
                                "line_content": line_content.strip(),
                                "match_text": name,
                                "col_start": node.col_offset,
                            })
        else:
            # Fallback to regex
            matches = self.find_pattern_matches(source, rule["pattern"])

        return matches
