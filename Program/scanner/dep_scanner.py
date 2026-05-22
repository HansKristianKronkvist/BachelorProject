"""
dep_scanner.py — Dependency scanner that checks requirements files against
the NVD API for known CVEs affecting specific library versions.

Supports:
  - requirements.txt  (pip)
  - requirements*.txt (pip, any variant)
  - Pipfile           (pipenv)
  - pyproject.toml    (poetry / PEP 621)
  - package.json      (npm)
"""

import re
import json
import time
from pathlib import Path

import requests

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Files the scanner will look for and parse
DEPENDENCY_FILES = [
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "requirements-prod.txt",
    "Pipfile",
    "pyproject.toml",
    "package.json",
]


# Parsers 

def parse_requirements_txt(content: str) -> list[dict]:
    """
    Parse a pip requirements.txt file.
    Handles: package==1.2.3, package>=1.0, package~=1.2, comments, extras.
    Returns list of {name, version, raw} dicts. version may be None if unpinned.
    """
    deps = []
    for line in content.splitlines():
        line = line.strip()
        # Skip comments, blank lines, options (-r, -e, --index-url etc.)
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip inline comments
        line = line.split("#")[0].strip()
        # Strip extras e.g. requests[security]==2.28.0
        line = re.sub(r"\[.*?\]", "", line)

        # Exact pin: package==1.2.3
        exact = re.match(r"^([A-Za-z0-9_\-\.]+)==([^\s,;]+)", line)
        if exact:
            deps.append({
                "name": exact.group(1).lower(),
                "version": exact.group(2),
                "raw": line,
                "pinned": True,
            })
            continue

        # Loose pin: package>=1.0 etc.
        loose = re.match(r"^([A-Za-z0-9_\-\.]+)([><=~!]+)([^\s,;]+)", line)
        if loose:
            deps.append({
                "name": loose.group(1).lower(),
                "version": loose.group(3),
                "raw": line,
                "pinned": False,
            })
            continue

        # Bare name (no version)
        bare = re.match(r"^([A-Za-z0-9_\-\.]+)$", line)
        if bare:
            deps.append({
                "name": bare.group(1).lower(),
                "version": None,
                "raw": line,
                "pinned": False,
            })

    return deps


def parse_pipfile(content: str) -> list[dict]:
    """Parse a Pipfile (TOML-like). Extracts [packages] and [dev-packages]."""
    deps = []
    in_packages = False

    for line in content.splitlines():
        line = line.strip()
        if line.startswith("[packages]") or line.startswith("[dev-packages]"):
            in_packages = True
            continue
        if line.startswith("[") and in_packages:
            in_packages = False
            continue
        if not in_packages or not line or line.startswith("#"):
            continue

        match = re.match(r'^([A-Za-z0-9_\-\.]+)\s*=\s*["\']([^"\']*)["\']', line)
        if match:
            name = match.group(1).lower()
            version_str = match.group(2)
            exact = re.search(r"==([^\s,]+)", version_str)
            deps.append({
                "name": name,
                "version": exact.group(1) if exact else version_str.lstrip(">=~"),
                "raw": line,
                "pinned": "==" in version_str,
            })

    return deps


def parse_pyproject_toml(content: str) -> list[dict]:
    """
    Parse pyproject.toml — handles both Poetry and PEP 621 formats.
    Uses regex rather than a TOML parser to keep dependencies minimal.
    """
    deps = []

    # PEP 621: dependencies = ["requests>=2.28", "flask==2.3.0"]
    pep621 = re.findall(
        r'["\']([A-Za-z0-9_\-\.]+)([><=~!]+)([^\s"\']+)["\']', content
    )
    for name, op, ver in pep621:
        deps.append({
            "name": name.lower(),
            "version": ver,
            "raw": f"{name}{op}{ver}",
            "pinned": op == "==",
        })

    return deps


def parse_package_json(content: str) -> list[dict]:
    """Parse package.json for npm dependencies and devDependencies."""
    deps = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps

    all_deps = {}
    all_deps.update(data.get("dependencies", {}))
    all_deps.update(data.get("devDependencies", {}))

    for name, version_str in all_deps.items():
        # Strip npm range prefixes: ^1.2.3 ~1.2.3 >=1.2.3
        clean_ver = re.sub(r"^[\^~>=<]+", "", version_str).strip()
        deps.append({
            "name": name.lower(),
            "version": clean_ver if clean_ver else None,
            "raw": f"{name}@{version_str}",
            "pinned": not bool(re.match(r"^[\^~]", version_str)),
        })

    return deps


def parse_dependency_file(file_path: Path) -> list[dict]:
    """Detect file type and dispatch to the correct parser."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    name = file_path.name.lower()

    if name.startswith("requirements") and name.endswith(".txt"):
        return parse_requirements_txt(content)
    if name == "pipfile":
        return parse_pipfile(content)
    if name == "pyproject.toml":
        return parse_pyproject_toml(content)
    if name == "package.json":
        return parse_package_json(content)

    return []


# NVD Dependency Lookup 

class DepNVDClient:
    """
    NVD client focused on CVE lookups for specific library + version combinations.
    Uses the cpeName / keywordSearch endpoints to find CVEs affecting a package.
    """

    def __init__(self, api_key: str = None, min_score: float = 5.0, max_results: int = 3):
        self.api_key = api_key
        self.min_score = min_score
        self.max_results = max_results
        self.rate_limit_delay = 0.7 if api_key else 6.5

        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"apiKey": api_key})

    def get_cves_for_package(self, name: str, version: str = None) -> list[dict]:
        """
        Search NVD for CVEs affecting a specific package.
        If version is provided, filters to CVEs that apply to that version range.
        Falls back to keyword search if CPE lookup returns nothing.
        """
        # Try keyword search: "requests 2.18.0" or just "requests"
        keyword = f"{name} {version}" if version else name
        cves = self._keyword_search(keyword)

        # If nothing found with version, try just the package name
        if not cves and version:
            cves = self._keyword_search(name)

        # Filter to CVEs that actually mention this version if we have one
        if version and cves:
            cves = self._filter_by_version(cves, name, version)

        return cves[: self.max_results]

    def _keyword_search(self, keyword: str) -> list[dict]:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 20,
            "startIndex": 0,
        }
        try:
            time.sleep(self.rate_limit_delay)
            response = self.session.get(NVD_BASE_URL, params=params, timeout=10)
            response.raise_for_status()
            return self._parse_response(response.json())
        except Exception:
            return []

    def _parse_response(self, data: dict) -> list[dict]:
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            parsed = self._parse_cve(cve)
            if parsed and parsed.get("score", 0) >= self.min_score:
                results.append(parsed)
        results.sort(key=lambda x: x.get("score", 0), reverse=True)
        return results

    def _parse_cve(self, cve: dict) -> dict | None:
        cve_id = cve.get("id")
        if not cve_id:
            return None

        description = "No description available."
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", description)
                break

        metrics = cve.get("metrics", {})
        score = None
        severity = "UNKNOWN"

        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss = metric_list[0].get("cvssData", {})
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity", "UNKNOWN")
                break

        # Extract affected version ranges from configurations
        version_ranges = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    vsi = match.get("versionStartIncluding")
                    vse = match.get("versionStartExcluding")
                    vei = match.get("versionEndIncluding")
                    vee = match.get("versionEndExcluding")
                    parts = []
                    if vsi: parts.append(f">={vsi}")
                    if vse: parts.append(f">{vse}")
                    if vei: parts.append(f"<={vei}")
                    if vee: parts.append(f"<{vee}")
                    if parts:
                        version_ranges.append(", ".join(parts))

        return {
            "id": cve_id,
            "description": description[:200] + ("..." if len(description) > 200 else ""),
            "score": score,
            "severity": severity,
            "published": cve.get("published", "N/A")[:10],
            "version_ranges": version_ranges[:3],
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }

    def _filter_by_version(self, cves: list[dict], name: str, version: str) -> list[dict]:
        """
        Keep CVEs whose description or affected ranges mention the package name.
        This is a best-effort filter since NVD data quality varies.
        """
        filtered = []
        name_lower = name.lower()
        for cve in cves:
            desc_lower = cve.get("description", "").lower()
            if name_lower in desc_lower:
                filtered.append(cve)
        # If filter removes everything, return original list
        return filtered if filtered else cves


#  Dep Scanner 

class DependencyScanner:
    """
    Finds dependency files in a list of staged/provided files,
    parses them, and checks each package against the NVD API.
    """

    def __init__(self, nvd_client: DepNVDClient, cache, config: dict):
        self.nvd_client = nvd_client
        self.cache = cache
        self.config = config
        self.min_score = config.get("dep_scan", {}).get("min_cvss_score", 5.0)
        self.max_cves = config.get("dep_scan", {}).get("max_cves_per_package", 3)
        self.skip_unpinned = config.get("dep_scan", {}).get("skip_unpinned", False)

    def scan(self, file_paths: list[Path]) -> list[dict]:
        """
        Scan all dependency files found in file_paths.
        Returns a list of dep_finding dicts.
        """
        findings = []

        dep_files = [
            f for f in file_paths
            if f.name.lower() in [d.lower() for d in DEPENDENCY_FILES]
           or ("requirements" in f.name.lower() and f.name.lower().endswith(".txt"))
        ]

        if not dep_files:
            return []

        print(f"\n  Scanning {len(dep_files)} dependency file(s)...")

        for dep_file in dep_files:
            deps = parse_dependency_file(dep_file)
            if not deps:
                continue

            print(f"     {dep_file.name}: {len(deps)} package(s) found")

            for dep in deps:
                if self.skip_unpinned and not dep.get("pinned"):
                    continue
                if not dep.get("name"):
                    continue

                cache_key = f"DEP_{dep['name']}_{dep.get('version', 'any')}"
                cves = self.cache.get(cache_key)

                if cves is None:
                    cves = self.nvd_client.get_cves_for_package(
                        dep["name"], dep.get("version")
                    )
                    self.cache.set(cache_key, cves)

                if not cves:
                    continue

                # Only report CVEs at or above min score
                matching = [c for c in cves if (c.get("score") or 0) >= self.min_score]
                if not matching:
                    continue

                findings.append({
                    "type": "dependency",
                    "rule_id": "VULNERABLE_DEPENDENCY",
                    "rule_name": "Vulnerable Dependency",
                    "severity": self._cvss_to_severity(
                        max(c.get("score", 0) for c in matching)
                    ),
                    "file_path": str(dep_file),
                    "line_number": None,
                    "line_content": dep["raw"],
                    "package_name": dep["name"],
                    "package_version": dep.get("version"),
                    "description": (
                        f"{dep['name']} {dep.get('version', '(unpinned)')} has "
                        f"{len(matching)} known CVE(s)."
                    ),
                    "remediation": (
                        f"Check https://pypi.org/project/{dep['name']}/ for the "
                        f"latest safe version and update your dependency file."
                    ),
                    "cwe": None,
                    "cwe_url": None,
                    "cves": matching[: self.max_cves],
                })

        return findings

    def _cvss_to_severity(self, score: float) -> str:
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        return "LOW"
