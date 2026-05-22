"""
nvd_client.py — Client for the NIST National Vulnerability Database (NVD) API v2.
API Docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import time
import requests


NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Severity order for filtering
SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class NVDClient:
    def __init__(
        self,
        api_key: str | None = None,
        max_results: int = 3,
        min_score: float = 7.0,
    ):
        self.api_key = api_key
        self.max_results = max_results
        self.min_score = min_score
        # NVD rate limits: 5 req/30s without key, 50 req/30s with key
        self.rate_limit_delay = 0.7 if api_key else 6.5

        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"apiKey": api_key})

    def get_cves_for_cwe(self, cwe_id: str) -> list[dict]:
        """
        Fetch CVEs linked to a given CWE ID (e.g. 'CWE-95').
        Returns a list of parsed CVE dicts, filtered by min CVSS score.
        Fails gracefully — returns [] on any error.
        """
        params = {
            "cweId": cwe_id,
            "resultsPerPage": min(self.max_results * 3, 20),  # Fetch extra to filter by score
            "startIndex": 0,
        }

        try:
            time.sleep(self.rate_limit_delay)
            response = self.session.get(NVD_BASE_URL, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            return self._parse_and_filter(data)

        except requests.exceptions.Timeout:
            print(f"  ⚠️  NVD API timeout for {cwe_id} — skipping CVE lookup.")
            return []
        except requests.exceptions.ConnectionError:
            print(f"  ⚠️  NVD API unreachable — skipping CVE lookup.")
            return []
        except requests.exceptions.HTTPError as e:
            print(f"  ⚠️  NVD API error ({e.response.status_code}) for {cwe_id}.")
            return []
        except Exception as e:
            print(f"  ⚠️  Unexpected NVD error for {cwe_id}: {e}")
            return []

    def get_cves_for_package(self, name: str, version: str = None) -> list[dict]:
        """
        Search NVD for CVEs affecting a specific package name and optional version.
        Used by the dependency scanner for CVE-level vulnerability detection.
        """
        keyword = f"{name} {version}" if version else name
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(self.max_results * 3, 20),
            "startIndex": 0,
        }
        try:
            time.sleep(self.rate_limit_delay)
            response = self.session.get(NVD_BASE_URL, params=params, timeout=10)
            response.raise_for_status()
            return self._parse_and_filter(response.json())
        except Exception:
            return []

    def get_cves_by_keyword(self, keyword: str) -> list[dict]:
        """
        Search CVEs by keyword (e.g. 'sql injection', 'eval injection').
        Useful for rule enrichment.
        """
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(self.max_results * 3, 20),
            "startIndex": 0,
        }

        try:
            time.sleep(self.rate_limit_delay)
            response = self.session.get(NVD_BASE_URL, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            return self._parse_and_filter(data)

        except Exception:
            return []

    def _parse_and_filter(self, data: dict) -> list[dict]:
        """Parse raw NVD API response and filter by minimum CVSS score."""
        parsed = []

        for item in data.get("vulnerabilities", []):
            cve_obj = item.get("cve", {})
            parsed_cve = self._parse_single_cve(cve_obj)
            if parsed_cve:
                parsed.append(parsed_cve)

        # Filter by minimum score and sort by score descending
        filtered = [
            c for c in parsed
            if isinstance(c.get("score"), (int, float)) and c["score"] >= self.min_score
        ]
        filtered.sort(key=lambda x: x.get("score", 0), reverse=True)

        return filtered[: self.max_results]

    def _parse_single_cve(self, cve: dict) -> dict | None:
        """Extract relevant fields from a single CVE object."""
        cve_id = cve.get("id")
        if not cve_id:
            return None

        # Get English description
        description = "No description available."
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", description)
                break

        # Try CVSS v3.1, then v3.0, then v2
        metrics = cve.get("metrics", {})
        score = None
        severity = "UNKNOWN"
        vector = None

        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                vector = cvss_data.get("vectorString")
                break

        # Get affected products (first 3)
        affected = []
        for config in cve.get("configurations", [])[:1]:
            for node in config.get("nodes", [])[:1]:
                for cpe_match in node.get("cpeMatch", [])[:3]:
                    criteria = cpe_match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        affected.append(f"{parts[3]}/{parts[4]}")

        return {
            "id": cve_id,
            "description": description[:200] + ("..." if len(description) > 200 else ""),
            "score": score,
            "severity": severity,
            "vector": vector,
            "published": cve.get("published", "N/A")[:10],
            "last_modified": cve.get("lastModified", "N/A")[:10],
            "affected": affected,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }
