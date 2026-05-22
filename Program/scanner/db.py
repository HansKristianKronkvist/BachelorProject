"""
db.py — SQLite database for tracking vulnerability findings across scans.

Tables:
  scans    — one row per scanner run (linked to commit/branch)
  findings — one row per vulnerability found, with lifecycle status
  cves     — CVE records from NVD, linked to findings
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager


DB_PATH = Path(".scanner_cache/vulnerabilities.db")

# Schema 

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    repo          TEXT,
    branch        TEXT,
    commit_hash   TEXT,
    triggered_by  TEXT DEFAULT 'pre-commit',
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    status        TEXT DEFAULT 'running',   -- running | passed | blocked
    total_found   INTEGER DEFAULT 0,
    files_scanned INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id),
    rule_id       TEXT NOT NULL,
    rule_name     TEXT,
    severity      TEXT NOT NULL,
    file_path     TEXT NOT NULL,
    line_number   INTEGER,
    line_content  TEXT,
    description   TEXT,
    remediation   TEXT,
    cwe           TEXT,
    cwe_url       TEXT,
    status        TEXT DEFAULT 'open',      -- open | resolved | ignored | false_positive
    first_seen    TEXT NOT NULL,
    resolved_at   TEXT,
    notes         TEXT
);

CREATE TABLE IF NOT EXISTS cves (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id    INTEGER NOT NULL REFERENCES findings(id),
    cve_id        TEXT NOT NULL,
    score         REAL,
    severity      TEXT,
    description   TEXT,
    published     TEXT,
    url           TEXT
);

CREATE TABLE IF NOT EXISTS dep_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id),
    package_name    TEXT NOT NULL,
    package_version TEXT,
    file_path       TEXT NOT NULL,
    line_content    TEXT,
    severity        TEXT NOT NULL,
    description     TEXT,
    remediation     TEXT,
    cve_ids         TEXT,           -- JSON array of CVE IDs e.g. '["CVE-2024-1234"]'
    cve_data        TEXT,           -- Full JSON blob of CVE details
    status          TEXT DEFAULT 'open',
    first_seen      TEXT NOT NULL,
    resolved_at     TEXT,
    notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_scan     ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_status   ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_rule     ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_file     ON findings(file_path);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_cves_finding      ON cves(finding_id);
CREATE INDEX IF NOT EXISTS idx_dep_scan          ON dep_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_dep_package       ON dep_findings(package_name);
CREATE INDEX IF NOT EXISTS idx_dep_status        ON dep_findings(status);
"""

# Connection 

@contextmanager
def get_connection(db_path: Path = DB_PATH):
    """Context manager that yields a sqlite3 connection with auto commit/rollback."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Path = DB_PATH) -> None:
    """Create all tables and indexes if they don't already exist."""
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA)


# Scans 

def create_scan(repo: str, branch: str, commit_hash: str, triggered_by: str = "pre-commit") -> int:
    """Insert a new scan record. Returns the new scan ID."""
    with get_connection() as conn:
        cursor = conn.execute(
            """INSERT INTO scans (repo, branch, commit_hash, triggered_by, started_at)
               VALUES (?, ?, ?, ?, ?)""",
            (repo, branch, commit_hash, triggered_by, datetime.now().isoformat()),
        )
        return cursor.lastrowid


def finish_scan(scan_id: int, status: str, total_found: int, files_scanned: int) -> None:
    """Update a scan record with final stats once the scan is complete."""
    with get_connection() as conn:
        conn.execute(
            """UPDATE scans
               SET status = ?, total_found = ?, files_scanned = ?, finished_at = ?
               WHERE id = ?""",
            (status, total_found, files_scanned, datetime.now().isoformat(), scan_id),
        )


def get_scan_history(limit: int = 10) -> list[dict]:
    """Return the most recent scan records."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_scan_by_id(scan_id: int) -> dict | None:
    """Return a single scan record by ID."""
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


#  Findings 

def save_finding(scan_id: int, finding: dict) -> int:
    """
    Insert a finding and its associated CVEs into the database.
    Returns the new finding ID.
    """
    with get_connection() as conn:
        cursor = conn.execute(
            """INSERT INTO findings
               (scan_id, rule_id, rule_name, severity, file_path, line_number,
                line_content, description, remediation, cwe, cwe_url, first_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                finding.get("rule_id"),
                finding.get("rule_name"),
                finding.get("severity"),
                finding.get("file_path"),
                finding.get("line_number"),
                finding.get("line_content"),
                finding.get("description"),
                finding.get("remediation"),
                finding.get("cwe"),
                finding.get("cwe_url"),
                datetime.now().isoformat(),
            ),
        )
        finding_id = cursor.lastrowid

        for cve in finding.get("cves", []):
            conn.execute(
                """INSERT INTO cves (finding_id, cve_id, score, severity, description, published, url)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    cve.get("id"),
                    cve.get("score"),
                    cve.get("severity"),
                    cve.get("description"),
                    cve.get("published"),
                    cve.get("url"),
                ),
            )
        return finding_id


def update_finding_status(finding_id: int, status: str, notes: str = None) -> bool:
    """
    Update the lifecycle status of a finding.
    Valid statuses: open | resolved | ignored | false_positive
    Returns True if a row was updated.
    """
    valid = {"open", "resolved", "ignored", "false_positive"}
    if status not in valid:
        raise ValueError(f"Invalid status '{status}'. Must be one of: {valid}")

    resolved_at = datetime.now().isoformat() if status == "resolved" else None

    with get_connection() as conn:
        cursor = conn.execute(
            """UPDATE findings
               SET status = ?, resolved_at = ?, notes = COALESCE(?, notes)
               WHERE id = ?""",
            (status, resolved_at, notes, finding_id),
        )
        return cursor.rowcount > 0


def get_finding_by_id(finding_id: int) -> dict | None:
    """Return a single finding with its CVEs."""
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not row:
            return None
        finding = dict(row)
        cves = conn.execute(
            "SELECT * FROM cves WHERE finding_id = ?", (finding_id,)
        ).fetchall()
        finding["cves"] = [dict(c) for c in cves]
        return finding


def get_findings_for_scan(scan_id: int) -> list[dict]:
    """Return all findings for a scan, each with its linked CVEs."""
    with get_connection() as conn:
        findings = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity DESC",
            (scan_id,),
        ).fetchall()

        result = []
        for finding in findings:
            f = dict(finding)
            cves = conn.execute(
                "SELECT * FROM cves WHERE finding_id = ?", (finding["id"],)
            ).fetchall()
            f["cves"] = [dict(c) for c in cves]
            result.append(f)
        return result


def get_open_findings(severity: str = None) -> list[dict]:
    """Return all open findings, optionally filtered by severity."""
    query = "SELECT * FROM findings WHERE status = 'open'"
    params = []
    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())
    query += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, first_seen DESC"

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def get_all_findings(status: str = None, severity: str = None, limit: int = 100) -> list[dict]:
    """Return findings with optional filters on status and severity."""
    query = "SELECT * FROM findings WHERE 1=1"
    params = []
    if status:
        query += " AND status = ?"
        params.append(status)
    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())
    query += (
        " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 "
        "WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, first_seen DESC LIMIT ?"
    )
    params.append(limit)

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def search_findings(keyword: str) -> list[dict]:
    """Full-text search across file path, rule name, description, and CWE."""
    pattern = f"%{keyword}%"
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT * FROM findings
               WHERE file_path LIKE ? OR rule_name LIKE ?
                  OR description LIKE ? OR cwe LIKE ?
               ORDER BY first_seen DESC""",
            (pattern, pattern, pattern, pattern),
        ).fetchall()
        return [dict(r) for r in rows]


# Dependency Findings 

def save_dep_finding(scan_id: int, dep: dict) -> int:
    """Save a dependency finding (CVE-based) to the database. Returns new ID."""
    import json as _json
    cve_ids = _json.dumps([c.get("id") for c in dep.get("cves", [])])
    cve_data = _json.dumps(dep.get("cves", []))

    with get_connection() as conn:
        cursor = conn.execute(
            """INSERT INTO dep_findings
               (scan_id, package_name, package_version, file_path, line_content,
                severity, description, remediation, cve_ids, cve_data, first_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                dep.get("package_name"),
                dep.get("package_version"),
                dep.get("file_path"),
                dep.get("line_content"),
                dep.get("severity"),
                dep.get("description"),
                dep.get("remediation"),
                cve_ids,
                cve_data,
                datetime.now().isoformat(),
            ),
        )
        return cursor.lastrowid


def get_dep_findings(status: str = "open") -> list[dict]:
    """Return dependency findings filtered by status."""
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT * FROM dep_findings WHERE status = ?
               ORDER BY CASE severity
                 WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5
               END, first_seen DESC""",
            (status,),
        ).fetchall()
        return [dict(r) for r in rows]


def update_dep_finding_status(dep_id: int, status: str, notes: str = None) -> bool:
    """Update status of a dependency finding."""
    valid = {"open", "resolved", "ignored", "false_positive"}
    if status not in valid:
        raise ValueError(f"Invalid status '{status}'. Must be one of: {valid}")
    resolved_at = datetime.now().isoformat() if status == "resolved" else None
    with get_connection() as conn:
        cursor = conn.execute(
            """UPDATE dep_findings
               SET status = ?, resolved_at = ?, notes = COALESCE(?, notes)
               WHERE id = ?""",
            (status, resolved_at, notes, dep_id),
        )
        return cursor.rowcount > 0


# Stats 

def get_stats() -> dict:
    """Return a full summary of all tracked scans and findings."""
    with get_connection() as conn:
        total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        total_dep_findings = conn.execute("SELECT COUNT(*) FROM dep_findings").fetchone()[0]
        total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

        by_status = dict(
            conn.execute("SELECT status, COUNT(*) FROM findings GROUP BY status").fetchall()
        )
        open_by_severity = dict(
            conn.execute(
                "SELECT severity, COUNT(*) FROM findings WHERE status='open' GROUP BY severity"
            ).fetchall()
        )
        dep_by_severity = dict(
            conn.execute(
                "SELECT severity, COUNT(*) FROM dep_findings WHERE status='open' GROUP BY severity"
            ).fetchall()
        )
        top_rules = conn.execute(
            """SELECT rule_id, rule_name, COUNT(*) as count
               FROM findings WHERE status = 'open'
               GROUP BY rule_id ORDER BY count DESC LIMIT 5"""
        ).fetchall()
        top_files = conn.execute(
            """SELECT file_path, COUNT(*) as count
               FROM findings WHERE status = 'open'
               GROUP BY file_path ORDER BY count DESC LIMIT 5"""
        ).fetchall()
        top_packages = conn.execute(
            """SELECT package_name, package_version, COUNT(*) as count
               FROM dep_findings WHERE status = 'open'
               GROUP BY package_name ORDER BY count DESC LIMIT 5"""
        ).fetchall()
        recent_scan = conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT 1"
        ).fetchone()

        return {
            "total_findings": total_findings,
            "total_dep_findings": total_dep_findings,
            "total_scans": total_scans,
            "by_status": by_status,
            "open_by_severity": open_by_severity,
            "dep_open_by_severity": dep_by_severity,
            "top_vulnerable_rules": [dict(r) for r in top_rules],
            "top_vulnerable_files": [dict(r) for r in top_files],
            "top_vulnerable_packages": [dict(r) for r in top_packages],
            "last_scan": dict(recent_scan) if recent_scan else None,
        }
