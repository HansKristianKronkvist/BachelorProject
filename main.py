import os
import re
import sqlite3
import requests
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("DB_PATH", "patches.db")
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()

def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS patches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            source_url TEXT NOT NULL,
            repo_owner TEXT NOT NULL,
            repo_name TEXT NOT NULL,
            commit_sha TEXT NOT NULL,
            diff_text TEXT NOT NULL
        )
    """)
    con.commit()
    return con

def fetch_cve_from_nvd(cve_id: str) -> dict:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"User-Agent": "smartseclab-mvp/0.1"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    r = requests.get(url, params={"cveId": cve_id}, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()

def find_direct_github_commit_url(nvd_json: dict) -> str | None:
    vulns = nvd_json.get("vulnerabilities", [])
    if not vulns:
        return None

    refs = vulns[0].get("cve", {}).get("references", [])
    for ref in refs:
        u = ref.get("url", "")
        if re.match(r"^https://github\.com/[^/]+/[^/]+/commit/[0-9a-fA-F]{7,40}$", u):
            return u
    return None

def fetch_commit_diff(commit_url: str) -> tuple[str, str, str, str]:
    m = re.search(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})", commit_url)
    if not m:
        raise ValueError("Ikke en gyldig GitHub commit-url")
    owner, repo, sha = m.group(1), m.group(2), m.group(3)

    api = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    headers = {
        "User-Agent": "smartseclab-mvp/0.1",
        "Accept": "application/vnd.github.diff"
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    r = requests.get(api, headers=headers, timeout=30)
    r.raise_for_status()
    return owner, repo, sha, r.text

def save_to_db(con, cve_id: str, commit_url: str, owner: str, repo: str, sha: str, diff_text: str):
    cur = con.cursor()
    cur.execute("""
        INSERT INTO patches (cve_id, source_url, repo_owner, repo_name, commit_sha, diff_text)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (cve_id, commit_url, owner, repo, sha, diff_text))
    con.commit()

def main():
    cve_id = "CVE-2024-32002"  # eksempel som ofte har direkte commit-lenke

    print("[1] Lager/åpner DB:", DB_PATH)
    con = init_db()

    print("[2] Henter CVE fra NVD:", cve_id)
    nvd_json = fetch_cve_from_nvd(cve_id)

    print("[3] Finner direkte GitHub commit-lenke (MVP)...")
    commit_url = find_direct_github_commit_url(nvd_json)
    if not commit_url:
        raise RuntimeError("Fant ingen direkte commit-lenke i NVD-referanser for denne CVE-en.")

    print("    Fant:", commit_url)

    print("[4] Henter diff fra GitHub...")
    owner, repo, sha, diff_text = fetch_commit_diff(commit_url)
    print("    Diff-lengde:", len(diff_text))

    print("[5] Lagrer i SQLite...")
    save_to_db(con, cve_id, commit_url, owner, repo, sha, diff_text)

    con.close()
    print("✅ Ferdig. Sjekk DB-fila:", DB_PATH)

if __name__ == "__main__":
    main()
