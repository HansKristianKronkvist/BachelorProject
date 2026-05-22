#  Pre-Commit Security Scanner

A Python-based pre-commit hook that scans staged code for vulnerabilities **before** they reach GitHub — enriched with live CVE data from the [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/).

---

## Features

-  **20+ built-in rules** across Python, JavaScript, TypeScript, Go, Java, Shell, Terraform, and more
-  **NVD API integration** — fetches real CVEs linked to each finding's CWE ID
-  **Local CVE cache** — fast commits, no repeated API calls
-  **AST-based analysis** for Python — more accurate than regex alone
-  **Configurable severity threshold** — block only HIGH/CRITICAL or adjust to your needs
-  **JSON output** for CI/CD pipeline integration
-  **Rule enrichment** — auto-update rules with latest CVE examples from NVD

---

## Installation

### 1. Clone and install dependencies

```bash
git clone <your-repo>
cd security-scanner
pip install -r requirements.txt
```

### 2. Install the git hook

```bash
python install_hook.py
```

This installs a `pre-commit` hook in your repo's `.git/hooks/` directory. It runs automatically on every `git commit`.

### 3. (Optional) Get an NVD API key

Free signup at: https://nvd.nist.gov/developers/request-an-api-key

Add it to `scanner_config.yaml`:
```yaml
nvd:
  api_key: "your-key-here"
```

---

## Usage

### Automatic (via git hook)
```bash
git add .
git commit -m "my commit"
# Scanner runs automatically
```

### Manual scan
```bash
# Scan staged files
python -m scanner.main

# Scan specific files
python -m scanner.main --files src/app.py src/config.py

# Use a custom config
python -m scanner.main --config my_config.yaml
```

### Update rules with latest NVD CVE data
```bash
python -m scanner.main --update-rules
```

### Skip the hook (use sparingly)
```bash
git commit --no-verify -m "skip scan"
```

---

## Example Output

```
🔍 Pre-Commit Security Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Scanning 2 staged file(s)...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  📄 src/config.py
  ────────────────────────────────────────────────────────

  🚨  CRITICAL  —  Hardcoded API Key or Secret
     Rule ID:  HARDCODED_API_KEY
     Location: Line 8
     Code:     api_key = "sk-abc123verylongsecretkey"
     Detail:   A hardcoded API key or secret token was found in source code.
     Fix:      Store secrets in environment variables (.env) or a secrets manager.
     CWE:      CWE-798  →  https://cwe.mitre.org/data/definitions/798.html

     📡 Related CVEs from NVD:
     ├── CVE-2024-27198  [CRITICAL, 9.8]
     │       JetBrains TeamCity authentication bypass via hardcoded credential...
     │       🔗 https://nvd.nist.gov/vuln/detail/CVE-2024-27198
     └── CVE-2023-46604  [CRITICAL, 10.0]
            Apache ActiveMQ RCE via hardcoded credential exploit...
            🔗 https://nvd.nist.gov/vuln/detail/CVE-2023-46604

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Found:  1 issue(s)  —  CRITICAL × 1
  ⛔ Commit BLOCKED. Resolve HIGH+ findings first.
```

---

## Configuration (`scanner_config.yaml`)

| Key | Default | Description |
|-----|---------|-------------|
| `rules_path` | `rules/rules.yaml` | Path to the vulnerability rules file |
| `severity_threshold` | `HIGH` | Minimum severity to block commits (`INFO/LOW/MEDIUM/HIGH/CRITICAL`) |
| `color_output` | `true` | Colored terminal output |
| `json_output_path` | `null` | Write findings to a JSON file |
| `nvd.enabled` | `true` | Enable NVD CVE lookups |
| `nvd.api_key` | `null` | NVD API key (free, increases rate limit) |
| `nvd.max_cves_per_finding` | `3` | Max CVEs to show per finding |
| `nvd.min_cvss_score` | `7.0` | Minimum CVSS score for displayed CVEs |
| `nvd.cache_ttl_hours` | `24` | Cache TTL for NVD responses |
| `ignore.files` | `[tests/*, test_*.py]` | Files/globs to skip |
| `ignore.rules` | `[]` | Rule IDs to disable globally |

---

## Built-in Rules

| ID | Severity | Language(s) | CWE |
|----|----------|-------------|-----|
| USE_OF_EVAL | HIGH | Python | CWE-95 |
| USE_OF_EXEC | HIGH | Python | CWE-95 |
| USE_OF_PICKLE | HIGH | Python | CWE-502 |
| HARDCODED_PASSWORD | CRITICAL | Multi | CWE-798 |
| HARDCODED_API_KEY | CRITICAL | Multi | CWE-798 |
| HARDCODED_AWS_KEY | CRITICAL | Multi | CWE-798 |
| PRIVATE_KEY_IN_CODE | CRITICAL | Multi | CWE-321 |
| SQL_INJECTION_FORMAT | HIGH | Python | CWE-89 |
| SQL_INJECTION_CONCAT | HIGH | Multi | CWE-89 |
| WEAK_HASH_MD5 | MEDIUM | Multi | CWE-327 |
| WEAK_HASH_SHA1 | MEDIUM | Multi | CWE-327 |
| WEAK_RANDOM | MEDIUM | Python | CWE-338 |
| PATH_TRAVERSAL | HIGH | Multi | CWE-22 |
| SHELL_INJECTION_SUBPROCESS | HIGH | Python | CWE-78 |
| OS_SYSTEM_CALL | MEDIUM | Python | CWE-78 |
| SSL_VERIFY_DISABLED | HIGH | Python/JS | CWE-295 |
| DEBUG_MODE_ENABLED | MEDIUM | Multi | CWE-215 |
| PRINT_SENSITIVE_DATA | LOW | Python | CWE-532 |
| XXE_LXML | HIGH | Python | CWE-611 |
| TF_PUBLIC_S3_BUCKET | HIGH | Terraform | CWE-284 |

---

## Project Structure

```
security-scanner/
├── scanner/
│   ├── __init__.py
│   ├── main.py          # Entry point & CLI
│   ├── git_utils.py     # Get staged files from git
│   ├── parser.py        # AST + regex code parsing
│   ├── rule_engine.py   # Load rules and run scans
│   ├── nvd_client.py    # NVD API client
│   ├── cache.py         # Local CVE cache
│   ├── reporter.py      # Terminal + JSON reporting
│   ├── config.py        # Config loader
│   └── update_rules.py  # Enrich rules with NVD data
├── rules/
│   └── rules.yaml       # Vulnerability rule definitions
├── install_hook.py      # Git hook installer
├── scanner_config.yaml  # User configuration
├── requirements.txt
└── README.md
```

---

## Database — Tracking Vulnerabilities Over Time

Every scan automatically saves its findings to a local SQLite database at `.scanner_cache/vulnerabilities.db`. This lets you track which vulnerabilities are open, resolved, or ignored across your entire commit history.

### CLI Commands

```bash
# Dashboard: totals, severity breakdown, top files and rules
python -m scanner.main --stats

# List all open findings (table view)
python -m scanner.main --report

# Filter by severity
python -m scanner.main --report --severity HIGH

# Full detail for a specific finding (including linked CVEs)
python -m scanner.main --detail 42

# Recent scan history
python -m scanner.main --history
python -m scanner.main --history --limit 25

# Search findings by keyword (file path, rule, description, CWE)
python -m scanner.main --search "config.py"
python -m scanner.main --search "CWE-89"

# Mark a finding as resolved
python -m scanner.main --resolve 42 --note "Fixed with parameterized queries"

# Mark as ignored (known acceptable risk)
python -m scanner.main --ignore 42 --note "Test file only"

# Mark as false positive
python -m scanner.main --fp 42

# Re-open a finding
python -m scanner.main --reopen 42
```

### Schema

```
scans        — one row per scan run (branch, commit, status, totals)
findings     — one row per vulnerability (rule, file, line, severity, status, notes)
cves         — CVE records from NVD linked to each finding
```

### Finding Lifecycle

```
open  ──→  resolved
      ──→  ignored
      ──→  false_positive
any   ──→  open  (via --reopen)
```

### Sharing the Database

The DB lives in `.scanner_cache/vulnerabilities.db`. You can:
- Add it to `.gitignore` to keep it local (default recommendation)
- Commit it to share vulnerability history across your team

---

## Uninstall

```bash
python install_hook.py --uninstall
```
