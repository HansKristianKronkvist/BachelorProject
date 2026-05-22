"""
config.py — Load and validate scanner_config.yaml.
Falls back to sensible defaults if the file is missing or incomplete.

API key priority (highest to lowest):
  1. NVD_API_KEY environment variable  (set in shell or CI/CD)
  2. .env file in the repo root        (local development)
  3. api_key field in scanner_config.yaml
  4. None (still works, just rate-limited)
"""

import os
from pathlib import Path

import yaml

try:
    from dotenv import load_dotenv
    _env_path = Path(__file__).resolve().parent.parent / ".env"
    load_dotenv(dotenv_path=_env_path, override=False)
except ImportError:
    pass  # python-dotenv not installed — falls back to env vars and config file


DEFAULTS = {
    "rules_path": "rules/rules.yaml",
    "severity_threshold": "HIGH",
    "color_output": True,
    "json_output_path": None,
    "nvd": {
        "enabled": True,
        "api_key": None,
        "max_cves_per_finding": 3,
        "min_cvss_score": 7.0,
        "cache_ttl_hours": 24,
        "fail_on_nvd_error": False,
    },
    "dep_scan": {
        "enabled": True,
        "min_cvss_score": 5.0,
        "max_cves_per_package": 3,
        "skip_unpinned": False,
    },
    "ignore": {
        "files": [],
        "rules": [],
        "paths": [],
    },
}


def load_config(config_path: str = "scanner_config.yaml") -> dict:
    """
    Load scanner config from YAML, then overlay any environment variables.
    Priority: env var > .env file > scanner_config.yaml > defaults.
    """
    path = Path(config_path)
    user_config = {}

    if path.exists():
        try:
            with open(path) as f:
                user_config = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            print(f"Warning: Could not parse {config_path}: {e}")

    config = _deep_merge(DEFAULTS, user_config)

    # Environment variable overrides everything — works for both
    # local .env (loaded above) and CI/CD secrets injected into the shell
    env_key = os.getenv("NVD_API_KEY")
    if env_key:
        config.setdefault("nvd", {})["api_key"] = env_key

    return config


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base."""
    result = base.copy()
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result
