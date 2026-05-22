"""
git_utils.py — Utilities for interacting with Git staged files.
"""

import subprocess
from pathlib import Path


def get_staged_files() -> list[Path]:
    """
    Returns a list of Path objects for all files currently staged in git
    (i.e. files added via `git add` that haven't been committed yet).
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            check=True,
        )
        files = [
            Path(line.strip())
            for line in result.stdout.splitlines()
            if line.strip()
        ]
        return files
    except subprocess.CalledProcessError as e:
        print(f"⚠️  Warning: Could not get staged files from git: {e}")
        return []
    except FileNotFoundError:
        print("⚠️  Warning: git not found in PATH.")
        return []


def get_repo_root() -> Path | None:
    """Returns the root directory of the current git repo."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(result.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def get_current_branch() -> str:
    """Returns the current git branch name."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def get_latest_commit_hash() -> str:
    """Returns the short hash of the latest commit (HEAD)."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def get_staged_diff(file_path: str) -> str:
    """Returns the staged diff content for a specific file."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--", file_path],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""
