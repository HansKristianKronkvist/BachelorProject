#!/usr/bin/env python3
"""
install_hook.py — Installs the pre-commit git hook into the current repo.

Usage:
    python install_hook.py
    python install_hook.py --uninstall
"""

import argparse
import os
import stat
from pathlib import Path


HOOK_CONTENT = """\
#!/usr/bin/env bash
# Pre-Commit Security Scanner Hook
# Installed by install_hook.py — do not edit manually.

# Find the scanner root (where install_hook.py lives)
SCANNER_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

# Activate virtualenv if present
if [ -f "$SCANNER_DIR/.venv/bin/activate" ]; then
    source "$SCANNER_DIR/.venv/bin/activate"
fi

# Run the scanner
python -m scanner.main --config "$SCANNER_DIR/scanner_config.yaml"
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "  💡 To skip this check (use sparingly): git commit --no-verify"
    echo ""
fi

exit $EXIT_CODE
"""


def find_git_dir() -> Path | None:
    """Walk up the directory tree to find .git/"""
    current = Path.cwd()
    for parent in [current, *current.parents]:
        git_dir = parent / ".git"
        if git_dir.is_dir():
            return git_dir
    return None


def install():
    git_dir = find_git_dir()
    if not git_dir:
        print("❌ Not inside a git repository. Run from within a git repo.")
        return False

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_file = hooks_dir / "pre-commit"

    if hook_file.exists():
        print(f"⚠️  Existing pre-commit hook found at {hook_file}")
        overwrite = input("   Overwrite it? [y/N]: ").strip().lower()
        if overwrite != "y":
            print("   Installation cancelled.")
            return False
        # Backup the existing hook
        backup = hook_file.with_suffix(".backup")
        hook_file.rename(backup)
        print(f"   Backed up existing hook to: {backup}")

    hook_file.write_text(HOOK_CONTENT, encoding="utf-8")

    # Make it executable
    current_mode = os.stat(hook_file).st_mode
    hook_file.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"\n✅ Pre-commit hook installed at: {hook_file}")
    print("   The scanner will run automatically on every `git commit`.\n")
    print("   To test it manually:")
    print(f"     python -m scanner.main\n")
    return True


def uninstall():
    git_dir = find_git_dir()
    if not git_dir:
        print("❌ Not inside a git repository.")
        return False

    hook_file = git_dir / "hooks" / "pre-commit"
    if not hook_file.exists():
        print("ℹ️  No pre-commit hook found. Nothing to remove.")
        return True

    hook_file.unlink()
    print(f"✅ Pre-commit hook removed from: {hook_file}")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Install/uninstall the security scanner git hook")
    parser.add_argument("--uninstall", action="store_true", help="Remove the hook instead of installing it")
    args = parser.parse_args()

    if args.uninstall:
        uninstall()
    else:
        install()
