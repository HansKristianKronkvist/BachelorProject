"""
cache.py — Local filesystem cache for NVD CVE data.
Prevents redundant API calls and keeps pre-commit hooks fast.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path


CACHE_DIR = Path(".scanner_cache")


class CVECache:
    def __init__(self, ttl_hours: int = 24, cache_dir: Path = CACHE_DIR):
        self.ttl = timedelta(hours=ttl_hours)
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(exist_ok=True)
        self._memory: dict[str, list] = {}  # In-memory layer for current run

    def _cache_file(self, key: str) -> Path:
        safe_key = key.replace("/", "_").replace(":", "_")
        return self.cache_dir / f"{safe_key}.json"

    def get(self, key: str) -> list | None:
        """
        Return cached data if it exists and hasn't expired.
        Checks memory cache first, then disk.
        """
        # Memory cache (fastest)
        if key in self._memory:
            return self._memory[key]

        # Disk cache
        cache_file = self._cache_file(key)
        if not cache_file.exists():
            return None

        try:
            cached = json.loads(cache_file.read_text())
            cached_time = datetime.fromisoformat(cached["timestamp"])
            if datetime.now() - cached_time < self.ttl:
                self._memory[key] = cached["data"]  # Warm memory cache
                return cached["data"]
        except (json.JSONDecodeError, KeyError, ValueError):
            pass  # Corrupt cache — treat as miss

        return None

    def set(self, key: str, data: list) -> None:
        """Write data to memory and disk cache."""
        self._memory[key] = data
        cache_file = self._cache_file(key)
        try:
            cache_file.write_text(
                json.dumps({"timestamp": datetime.now().isoformat(), "data": data},
                           indent=2)
            )
        except OSError:
            pass  # Non-fatal — just won't persist to disk

    def get_or_fetch(self, key: str, nvd_client) -> list:
        """
        Return cached CVEs for a key, or fetch from NVD and cache the result.
        key is expected to be a CWE ID like 'CWE-95'.
        """
        cached = self.get(key)
        if cached is not None:
            return cached

        data = nvd_client.get_cves_for_cwe(key)
        self.set(key, data)
        return data

    def clear(self) -> None:
        """Delete all cached files."""
        self._memory.clear()
        for f in self.cache_dir.glob("*.json"):
            f.unlink(missing_ok=True)
        print(f"🗑️  Cache cleared: {self.cache_dir}")

    def stats(self) -> dict:
        """Return cache statistics."""
        files = list(self.cache_dir.glob("*.json"))
        expired = 0
        valid = 0
        for f in files:
            try:
                data = json.loads(f.read_text())
                ts = datetime.fromisoformat(data["timestamp"])
                if datetime.now() - ts > self.ttl:
                    expired += 1
                else:
                    valid += 1
            except Exception:
                expired += 1
        return {"total": len(files), "valid": valid, "expired": expired}
