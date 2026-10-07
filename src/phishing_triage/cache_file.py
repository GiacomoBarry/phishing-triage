"""The real Reputation Lookup cache: a JSON file in .cache/ (git-ignored).

This lives outside the core because saving files is the caller's job. The
core decides what to cache and for how long; this only stores entries.

The cache is a convenience, so it never stops a Triage: a missing or damaged
file is treated as empty, and if it can't be saved, the run carries on.
"""

import json
import math
import os
import time
from pathlib import Path
from typing import Any

from phishing_triage.core import LONGEST_LIFETIME, CachedLookup, Lookup, LookupCache, Outcome

CACHE_PATH = Path(".cache") / "lookups.json"


class JsonFileCache:
    """Cached Lookups kept in one JSON file, read once and rewritten on each change.

    Entries too old to ever be fresh again are dropped when the file is read,
    so it doesn't keep every URL ever triaged.
    """

    def __init__(self, path: Path = CACHE_PATH) -> None:
        self._path = path
        self._entries = _drop_expired(_read(path), now=time.time())
        # Set when saving failed; the caller can warn the analyst.
        self.save_error: str | None = None

    def get(self, key: str) -> CachedLookup | None:
        data = self._entries.get(key)
        if not isinstance(data, dict):
            return None
        try:
            lookup = Lookup(Outcome(data["outcome"]), str(data["detail"]), dict(data["evidence"]))
            stored_at = float(data["stored_at"])
        except (KeyError, TypeError, ValueError):
            return None  # A damaged entry is simply a miss.
        return CachedLookup(lookup, stored_at) if math.isfinite(stored_at) else None

    def put(self, key: str, entry: CachedLookup) -> None:
        if self.save_error:
            return  # Already failed once this run; don't keep trying.
        self._entries[key] = {
            "outcome": str(entry.lookup.outcome),
            "detail": entry.lookup.detail,
            "evidence": entry.lookup.evidence,
            "stored_at": entry.stored_at,
        }
        try:
            _write(self._path, self._entries)
        except (OSError, TypeError, ValueError) as error:
            self.save_error = str(error)


class WriteOnlyCache:
    """For --no-cache: never answers from the cache, but still stores fresh answers."""

    def __init__(self, cache: LookupCache) -> None:
        self._cache = cache

    def get(self, key: str) -> CachedLookup | None:
        return None

    def put(self, key: str, entry: CachedLookup) -> None:
        self._cache.put(key, entry)


def _read(path: Path) -> dict[str, Any]:
    """The file's entries, or none if it's missing or damaged (it's only a cache)."""
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _drop_expired(entries: dict[str, Any], now: float) -> dict[str, Any]:
    """Keep only entries young enough that they might still be fresh."""
    kept = {}
    for key, data in entries.items():
        stored_at = data.get("stored_at") if isinstance(data, dict) else None
        if isinstance(stored_at, (int, float)) and now - stored_at < LONGEST_LIFETIME:
            kept[key] = data
    return kept


def _write(path: Path, entries: dict[str, Any]) -> None:
    """Write to a temporary file, then swap it in, so a crash can't leave half a file.

    The temporary name includes this run's process ID, so two runs at once
    can't write into the same temporary file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(json.dumps(entries, indent=1, allow_nan=False), "utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
