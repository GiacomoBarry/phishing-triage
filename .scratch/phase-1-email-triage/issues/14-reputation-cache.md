# 14: Reputation cache

**What to build:** Re-running a Triage on the same sample doesn't use up Provider quota, but stale "Unknown" results don't hide a newly flagged phishing link.

**Blocked by:** 09

**Status:** ready-for-agent

- [x] Reputation Lookup results are cached locally, keyed by Provider and Observable, in a git-ignored location
- [x] Malicious results are kept for 7 days; Unknown, clean and suspicious results for 24 hours; Not Checked is never cached
- [x] Expiry uses an injected clock
- [x] `--no-cache` bypasses reading the cache (fresh results are still stored)
- [x] The Triage Report notes which outcomes came from the cache
- [x] Core-seam tests with call-counting fake Providers and a fake clock cover hits, each expiry boundary, Not Checked not cached, and `--no-cache`

## Comments

**2026-10-07, implemented (ADR 0009).** Notes for later tickets:

- Core: `core/cache.py` has the `LookupCache` shape (`get`, `put`), `cache_key(provider, observable, decisive_engines)`, `LIFETIMES` and `is_fresh`. `run_lookups` checks the cache before pacing, so a hit is never waited for and doesn't touch stop-asking state. `triage(..., cache=None)`; `None` means no cache.
- CLI: `cache_file.py` has `JsonFileCache` (`.cache/lookups.json` in the folder you run from, like `.env` and `reports/`), written via a temporary file and `os.replace`. A damaged file or entry is a miss. `--no-cache` wraps it in `WriteOnlyCache` (never answers, still stores).
- **Deviation:** `--no-cache` is tested at the CLI seam, where the option lives, not the core seam the ticket lists. The core tests cover hits, every expiry boundary (lifetime − 1s hit, lifetime miss), Not Checked never stored, the decisive-count key and `cached_at`.
- `SystemClock.now()` is now `time.time()` (calendar time), because expiry compares across runs. CONCEPTS explains the trade-off.
- The report gains `from_cache` and `cached_at` (UTC text) on each lookup result; `format_version` stays 1 because the change only adds fields.
- The expiry tests passed on first run, because cycle 1's green step already had the lifetimes. They were checked by breaking the code on purpose (lifetime, boundary `<` vs `<=`, key without the count, caching Not Checked): all four breaks were caught.
- Real run: the wicar test email took 17s cold and 0.07s from the cache.
- For ticket 16 (evaluation): the cache is shared across emails, so evaluating a dataset twice is fast. Use `--no-cache` (or delete `.cache/`) to measure fresh results.
- **Review fixes:** an entry stored "in the future" (fast clock, edited file, `1e20`) is a miss, not fresh, which previously crashed formatting `cached_at`; a failed save (disk full, `.cache` not a folder, non-JSON evidence) sets `JsonFileCache.save_error` and the CLI warns instead of losing the Triage; temporary files are named per process; entries older than 7 days are dropped on read (privacy); `decisive_engines` is now a required argument to `run_lookups`.
- Known limit: two runs at once each rewrite the whole file, so the last to save wins (ADR 0009). Fine for one analyst; a SQLite cache would fix it if the alert queue phase needs it.
