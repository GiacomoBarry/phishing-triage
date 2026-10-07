# The reputation cache is kept outside the core and keyed on the decisive Engine count

Re-running a Triage would otherwise repeat every Reputation Lookup, which costs about 16.5 seconds per VirusTotal lookup and eats the 500-a-day quota. So answers are cached: malicious ones for 7 days, suspicious, clean and Unknown ones for 24 hours (so a newly flagged link isn't hidden for long), and Not Checked never.

Three choices shape it:

- **The core decides, the CLI stores.** The core never saves files, so it only knows a small `LookupCache` shape (`get` and `put`) and decides what to keep and for how long. The CLI passes a JSON file in `.cache/` (git-ignored); tests pass one kept in memory. This is the same pattern as Providers.
- **The decisive Engine count is part of the cache key.** A VirusTotal outcome depends on that setting (ADR 0006), so a cached "malicious, 4 Engines" would be wrong after raising it to 5. With the setting in the key, changing it simply misses the old entries. Changing points or thresholds doesn't touch the key, so tuning against the datasets still benefits from the cache.
- **The clock gives calendar time, not monotonic time.** Expiry compares a time saved in one run with the time in a later run, which `time.monotonic()` can't do. Pacing uses the same clock; if the computer's clock is corrected mid-run, a pacing wait is at worst slightly off once.

## Considered Options

- **Cache the Engine counts and recompute the outcome**: exact, but every Provider would need its own "recompute" code. Keying on the setting gets the same safety with none.
- **Cache inside each Provider**: each would repeat the expiry rules, and the core couldn't skip rate-limit waits for cache hits.

## Consequences

- A cache hit isn't paced, so a re-run is near-instant. `--no-cache` forces fresh lookups but still stores them.
- Cached answers are marked in the Triage Report (`from_cache`, `cached_at`) and in the progress lines, so an analyst knows how old an answer is.
- `.cache/lookups.json` holds the URLs and domains of recently triaged emails. It's git-ignored and stays on the analyst's machine, and entries older than 7 days (too old to ever be fresh) are dropped whenever it's read. Like `.env` and `reports/`, it lives in the folder the tool is run from.
- The cache never stops a Triage: a missing or damaged file is empty, an entry with a damaged or future time is a miss, and if saving fails the run carries on with a warning.
- Two runs at the same time each rewrite the whole file, so the last to save wins and the other's new entries are lost (they're simply looked up again next time). Each run uses its own temporary file, so neither can swap in a half-written one.
