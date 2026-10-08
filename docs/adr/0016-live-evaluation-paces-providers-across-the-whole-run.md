# Live evaluation takes a seeded sample, paces Providers across the whole run, and counts the final Verdict

Ticket 17 adds a **Live Evaluation**: `phishing-triage-evaluate --live` runs the same evaluation with the real Providers, over a small sample, to see how Reputation Lookups change the Offline Evaluation's numbers (ADR 0015). Free tiers are tight (VirusTotal allows 4 lookups a minute and 500 a day), so five choices shape it.

**The sample is picked at random with a fixed seed.** `--sample N` takes N phish and N ham (20 of each by default when live; every sample offline). Each label's files are sorted, then `random.Random(seed).sample()` picks N, so the same folder and the same `--seed` (default 1) always give the same emails. Each label gets its own generator, so adding ham doesn't change which phish are picked. `--sample` works offline too, so `phishing-triage-evaluate --sample 20` gives the offline numbers for exactly the emails a live run uses.

**Providers are paced across the whole run, not just within one email.** The core paces each Provider inside one Triage and forgets when the Triage ends (ADR 0008). That suits the CLI, but the evaluation triages dozens of emails in a row, so the next email's first lookup could follow the last one's straight away and break the limit. The evaluation wraps each Provider in `RunWidePacing` (`run_wide_pacing.py`), which remembers the last lookup for the whole run and waits its turn. It tells the core it has no limit, so the core doesn't wait a second time. It also remembers a "stop asking" answer (a rejected key, a used-up quota) for the rest of the run, because the next email won't fix it, and asking again would only spend more of the daily quota.

**The warning gives the most lookups the run can make, per Provider, before any is made.** A quick offline pass over the sample first finds each email's Observables (about 30 ms an email, and it is needed for the comparison anyway). For each Provider the estimate counts the Observables of the kinds it handles, leaving out URLs over the Lookup Cap, and, for a Provider with a rate limit, the shortest time that takes. It is an upper bound: Cached Lookups, an Observable repeated across emails (cached after its first lookup), and a Provider that stops answering all make it fewer. The warning goes to stderr and the run carries on; to stay under a quota, the maintainer picks a smaller `--sample`.

**It counts the final Verdict, after the clean-requires-evidence cap**, as an analyst would see it, plus how many Observables were Not Checked. With lookups, a ham email can only be called clean if its links and attachments were actually checked, so a missing key shows up as a higher False-Positive Rate, and the Not Checked count explains why.

**The offline counts for the same sample are printed underneath**, from the offline pass the estimate already needed, so one run shows what the lookups changed.

The reputation cache is the CLI's (`.cache/lookups.json`), so answers fetched by the CLI or an earlier run are reused, and a rerun of the same sample asks almost nothing again.

## Considered Options

- **The first N files of each label**: reproducible, but file names often follow the order a dataset was collected in, so the sample could all come from one period or one source. A seeded random pick is just as reproducible.
- **Pacing in the core across Triages** (passing the core's pacing state in, or a long-lived "lookup session"): would also work, but adds a concept to the core's interface for a maintainer tool. A wrapper Provider needs no change to the core, as ADR 0015 also preferred.
- **Asking for confirmation after the warning**: safer for quotas, but stops the command running unattended, and tests would have to fake a keyboard. The estimate is printed first, so Ctrl-C works, and the default sample is small.
- **Counting cache hits in the estimate**: more exact, but needs the core's cache keys outside the core. "Up to" is honest without it.
- **Counting the Verdict before the cap, as offline does**: would hide what the lookups (or missing keys) do to the Verdict an analyst actually sees, which is the point of the live run.

## Consequences

- A live run is slow on a free VirusTotal key: about 16.5 seconds per VirusTotal lookup after the first. 20 phish and 20 ham with a few links each can take half an hour or more; the warning says so up front, and reruns are fast thanks to the cache.
- Live numbers change from day to day as blocklists change. They are a snapshot, unlike the offline baseline.
- `main()` takes `providers` and `clock`, as the CLI and `triage()` do, so tests pass fake Providers and a fake clock, and never touch the network or really wait.
- The core now exports `Clock`, `SystemClock` and `SAFETY_MARGIN`, so the wrapper keeps the same 10% margin as the core's own pacing.
