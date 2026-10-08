# 11: Lookup orchestration

**Moved to:** https://github.com/GiacomoBarry/phishing-triage/issues/11 — GitHub is now the source of truth.

**What to build:** A link-heavy email finishes in reasonable time on free-tier keys without wasting quota. Lookups are de-duplicated, domains go first, URL lookups are capped, rate limits are respected by waiting, and the terminal shows progress.

**Blocked by:** 10

**Status:** resolved

- [x] Each distinct Observable is looked up once per Provider per Triage
- [x] Domains are looked up before individual URLs
- [x] URL lookups are capped (setting, default 10); URLs over the cap are Not Checked with reason "over lookup cap", which also triggers the clean-to-suspicious cap
- [x] Each Provider's rate limit is respected by waiting, not failing; waiting is testable without real delays (injected clock or sleeper)
- [x] The CLI shows progress during lookups; the core reports progress without printing
- [x] Core-seam tests with call-counting fake Providers cover de-duplication, ordering, the cap and rate-limit waiting

## Comments

**2026-10-07, from ticket 09.** When a Provider can't be reached (a TransportError such as a timeout), skip its remaining lookups for this Triage and mark them Not Checked straight away. During the URLhaus outage, a one-link email took 30 seconds because the URL and domain lookups each waited out the 15-second timeout. Also be gentle with URLhaus: abuse.ch now limits accounts with unusually high query volumes for up to 72 hours.

**2026-10-07, implemented.** Notes for later tickets:

- **Order:** domains, then URLs, then attachment hashes (`LOOKUP_ORDER` in `core/lookups.py`); the email's order is kept within each kind. The Triage Report's `lookups` list follows this order. De-duplication was already done by `extract_observables`; a call-counting test now pins it.
- **URL cap:** `[lookups] url_cap = 10`. URLs beyond it get a Not Checked result per Provider ("over lookup cap"), so they appear in the report and trigger the clean-to-suspicious cap. Domains and hashes aren't capped.
- **Rate limits (ADR 0008):** the `Provider` shape gained `lookups_per_minute` (VirusTotal 4, URLhaus 30, `None` for no limit). The core keeps each Provider's lookups at least 60/rate seconds apart plus a 10% margin (VirusTotal 16.5s) by waiting (`_ProviderTurns` in `core/lookups.py`). `triage(..., clock=)` takes a `Clock` (`core/clock.py`); tests pass `FakeClock`. A 429 is still Not Checked and never retried; pacing should prevent it.
- **Stop asking (ADR 0008):** `Lookup.stop_asking` is set by both Providers for no key, unreachable, rejected key and rate limited, and by the core when a Provider crashes. A `ProviderStopped` progress event explains it ("Not asking VirusTotal again: …"). The core then marks that Provider's remaining lookups Not Checked with the same reason, without asking or waiting. This took the test suite from 109s back to 0.2s, because no-key Providers no longer wait between "no API key" answers.
- **Progress:** `triage(..., on_progress=)` receives `LookupStarted(number, total, provider, observable)`, `WaitingForRateLimit(provider, seconds)` and `ProviderStopped(provider, reason)`; the CLI prints them to stderr, defanged. `total` counts lookups to be asked (not over-cap ones); skipped (stop-asking) lookups still advance `number` without their own event; the `ProviderStopped` line explains the jump.
- **For ticket 14 (cache):** a cached answer shouldn't be paced. Check the cache before `wait_needed()`, or wrap the Provider so a cache hit never reaches the pacer.
- Real run: the wicar test email (2 lookups each on URLhaus and VirusTotal) took 15.8s, with VirusTotal's second lookup waiting 13s.
- Review follow-ups not done: a shared helper for the four Provider-wide failure shapes in `urlhaus.py` and `virustotal.py` (wait for the third Provider, ticket 12); Providers are asked one after another, so URLhaus sits idle during VirusTotal's waits (VirusTotal is the bottleneck either way).
