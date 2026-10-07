# 11: Lookup orchestration

**What to build:** A link-heavy email finishes in reasonable time on free-tier keys without wasting quota. Lookups are de-duplicated, domains go first, URL lookups are capped, rate limits are respected by waiting, and the terminal shows progress.

**Blocked by:** 10

**Status:** ready-for-agent

- [ ] Each distinct Observable is looked up once per Provider per Triage
- [ ] Domains are looked up before individual URLs
- [ ] URL lookups are capped (setting, default 10); URLs over the cap are Not Checked with reason "over lookup cap", which also triggers the clean-to-suspicious cap
- [ ] Each Provider's rate limit is respected by waiting, not failing; waiting is testable without real delays (injected clock or sleeper)
- [ ] The CLI shows progress during lookups; the core reports progress without printing
- [ ] Core-seam tests with call-counting fake Providers cover de-duplication, ordering, the cap and rate-limit waiting

## Comments

**2026-10-07, from ticket 09.** When a Provider can't be reached (a TransportError such as a timeout), skip its remaining lookups for this Triage and mark them Not Checked straight away. During the URLhaus outage, a one-link email took 30 seconds because the URL and domain lookups each waited out the 15-second timeout. Also be gentle with URLhaus: abuse.ch now limits accounts with unusually high query volumes for up to 72 hours.
