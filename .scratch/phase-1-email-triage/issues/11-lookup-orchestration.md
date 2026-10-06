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
