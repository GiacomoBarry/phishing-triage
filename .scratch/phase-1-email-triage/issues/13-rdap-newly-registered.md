# 13: RDAP: newly registered domains

**What to build:** Each sender and link domain's registration date is looked up via RDAP (asking the registry, never contacting the domain), and recently registered domains add a Finding.

**Blocked by:** 09

**Status:** ready-for-agent

- [ ] RDAP Provider returns a registration date, or "unknown age" when the registry hides or lacks it
- [ ] Settings hold the age limit (default 30 days); younger domains give the newly registered Finding (20 points) with evidence (domain, registration date, age)
- [ ] Unknown age never counts as old and never produces the Finding; it is shown in the report
- [ ] Age is computed against an injected clock
- [ ] Response parsing tested against saved real responses through a fake transport
- [ ] Core-seam tests cover young, old, exactly-at-limit and unknown-age domains
