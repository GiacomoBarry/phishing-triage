# 13: RDAP: newly registered domains

**What to build:** Each sender and link domain's registration date is looked up via RDAP (asking the registry, never contacting the domain), and recently registered domains add a Finding.

**Blocked by:** 09

**Status:** ready-for-agent

- [x] RDAP Provider returns a registration date, or "unknown age" when the registry hides or lacks it
- [x] Settings hold the age limit (default 30 days); younger domains give the newly registered Finding (20 points) with evidence (domain, registration date, age)
- [x] Unknown age never counts as old and never produces the Finding; it is shown in the report
- [x] Age is computed against an injected clock
- [x] Response parsing tested against saved real responses through a fake transport
- [x] Core-seam tests cover young, old, exactly-at-limit and unknown-age domains

## Comments

**2026-10-07, implemented (ADR 0010).** Notes for later tickets:

- **New Observable kind `SENDER_DOMAIN`** (the From address's domain), looked up only by RDAP for now. It's first in `LOOKUP_ORDER`, appears in the report and Incident Note, and doesn't count towards "clean requires evidence". Every email now has one, which changed expectations in about 20 existing tests; link-focused tests (orchestration, cache, VirusTotal) now use emails with no From header so they count only links.
- `providers/rdap.py`: IANA bootstrap fetched once per run; GET the registry with `Accept: application/rdap+json`; 400 and 404 trim a label (the .org registry says 400 for subdomains, Verisign 404 with an empty body). Outcome is always Unknown, with `evidence["registered"]` (UTC text) or `None` for unknown age (no RDAP service, e.g. .de/.io; no date published; not found). Unreachable or 429 → Not Checked with `stop_asking`. 30 lookups a minute.
- `RuleInput.now` comes from the injected clock, and `analysed_at` uses the same clock.
- Rule `newly_registered_domain` (20 points, `[rdap] new_domain_days = 30`): fires when age is under the limit; exactly 30 days doesn't. Sender and link use of the same domain gives one Finding.
- The rule's boundary tests passed first time (the rule was written whole in one green step); checked by breaking it four ways on purpose, all caught.
- `registered_no_date.200.json` is derived from a real answer (registration event removed); no real example was found.
- For ticket 12 (AbuseIPDB): `list(ObservableKind)` in tests now includes SENDER_DOMAIN; parametrise over the kinds a Provider handles, as the VirusTotal tests now do.
- **Review fixes:** non-Latin domains are sent in punycode (before, urllib crashed and RDAP stopped for the rest of the email); registration dates in the future give no Finding; dates without a time zone are UTC; an unreadable date is unknown age, not Not Checked; trailing dots are ignored; a sender at an IP address (`user@[192.0.2.7]`) gives no Sender Domain.
- Not done: a domain that is both sender and link is looked up twice by RDAP (the cache key includes the kind); harmless, the rule merges them. No test for trimming reaching `co.uk` on an unregistered domain (ADR 0010 accepts it).
