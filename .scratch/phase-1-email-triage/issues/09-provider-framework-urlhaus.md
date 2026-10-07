# 09: Provider framework, URLhaus, and "clean requires evidence"

**What to build:** The tool can now make Reputation Lookups. Providers share one shape and are passed into the core. URLhaus is the first real Provider, and a URLhaus listing is a Decisive Finding. The tool is honest about gaps: missing keys or errors give Not Checked with a reason, and the Verdict can never be clean if any URL or attachment was Not Checked.

**Blocked by:** 07, 08

**Status:** ready-for-agent

- [x] Every Provider declares which Observable kinds it handles and returns, per Observable, one of: malicious (with detail), suspicious (with detail), clean, Unknown, or Not Checked (with reason), plus raw evidence for the report
- [x] Providers are built by the CLI and passed into the core; the core never builds them or reads keys
- [x] A missing API key gives Not Checked with reason "no API key"; a Provider error or timeout gives Not Checked with the reason; the run never crashes
- [x] URLhaus Provider for URLs and domains; a listing is a Decisive Finding making the Verdict malicious (ADR 0002); not listed is Unknown, never clean
- [x] If any URL or attachment Observable is Not Checked, a clean Verdict becomes suspicious; the Triage Report records both the final Verdict and the Verdict before this cap, and the reason
- [x] Lookup outcomes per Observable per Provider appear in the Triage Report
- [x] The Incident Note gains a "Not Checked" section listing what wasn't checked and why
- [x] Privacy test: fake Providers never receive recipient addresses, subject text or body text
- [x] Safety test: no Provider is ever asked to submit or scan anything (ADR 0001)
- [x] URLhaus response parsing tested against saved real responses through a fake transport; no network in any test
- [x] Core-seam tests with fake Providers cover listed, Unknown, missing key, Provider error, and the clean-to-suspicious cap

## Comments

**2026-10-07, implemented.** Notes for later tickets:

- **URLhaus fixtures are provisional.** URLhaus was down all session (abuse.ch was introducing rate limits after Fair Use abuse), so `tests/fixtures/urlhaus/*.json` follow the documented format rather than being captured. Run `uv run python scripts/capture_urlhaus_fixtures.py` (5 queries, key from `.env`) once it's back, re-run the tests, and remove the "provisional" note in the fixtures README. The maintainer's key is in `.env` but couldn't be validated yet.
- Provider shape (`core/providers.py`): `name`, `handles` (a set of `ObservableKind`) and `lookup(observable) -> Lookup(outcome, detail, evidence)`. Real Providers live in `src/phishing_triage/providers/` and talk to the network only through a `Transport` (`providers/transport.py`), so tests use a fake one. `build_providers(environ)` builds them; the CLI loads `.env` with python-dotenv and passes them in (`main(argv, providers=...)` lets CLI tests pass fakes).
- `core/lookups.py` runs every Provider on every Observable of a kind it handles (ticket 11 adds de-duplication, domains-first ordering, the cap and rate limiting there). Any exception from a Provider becomes Not Checked.
- **Clean requires evidence, agreed interpretation:** an Observable is Not Checked when no Provider gave a real answer (malicious, suspicious, clean or Unknown), including when no Provider handles its kind. Only URL and SHA-256 Observables trigger the clean-to-suspicious cap; domains are listed but don't trigger it. Consequence until ticket 10: any email with an attachment is at least suspicious, because nothing checks hashes yet.
- **Agreed deviation (ADR 0005):** a URLhaus URL listing is decisive (`known_malicious`), but a domain listing is a 20-point `urlhaus_domain_listed` Finding, because shared platforms like github.com host listed URLs.
- `known_malicious` turns any Provider's MALICIOUS outcome into a Decisive Finding, so ticket 10 only needs VirusTotal to return MALICIOUS at or above the engine threshold, and SUSPICIOUS for 1 to threshold−1 (with its own 15-point rule).
- Rate limiting: a 429 from URLhaus is Not Checked ("rate limited by URLhaus"), never retried. abuse.ch now limits heavy accounts for up to 72 hours, which makes ticket 14's cache important; ticket 11's rate-limit waiting should be gentle with URLhaus.
- Privacy gap for later: personalised phishing URLs (`?email=victim@ourcompany.example`) carry the recipient's address to Providers. The privacy test covers headers and body text, not addresses embedded in URLs. A future option is stripping recipient addresses from URLs before lookup, at the cost of possibly missing a listing.
