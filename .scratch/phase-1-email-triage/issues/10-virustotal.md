# 10: VirusTotal Provider

**Moved to:** https://github.com/GiacomoBarry/phishing-triage/issues/10 — GitHub is now the source of truth.

**What to build:** URLs, domains and attachment hashes are looked up on VirusTotal. Three or more malicious engine detections is a Decisive Finding; one or two adds points.

**Blocked by:** 09

**Status:** resolved

- [x] VirusTotal Provider handles URLs, domains and file hashes, using lookup endpoints only, never submission or rescan (ADR 0001)
- [x] An Observable VirusTotal has never seen is Unknown, never clean
- [x] The decisive engine count is a setting (default 3); at or above it, a Decisive Finding with evidence (engine count, Observable)
- [x] 1 to (threshold − 1) detections gives the low-detection Finding (15 points)
- [x] Response parsing tested against saved real responses (detected, clean, not found, rate-limited, bad key) through a fake transport
- [x] Core-seam tests with fake Providers cover decisive, low-detection, clean and Unknown outcomes for each Observable kind

## Comments

**2026-10-07, implemented.** Notes for later tickets:

- `VirusTotalProvider(api_key, transport, decisive_engines)` in `providers/virustotal.py`. GET only (`Transport` gained `get`): `/files/{sha256}`, `/domains/{domain}`, `/urls/{base64url of the URL, no padding}`. `build_providers(environ, settings)` now takes the settings for the threshold.
- Outcomes: ≥ `decisive_engines` malicious → MALICIOUS (the existing `known_malicious` rule makes it decisive); 1 to threshold−1 → SUSPICIOUS (new `virustotal_low_detections` rule, 15 points, **one Finding per Observable**); 404 → Unknown; 0 detections → clean for hashes, but for URLs and domains only if at least one Engine says "harmless", otherwise Unknown (**ADR 0006**); 401/429/400/other/unreadable/unreachable → Not Checked with the reason.
- Only Engines saying **malicious** are counted, as the ticket says ("malicious engine detections"); Engines saying "suspicious" are kept in the evidence but don't add points. If no Engine gave an answer at all (all timeouts or unsupported file type), the lookup is Unknown, never "0 of 0" clean (found in review).
- **Discovered:** looking up a domain VirusTotal has never seen makes it create a record on the spot (DNS lookup, all Engines "undetected", tagged `dga`). That's why ADR 0006 exists. Still within ADR 0001, but an attacker watching their DNS could notice.
- **Agreed deviation (ADR 0007), 2026-10-07:** the ticket said 3+ Engines is decisive for every kind, but the spec (user story 47) only lists hashes and URLs. Following the spec: a flagged domain is SUSPICIOUS however many Engines flag it, giving the 15-point low-detection Finding, never decisive. Same reasoning as ADR 0005. The DNS side effect of domain lookups (ADR 0006) was accepted; domain lookups stay.
- **Tuning flag for ticket 16:** google.com itself has 2 malicious detections (fixture `domain_low_detections`), so every link to google.com earns 15 points. A URL and its domain both weakly flagged reach 30 (suspicious). Watch the false-positive rate on SpamAssassin ham. Options if it's noisy: low-detection Findings for domains only above 1, or one Finding per email rather than per Observable.
- **Rate limits (ticket 11):** the free API is 4 a minute and 500 a day. A 429 is Not Checked, never retried. In practice 8 rapid lookups didn't trigger a 429, so `rate_limited.429.json` is hand-written from the documented format (see the fixtures README). Ticket 11 should pace VirusTotal at 4 a minute regardless.
- **Cache (ticket 14):** the outcome depends on `decisive_engines`, so cache the Engine counts (`evidence["malicious"]` etc.) and re-derive the outcome, or key the cache on the threshold too.
- Real end-to-end run: a link to the wicar.org test URL gave a decisive malicious Verdict (19 and 16 Engines); `benign_attachment.eml` is now clean, because its hash got a real (Unknown) answer instead of being Not Checked.
