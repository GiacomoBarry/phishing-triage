# AbuseIPDB reports the Abuse Confidence, and the rule applies the threshold

Ticket 12 looks the Claimed Origin's IP address up on AbuseIPDB. An Abuse Confidence at or above `[abuseipdb] confidence_threshold` (75% by default) gives the 15-point `abuseipdb_high_confidence` Finding. Three choices shape it.

**The Provider maps AbuseIPDB's answer to an outcome, but never applies the threshold.**
- AbuseIPDB answers HTTP 200 for every public IP. There is no "not found", so the outcome is worked out from the answer itself:
  - no reports in the last 30 days → Unknown
  - an IP on AbuseIPDB's allowlist of known-good addresses → clean, whatever its reports (8.8.8.8 has dozens)
  - any Abuse Confidence above 0 → suspicious
  - reports that leave an Abuse Confidence of 0 → Unknown
- The Abuse Confidence itself goes in the evidence, and the rule compares it with the threshold.
- This follows ADR 0010 (a Provider gives facts, a rule judges them) and avoids ADR 0009's trap: if the Provider applied the threshold, the threshold would have to be part of the cache key, or a change to it would be hidden by cached answers for 24 hours.
- One side effect: a low Abuse Confidence shows as "suspicious" in the Reputation Lookups without giving a Finding. That reads fine, because the detail always shows it.

**The Claimed Origin is its own kind of Observable, not a general "IP".**
- Only AbuseIPDB handles it, so the IP is never sent to VirusTotal or URLhaus. IP addresses in link URLs never become Observables at all.
- Like a link domain, a Claimed Origin that wasn't checked doesn't stop a clean Verdict. It can be forged, so its absence isn't missing evidence about the payload.

**The Finding says how far to trust the IP.** If no Trusted Relay recorded the Claimed Origin, the evidence says the sender could have forged it (ADR 0011). A forged origin pointing at an innocent, heavily reported IP would otherwise read as a strong signal.

## Considered Options

- **Malicious above the threshold, decided in the Provider**: simpler to read in the lookup list. But the threshold would leak into the cache key, and an IP reputation (which may be forged and is often shared) shouldn't be decisive anyway.
- **Unknown for every answer, as RDAP does**: consistent, but "unknown (abuse confidence 100%)" undersells a real signal, and the allowlist really is evidence of good standing.
- **Sending `verbose` to get individual reports**: more detail, but much larger answers, and the Abuse Confidence already summarises them.

## Consequences

- The free tier allows 1,000 checks a day with no per-minute limit, and each email has at most one Claimed Origin, so AbuseIPDB isn't paced.
- Without Trusted Relays, a forged bottom hop decides which IP is checked. The Finding's wording makes this visible but can't prevent it.
- At 15 points, a high Abuse Confidence alone leaves an email clean (under 30). It adds to other Findings rather than deciding.
