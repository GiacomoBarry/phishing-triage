# 10: VirusTotal Provider

**What to build:** URLs, domains and attachment hashes are looked up on VirusTotal. Three or more malicious engine detections is a Decisive Finding; one or two adds points.

**Blocked by:** 09

**Status:** ready-for-agent

- [ ] VirusTotal Provider handles URLs, domains and file hashes, using lookup endpoints only, never submission or rescan (ADR 0001)
- [ ] An Observable VirusTotal has never seen is Unknown, never clean
- [ ] The decisive engine count is a setting (default 3); at or above it, a Decisive Finding with evidence (engine count, Observable)
- [ ] 1 to (threshold − 1) detections gives the low-detection Finding (15 points)
- [ ] Response parsing tested against saved real responses (detected, clean, not found, rate-limited, bad key) through a fake transport
- [ ] Core-seam tests with fake Providers cover decisive, low-detection, clean and Unknown outcomes for each Observable kind
