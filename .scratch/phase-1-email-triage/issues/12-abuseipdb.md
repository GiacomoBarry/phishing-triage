# 12: AbuseIPDB on the Claimed Origin

**What to build:** The Claimed Origin IP is looked up on AbuseIPDB, and a high abuse-confidence score adds a Finding.

**Blocked by:** 03, 09

**Status:** ready-for-agent

- [ ] AbuseIPDB Provider handles IP Observables via lookup only; only the Claimed Origin IP is sent
- [ ] Settings hold the confidence threshold; at or above it, the high-confidence Finding (15 points) with evidence (score, IP, that the origin is unverified where applicable)
- [ ] No record is Unknown; missing key or error is Not Checked (this does not trigger the clean-to-suspicious cap, which covers URLs and attachments only)
- [ ] Response parsing tested against saved real responses through a fake transport
- [ ] Core-seam tests cover high, low and unknown scores and a missing key
