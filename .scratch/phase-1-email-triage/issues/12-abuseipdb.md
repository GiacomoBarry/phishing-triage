# 12: AbuseIPDB on the Claimed Origin

**Moved to:** https://github.com/GiacomoBarry/phishing-triage/issues/12 — GitHub is now the source of truth.

**What to build:** The Claimed Origin IP is looked up on AbuseIPDB, and a high abuse-confidence score adds a Finding.

**Blocked by:** 03, 09

**Status:** resolved

- [x] AbuseIPDB Provider handles IP Observables via lookup only; only the Claimed Origin IP is sent
- [x] Settings hold the confidence threshold; at or above it, the high-confidence Finding (15 points) with evidence (score, IP, that the origin is unverified where applicable)
- [x] No record is Unknown; missing key or error is Not Checked (this does not trigger the clean-to-suspicious cap, which covers URLs and attachments only)
- [x] Response parsing tested against saved real responses through a fake transport
- [x] Core-seam tests cover high, low and unknown scores and a missing key

## Comments

2026-10-08: Resolved on `main` in d3ad3e8 (AbuseIPDB Provider and high Abuse Confidence Finding; ADR 0012). Status line updated retrospectively; checklist confirmed against the commit and a green test suite (340 passed).
