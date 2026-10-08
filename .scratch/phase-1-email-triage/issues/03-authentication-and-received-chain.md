# 03: Authentication results and the Received chain

**What to build:** The tool reports what the receiving server recorded for SPF, DKIM and DMARC, and turns failures into Findings. It also shows the Received chain hop by hop and identifies the Claimed Origin, clearly labelled unverified unless a Trusted Relay recorded it.

**Blocked by:** 02

**Status:** resolved

- [x] SPF, DKIM and DMARC are read from the recorded Authentication-Results header only, never re-checked; each is pass, fail, another recorded value, or not recorded
- [x] A missing header gives "not recorded", which never produces a fail Finding
- [x] Findings: DMARC fail (20), SPF fail (10), DKIM fail (10), each with evidence
- [x] Received headers are parsed into ordered hops shown in the report and terminal view
- [x] The Claimed Origin is the earliest public IP in the chain, labelled unverified; private and reserved IPs are skipped
- [x] Trusted Relays are configurable in settings; when one is present in the chain, the Claimed Origin is the IP it recorded, and it is labelled as recorded by a Trusted Relay
- [x] Core-seam tests cover pass/fail/not-recorded for each check, forged-looking chains, private IPs, and with and without Trusted Relays

## Comments

2026-10-08: Resolved on `main` in 2556878 (authentication results, Received chain, Claimed Origin; ADR 0011). Status line updated retrospectively; checklist confirmed against the commit and a green test suite (340 passed).
