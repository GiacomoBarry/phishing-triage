# AbuseIPDB response fixtures

Real AbuseIPDB API v2 response bodies, captured on 2026-10-07 with
`scripts/capture_abuseipdb_fixtures.py`. They're fed to the AbuseIPDB
Provider through a fake transport, so no test touches the network. Each file
is named `<case>.<HTTP status>.json`.

- `high_confidence` is the first IP on AbuseIPDB's blacklist that day: a
  score of 100 from over 2,000 reports.
- `allowlisted` is 8.8.8.8 (Google's DNS). It has 51 reports, but AbuseIPDB
  lists it as known-good and scores it 0: report counts alone would mislead.
- `not_reported` is a Microsoft IP with no reports in the last 30 days.
  AbuseIPDB still answers 200 (it has no "not found"), and still gives the
  date of an older report.
- `invalid_ip` is AbuseIPDB refusing a value that isn't an IP (HTTP 422).
- **`low_confidence.200.json` is hand-written**, in the shape of the real
  answers: none of the IPs tried had a low, non-zero score that day. It
  uses a documentation address (198.51.100.23) so no real IP is shown with
  made-up reports.
- **`rate_limited.429.json` is hand-written** from AbuseIPDB's documented
  error format, rather than spending a day's 1,000 checks to provoke it.

To refresh them, run the script again. It makes at most 12 requests with the
key in `.env`.
