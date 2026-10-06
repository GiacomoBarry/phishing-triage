# 14: Reputation cache

**What to build:** Re-running a Triage on the same sample doesn't use up Provider quota, but stale "Unknown" results don't hide a newly flagged phishing link.

**Blocked by:** 09

**Status:** ready-for-agent

- [ ] Reputation Lookup results are cached locally, keyed by Provider and Observable, in a git-ignored location
- [ ] Malicious results are kept for 7 days; Unknown, clean and suspicious results for 24 hours; Not Checked is never cached
- [ ] Expiry uses an injected clock
- [ ] `--no-cache` bypasses reading the cache (fresh results are still stored)
- [ ] The Triage Report notes which outcomes came from the cache
- [ ] Core-seam tests with call-counting fake Providers and a fake clock cover hits, each expiry boundary, Not Checked not cached, and `--no-cache`
