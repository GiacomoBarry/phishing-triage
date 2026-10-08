# 17: Evaluation with live lookups

**Moved to:** https://github.com/GiacomoBarry/phishing-triage/issues/17 — GitHub is now the source of truth.

**What to build:** The maintainer can run the evaluation on a small sample with real Providers enabled, within free-tier rate limits, to see how Reputation Lookups change the results compared with the offline baseline.

**Blocked by:** 09, 16

**Status:** ready-for-agent

- [ ] The evaluation command has a live mode that uses the real Providers configured by API keys
- [ ] The sample size is chosen by the maintainer (default small, such as 20 phish and 20 ham), picked reproducibly
- [ ] It respects rate limits and uses the reputation cache when available
- [ ] It prints the same counts as offline mode, using the final Verdicts, plus how many Observables were Not Checked
- [ ] It warns about the estimated number of lookups before starting
- [ ] Tests use fake Providers only; no test uses the network
