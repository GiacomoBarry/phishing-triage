# 09: Provider framework, URLhaus, and "clean requires evidence"

**What to build:** The tool can now make Reputation Lookups. Providers share one shape and are passed into the core. URLhaus is the first real Provider, and a URLhaus listing is a Decisive Finding. The tool is honest about gaps: missing keys or errors give Not Checked with a reason, and the Verdict can never be clean if any URL or attachment was Not Checked.

**Blocked by:** 07, 08

**Status:** ready-for-agent

- [ ] Every Provider declares which Observable kinds it handles and returns, per Observable, one of: malicious (with detail), suspicious (with detail), clean, Unknown, or Not Checked (with reason), plus raw evidence for the report
- [ ] Providers are built by the CLI and passed into the core; the core never builds them or reads keys
- [ ] A missing API key gives Not Checked with reason "no API key"; a Provider error or timeout gives Not Checked with the reason; the run never crashes
- [ ] URLhaus Provider for URLs and domains; a listing is a Decisive Finding making the Verdict malicious (ADR 0002); not listed is Unknown, never clean
- [ ] If any URL or attachment Observable is Not Checked, a clean Verdict becomes suspicious; the Triage Report records both the final Verdict and the Verdict before this cap, and the reason
- [ ] Lookup outcomes per Observable per Provider appear in the Triage Report
- [ ] The Incident Note gains a "Not Checked" section listing what wasn't checked and why
- [ ] Privacy test: fake Providers never receive recipient addresses, subject text or body text
- [ ] Safety test: no Provider is ever asked to submit or scan anything (ADR 0001)
- [ ] URLhaus response parsing tested against saved real responses through a fake transport; no network in any test
- [ ] Core-seam tests with fake Providers cover listed, Unknown, missing key, Provider error, and the clean-to-suspicious cap
