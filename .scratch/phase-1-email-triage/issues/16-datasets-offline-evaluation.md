# 16: Datasets and offline evaluation

**What to build:** The maintainer can download public datasets and run a rules-only evaluation that prints Verdict counts for phish versus ham, to catch false positives early. It is rerun after each rule ticket.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] A download script fetches phishing_pot (phish) and SpamAssassin ham into the git-ignored samples folder, separated by label; raw samples are never committed
- [ ] An evaluation command runs the core over a samples folder with no Providers (offline, no network) and prints Verdict counts for phish and for ham, plus the false-positive rate (ham not clean) and missed-phish rate (phish clean)
- [ ] Once ticket 09 exists, offline evaluation counts the Verdict before the clean-requires-evidence cap, so missing lookups don't make every ham email a false positive
- [ ] It can list which samples got which Verdict, to investigate mistakes
- [ ] Unparseable samples are counted and skipped, not fatal
- [ ] Tests run the evaluation over a tiny committed fixture folder and check the counts
- [ ] `README.md` explains how to download the datasets and run the evaluation
