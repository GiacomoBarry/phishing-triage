# 16: Datasets and offline evaluation

**What to build:** The maintainer can download public datasets and run a rules-only evaluation that prints Verdict counts for phish versus ham, to catch false positives early. It is rerun after each rule ticket.

**Blocked by:** 02

**Status:** resolved

- [x] A download script fetches phishing_pot (phish) and SpamAssassin ham into the git-ignored samples folder, separated by label; raw samples are never committed
- [x] An evaluation command runs the core over a samples folder with no Providers (offline, no network) and prints Verdict counts for phish and for ham, plus the false-positive rate (ham not clean) and missed-phish rate (phish clean)
- [x] Once ticket 09 exists, offline evaluation counts the Verdict before the clean-requires-evidence cap, so missing lookups don't make every ham email a false positive
- [x] It can list which samples got which Verdict, to investigate mistakes
- [x] Unparseable samples are counted and skipped, not fatal
- [x] Tests run the evaluation over a tiny committed fixture folder and check the counts
- [x] `README.md` explains how to download the datasets and run the evaluation

## Comments

2026-10-08: Resolved on `integration/16-offline-evaluation` in 48e0f37 (`phishing-triage-evaluate`: counts the Verdict before the cap, `--list`, unparseable samples skipped), a6f983b (sample count on stderr), e3c01b4 (`scripts/download_datasets.py`) and cfd7a17 (docs, ADR 0015, baseline). Review fixes: 2949af0 (core failures and unreadable files counted in a separate `error` column; exit codes and usage parser shared with the CLI via `command_line.py`), 2e88bbf (tests that archive members can't escape their folder) and d0a8e64 (docs; the README baseline marked as a dated snapshot). Decisions are in docs/adr/0015-offline-evaluation-counts-the-verdict-before-the-cap.md. Follow-ups: the baseline missed-phish rate is 92.8% (6,463 missed phish fired a rule but stayed under the threshold), so weights need tuning; rerun the baseline now that the error column exists; a full run takes about 7 minutes (~30 ms per email).
