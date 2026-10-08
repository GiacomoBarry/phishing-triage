# Offline evaluation counts the Verdict before the cap, and never stops for one bad sample

Ticket 16 adds an **Offline Evaluation**: `phishing-triage-evaluate` runs the core over a samples folder of known **Phish** and **Ham** and prints how many of each got each Verdict, so the rules and weights can be tuned against public datasets (phishing_pot and SpamAssassin ham). Four choices shape it.

**It runs with no Providers, and counts the Verdict from before the clean-requires-evidence cap.** Thousands of lookups per run would be slow, would use up free API quotas in minutes, and would make the result change from day to day as blocklists change. So the core is given an empty list of Providers. But then every URL and attachment is Not Checked, and the cap would raise every clean Verdict to suspicious: nearly every ham email with a link would count as a false positive, and the numbers would say nothing about the rules. The Triage Report already keeps `verdict_before_cap` (what the rules and Score alone decided), so the evaluation counts that. No change to the core was needed.

**A sample that can't be triaged is counted as unparseable, with its reason, and the run carries on.** That covers files that aren't emails (`UnparseableEmailError`), files that can't be read, and any other error the core raises on an odd email. Real datasets hold emails malformed enough to trip up Python's email parser or a rule; one of those must not stop a run over thousands. The `--list` view gives each one's reason, and a core failure is named as one (`the core failed (ValueError: ...)`), so a bug isn't mistaken for a bad sample.

**The rates leave unparseable samples out.** The **False-Positive Rate** is the share of triaged ham that wasn't clean, and the **Missed-Phish Rate** the share of triaged phish that was clean. An unparseable sample has no Verdict, so it counts towards neither; its count is shown in the table instead.

**The samples folder is `samples/phish/` and `samples/ham/`, and every non-hidden file in them is a sample.** The label comes from the folder, not from the file. Each dataset gets its own subfolder (such as `samples/ham/spamassassin_hard_ham/`), so datasets can be added or refreshed one at a time. SpamAssassin's emails have no `.eml` ending, so files aren't filtered by name; hidden files such as macOS's `.DS_Store` are skipped. The whole folder is ignored by git, as raw samples hold real people's addresses.

## Considered Options

- **Evaluating with the real Providers**: closest to real use, but slow, quota-hungry and not repeatable. That is ticket 17 (live evaluation), over a small sample.
- **Fake Providers answering Unknown for everything**: would also stop the cap, but by pretending lookups happened. Using the Verdict before the cap says plainly what is being measured: the rules alone.
- **Adding an "offline" switch to the core that turns the cap off**: works, but adds a mode to the core for a maintainer tool, when the report already holds the answer.
- **Stopping on the first unparseable or failing sample**: makes bugs impossible to miss, but makes a run over a real dataset fail on the first odd email. Listing them gives the same information without stopping.
- **Counting unparseable samples as mistakes in the rates**: would mix up "the parser couldn't read it" with "the rules got it wrong".

## Consequences

- The numbers measure the rules and weights only. Lookups (URLhaus, VirusTotal, AbuseIPDB, RDAP) would catch some of the missed phish, so the real missed-phish rate should be lower.
- The command is outside the core, like the CLI: it reads files and prints. `main()` takes `rules`, as `triage()` does, so tests can make the core fail on purpose.
- The download script (`scripts/download_datasets.py`) fetches the datasets themselves, not anything they link to. It reads each archive and writes every email under its plain file name, never unpacking with the archive's own paths.
