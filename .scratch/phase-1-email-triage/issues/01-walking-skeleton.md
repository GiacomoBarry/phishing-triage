# 01: Walking skeleton

**What to build:** The thinnest working version of the tool. Running the CLI on a `.eml` file performs a Triage through the core, saves a Triage Report and prints a short result. There are no rules yet, so every parseable email gets a clean Verdict. This sets up the project, the core/CLI split and the living docs that every later ticket builds on.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [x] Python 3.12+ project managed with uv, src layout, pytest configured and running
- [x] `.gitignore` covers `.env`, the samples folder, the reports folder, the cache and `.DS_Store`; a committed `.env.example` exists
- [x] The core has one public entry point that takes raw email bytes, settings and Providers (none yet) and returns a Triage Report; it does no printing, file saving or environment reading
- [x] The Triage Report carries a report ID, analysis timestamp, tool version, format version 1, the SHA-256 of the source email, the From address, display name, subject, Score (0), Verdict, warnings and an empty tags list
- [x] The CLI takes one `.eml` path, prints a readable view (sender, subject, Verdict) and the Incident Note summary line (Verdict, Score, sender, subject)
- [x] The CLI saves the Triage Report as JSON in the reports folder, named by report ID
- [x] `--json` prints the Triage Report instead of the readable view
- [x] Exit codes: 0 clean, 1 suspicious, 2 malicious, 3 or higher for an unreadable file or unparseable email, with a clear error message
- [x] Tests at the core seam check the report metadata; a few CLI tests check exit codes, `--json`, the saved file and the error case
- [x] `README.md`, `docs/ARCHITECTURE.md` (with a Mermaid diagram) and `docs/CONCEPTS.md` created for a beginner reader

## Comments

**2026-10-06, implemented.** Notes for later tickets, from the code review:

- The CLI hard-codes `Settings()` and `providers=[]`, so CLI tests can't inject fake Providers yet and exit codes 1 and 2 are untested. Ticket 02 (settings loading) or 09 (first Provider) should add that hook.
- `from_address` and `display_name` always travel together. Consider a small `Sender` type once more sender logic arrives (ticket 04).
- Exit codes beyond the spec: 4 for an unparseable email, 5 for bad usage (argparse's usual 2 would mean "malicious"), and 6 for a report that couldn't be saved.
