# 01: Walking skeleton

**What to build:** The thinnest working version of the tool. Running the CLI on a `.eml` file performs a Triage through the core, saves a Triage Report and prints a short result. There are no rules yet, so every parseable email gets a clean Verdict. This sets up the project, the core/CLI split and the living docs that every later ticket builds on.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Python 3.12+ project managed with uv, src layout, pytest configured and running
- [ ] `.gitignore` covers `.env`, the samples folder, the reports folder, the cache and `.DS_Store`; a committed `.env.example` exists
- [ ] The core has one public entry point that takes raw email bytes, settings and Providers (none yet) and returns a Triage Report; it does no printing, file saving or environment reading
- [ ] The Triage Report carries a report ID, analysis timestamp, tool version, format version 1, the SHA-256 of the source email, the From address, display name, subject, Score (0), Verdict, warnings and an empty tags list
- [ ] The CLI takes one `.eml` path, prints a readable view (sender, subject, Verdict) and the Incident Note summary line (Verdict, Score, sender, subject)
- [ ] The CLI saves the Triage Report as JSON in the reports folder, named by report ID
- [ ] `--json` prints the Triage Report instead of the readable view
- [ ] Exit codes: 0 clean, 1 suspicious, 2 malicious, 3 or higher for an unreadable file or unparseable email, with a clear error message
- [ ] Tests at the core seam check the report metadata; a few CLI tests check exit codes, `--json`, the saved file and the error case
- [ ] `README.md`, `docs/ARCHITECTURE.md` (with a Mermaid diagram) and `docs/CONCEPTS.md` created for a beginner reader
