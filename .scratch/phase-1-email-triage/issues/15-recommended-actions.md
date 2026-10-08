# 15: Recommended Actions

**Moved to:** https://github.com/GiacomoBarry/phishing-triage/issues/15 — GitHub is now the source of truth.

**What to build:** The Incident Note is complete with all five sections, ending in Recommended Actions chosen from a fixed list based on the Verdict and which Findings fired. The tool suggests them and never performs them.

**Blocked by:** 03, 04, 05, 09

**Status:** resolved

- [x] A fixed list of Recommended Actions (for example: block sender domain, block listed URLs, search mailboxes for the same subject/sender, check whether recipients clicked, reset credentials if a recipient entered them, verify manually the Not Checked items, close as no action)
- [x] Selection is a clear mapping from Verdict and Finding types to actions, readable in one place
- [x] The Incident Note has all five sections in order: summary line, key Findings with evidence, defanged IOCs, Not Checked, Recommended Actions
- [x] No code path carries out an action
- [x] Core-seam tests cover the action selection for malicious, suspicious (including capped for missing evidence) and clean emails, and the full note layout

## Comments

2026-10-08: Resolved on `integration/15-recommended-actions` in 87d4fd4 (Recommended Actions table, five-section Incident Note) and 1bf353f (review fixes). Close only when no other action applies, the sender domain is never blocked twice, and section 3 lists IOCs apart from the other Observables. Decisions are recorded in docs/adr/0013-recommended-actions-are-chosen-from-one-table.md. Follow-up: Finding evidence text still shows some domains undefanged (for example the Reply-To and impersonation rules).
