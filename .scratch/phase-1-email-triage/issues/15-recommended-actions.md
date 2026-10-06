# 15: Recommended Actions

**What to build:** The Incident Note is complete with all five sections, ending in Recommended Actions chosen from a fixed list based on the Verdict and which Findings fired. The tool suggests them and never performs them.

**Blocked by:** 03, 04, 05, 09

**Status:** ready-for-agent

- [ ] A fixed list of Recommended Actions (for example: block sender domain, block listed URLs, search mailboxes for the same subject/sender, check whether recipients clicked, reset credentials if a recipient entered them, verify manually the Not Checked items, close as no action)
- [ ] Selection is a clear mapping from Verdict and Finding types to actions, readable in one place
- [ ] The Incident Note has all five sections in order: summary line, key Findings with evidence, defanged IOCs, Not Checked, Recommended Actions
- [ ] No code path carries out an action
- [ ] Core-seam tests cover the action selection for malicious, suspicious (including capped for missing evidence) and clean emails, and the full note layout
