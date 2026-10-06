# 02: Settings, Score and Verdict, with the Reply-To mismatch rule

**What to build:** The scoring machinery, proved end to end by one real rule. A Finding has a rule identifier, points, whether it is decisive, and evidence. Findings add up to a Score, and thresholds turn the Score into a Verdict. An email whose Reply-To domain differs from its From domain now gets a Finding that shows up in the report, the terminal view and the Incident Note.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] A settings file holds Finding points and Verdict thresholds, with the spec's defaults; the CLI loads it and passes it to the core
- [ ] Score is the sum of non-decisive Finding points, capped at 100
- [ ] Verdict thresholds: 0–29 clean, 30–59 suspicious, 60+ malicious; any Decisive Finding makes the Verdict malicious regardless of Score (ADR 0002)
- [ ] Reply-To mismatch Finding (20 points) with evidence naming both domains; no Finding when Reply-To is absent or matches
- [ ] Findings appear in the Triage Report, the terminal view and an Incident Note section listing key Findings with evidence
- [ ] Core-seam tests cover the rule firing and not firing, the 29/30 and 59/60 boundaries, the cap at 100, and a decisive Finding overriding a low Score (using a test-only rule or settings)
