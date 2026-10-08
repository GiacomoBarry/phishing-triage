# 02: Settings, Score and Verdict, with the Reply-To mismatch rule

**Moved to:** https://github.com/GiacomoBarry/phishing-triage/issues/2 — GitHub is now the source of truth.

**What to build:** The scoring machinery, proved end to end by one real rule. A Finding has a rule identifier, points, whether it is decisive, and evidence. Findings add up to a Score, and thresholds turn the Score into a Verdict. An email whose Reply-To domain differs from its From domain now gets a Finding that shows up in the report, the terminal view and the Incident Note.

**Blocked by:** 01

**Status:** resolved

- [x] A settings file holds Finding points and Verdict thresholds, with the spec's defaults; the CLI loads it and passes it to the core
- [x] Score is the sum of non-decisive Finding points, capped at 100
- [x] Verdict thresholds: 0–29 clean, 30–59 suspicious, 60+ malicious; any Decisive Finding makes the Verdict malicious regardless of Score (ADR 0002)
- [x] Reply-To mismatch Finding (20 points) with evidence naming both domains; no Finding when Reply-To is absent or matches
- [x] Findings appear in the Triage Report, the terminal view and an Incident Note section listing key Findings with evidence
- [x] Core-seam tests cover the rule firing and not firing, the 29/30 and 59/60 boundaries, the cap at 100, and a decisive Finding overriding a low Score (using a test-only rule or settings)

## Comments

**2026-10-06, implemented.** Notes for later tickets:

- Settings live in the packaged `src/phishing_triage/settings.toml`, and `--settings PATH` loads an edited copy that must have every key (ADR 0003). A new setting needs a line in the TOML, a field in `Settings` and a line in `config._build`. List settings (ticket 04 onwards) need the validation in `config._first_problem` extended beyond whole numbers.
- `triage()` takes an optional `rules=` argument (agreed with the maintainer) so tests can inject test-only rules. Real Decisive Findings arrive in tickets 09 and 10.
- Every Reply-To address is compared with the From domain, not just the first.
- The comparison is on exact domains, so `mail.example.org` versus `example.org` fires. Revisit after the dataset evaluation (ticket 16) if it causes false positives.
- Review notes not acted on: rule IDs are bare strings, and the two thresholds could be grouped. Reconsider both once more rules exist.
