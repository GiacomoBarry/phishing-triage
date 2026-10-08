# Spec: Phase 1 email Triage

**Moved to:** https://github.com/GiacomoBarry/phishing-triage/issues/18 — GitHub is now the source of truth.

Status: ready-for-agent

## Problem Statement

An L1 SOC analyst handling a reported phishing email has to do the same tedious steps every time: open the raw headers, pick out the sender, Reply-To and Received chain, read the SPF/DKIM/DMARC results, copy each URL and attachment hash into several threat-intel sites one by one, judge the red flags by eye, and then write a ticket note. It is slow, easy to do inconsistently, and easy to get dangerously wrong: clicking a link "just to check", or closing a ticket as clean when half the links were never actually checked.

The user works on a service desk and wants to move into SOC work. They want a tool that does this L1 workflow properly and safely, both to learn the domain and as a portfolio piece that shows sound analyst judgement.

## Solution

A command-line tool that takes one raw `.eml` file and performs a Triage. It extracts the email's Observables, makes Reputation Lookups against Providers (never visiting a URL or opening an attachment), applies red-flag rules to produce Findings, and reaches a Verdict of malicious, suspicious or clean, with a Score and the evidence behind it.

Each Triage produces a saved Triage Report (a structured record that later phases can build on) and an Incident Note the analyst can paste straight into a ticket. The tool is honest about its limits. It shows what it could not check, it never treats Unknown as clean, and it will not give a clean Verdict without the evidence to back it.

The triage logic lives in a core package, and the CLI is a thin wrapper around it, so a later web-based alert queue can reuse the same core.

## User Stories

### Running a Triage

1. As an L1 analyst, I want to run the tool on a single `.eml` file from the command line, so that I can triage a reported email in one step.
2. As an L1 analyst, I want a clear, readable summary in the terminal, so that I can understand the Verdict at a glance.
3. As an L1 analyst, I want to see progress while Reputation Lookups are running, so that I know the tool hasn't frozen while it waits on rate limits.
4. As an L1 analyst, I want the tool to warn me when the file is a Wrapper Email, so that I don't triage a colleague's forwarded report instead of the phish.
5. As an L1 analyst, I want an `--inner` option that triages the email attached inside a Wrapper Email, so that I can analyse the actual phish without extracting it by hand.
6. As an L1 analyst, I want the tool to fail with a clear message if the file isn't a parseable email, so that I'm not given a misleading Verdict on garbage input.

### Extracting Observables

7. As an L1 analyst, I want the From address and display name extracted, so that I can see who the email claims to be from.
8. As an L1 analyst, I want the Reply-To address extracted, so that I can spot replies being diverted elsewhere.
9. As an L1 analyst, I want the full Received chain shown hop by hop, so that I can follow the email's route.
10. As an L1 analyst, I want the Claimed Origin identified and clearly labelled unverified, so that I don't over-trust a header the attacker may have forged.
11. As an analyst in a real deployment, I want to configure Trusted Relays, so that the tool can identify the first hop added by a server I trust.
12. As an L1 analyst, I want the SPF, DKIM and DMARC results read from the recorded Authentication-Results, so that I see what the receiving server decided at delivery time.
13. As an L1 analyst, I want a missing Authentication-Results header reported as "not recorded", not "fail", so that I don't confuse missing data with a failed check.
14. As an L1 analyst, I want every URL in the plain-text and HTML bodies extracted, so that no link is missed.
15. As an L1 analyst, I want defanged URLs, HTML-entity-encoded URLs and SafeLinks-style wrapped URLs decoded offline, so that obfuscated links are analysed as their real destinations.
16. As an L1 analyst, I want shortened URLs recognised as shortened, so that I know their real destination is hidden.
17. As an L1 analyst, I want each attachment's filename, declared type, size and hashes (SHA-256, plus MD5 and SHA-1 for Providers that use them) listed, so that I can look them up and quote them in a ticket.
18. As an L1 analyst, I want attachments hashed whole and never unpacked or opened, so that nothing malicious is ever processed beyond reading its bytes.

### Reputation Lookups

19. As an L1 analyst, I want URLs, domains, the Claimed Origin IP and attachment hashes looked up against VirusTotal, URLhaus, AbuseIPDB and RDAP as appropriate, so that I don't have to paste each one into each site by hand.
20. As an L1 analyst, I want the tool to only look up what Providers already know and never submit anything for scanning, so that no Provider visits the attacker's link on my behalf.
21. As an L1 analyst, I want recipient addresses, subject lines and body text never sent to any Provider, so that the tool doesn't reveal who was targeted.
22. As an L1 analyst, I want a Provider having no record of an Observable shown as Unknown, so that I never mistake "never seen" for "known safe".
23. As an L1 analyst, I want lookups that didn't happen shown as Not Checked, with the reason, so that I know exactly which evidence is missing.
24. As someone trying the tool without every API key, I want it to run anyway and mark the missing Provider's lookups as Not Checked, so that I can still use it.
25. As an L1 analyst, I want duplicate Observables looked up only once, so that rate limits aren't wasted.
26. As an L1 analyst, I want domains looked up before individual URLs, and URL lookups capped at a configurable limit (10 by default), so that a link-heavy email finishes in reasonable time.
27. As an L1 analyst, I want URLs over the cap marked Not Checked, so that the cap is visible and can't produce a false clean.
28. As an L1 analyst, I want the tool to respect each Provider's rate limits by waiting rather than failing, so that lookups succeed on free-tier keys.
29. As an L1 analyst, I want Reputation Lookup results cached, so that re-running a sample doesn't use up my daily quota.
30. As an L1 analyst, I want cached malicious results kept for 7 days and cached Unknown or clean results for only 24 hours, so that a newly flagged phishing URL isn't hidden by a stale cache entry.
31. As an L1 analyst, I want a `--no-cache` option, so that I can force fresh lookups when I need them.
32. As an L1 analyst, I want each domain's registration age looked up via RDAP, so that newly registered domains can be flagged.
33. As an L1 analyst, I want a hidden registration date treated as "unknown age", not "old", so that hidden data doesn't make a domain look trustworthy.

### Findings

34. As an L1 analyst, I want a Finding when the Reply-To domain differs from the From domain, so that I can spot diverted replies.
35. As an L1 analyst, I want a Finding when the display name claims a Protected brand but the sending domain isn't theirs, so that I can spot impersonation.
36. As an L1 analyst, I want a Finding when the sender domain or a link domain is a Lookalike Domain of a Protected Domain, so that I can spot typosquatting.
37. As an L1 analyst, I want the Protected Domains list to be editable, so that I can add my organisation's own domains and the brands relevant to us.
38. As an L1 analyst, I want Findings for DMARC, SPF and DKIM failures, so that authentication problems count towards the Verdict.
39. As an L1 analyst, I want a Finding when a domain was registered in the last 30 days (configurable), so that freshly created phishing infrastructure stands out.
40. As an L1 analyst, I want a Finding when the email uses urgency language, so that pressure tactics count towards the Verdict.
41. As an L1 analyst, I want the urgency phrases kept in an editable list, so that I can tune them without changing code.
42. As an L1 analyst, I want a Finding when a URL shortener is used, so that hidden destinations count towards the Verdict.
43. As an L1 analyst, I want Findings for risky extensions, double extensions (such as `.pdf.exe`), archives and password-protected attachments, so that dangerous attachments are flagged without being opened.
44. As an L1 analyst, I want a Finding when an Observable has some VirusTotal detections but fewer than the decisive threshold, so that weak signals still count.
45. As an L1 analyst, I want a Finding when the Claimed Origin IP has a high AbuseIPDB confidence score, so that known-abusive senders count.
46. As an L1 analyst, I want every Finding to show the evidence that triggered it, so that I can verify it and explain it in a ticket.

### Verdict and Score

47. As an L1 analyst, I want a malicious Verdict whenever there's a Decisive Finding (an attachment hash or URL flagged by 3 or more VirusTotal engines, or a URL or domain listed on URLhaus), so that a confirmed IOC is never outvoted.
48. As an L1 analyst, I want all other Findings to add points to a Score capped at 100, so that I can see how much evidence there is.
49. As an L1 analyst, I want the Score turned into a Verdict by thresholds (0–29 clean, 30–59 suspicious, 60+ malicious), so that Verdicts are consistent between emails.
50. As an L1 analyst, I want the Verdict never to be clean if any URL or attachment was Not Checked, so that missing evidence can't produce false reassurance.
51. As an L1 analyst, I want to be told when the Verdict was capped at suspicious because of missing evidence, so that I know what to check by hand.
52. As the maintainer, I want the Finding weights, thresholds, decisive engine count, URL cap and domain-age limit in a config file, so that I can tune them against the datasets without editing code.

### Triage Report and Incident Note

53. As an L1 analyst, I want each Triage saved as a Triage Report, so that I have a record of what was found and decided.
54. As a future phase (alert queue, blocklist, dashboard), I want each Triage Report to carry a unique report ID, analysis timestamp, tool version, format version, the SHA-256 of the source email and a reserved place for tags, so that old reports can be found, de-duplicated, interpreted and extended.
55. As an L1 analyst, I want an Incident Note generated from the Triage Report, so that I can paste a consistent note into the ticket.
56. As an L1 analyst, I want the Incident Note to open with one line giving the Verdict, Score, sender and subject, so that the next shift can scan it quickly.
57. As an L1 analyst, I want the Incident Note to list the key Findings with their evidence, so that the Verdict is justified in the ticket.
58. As an L1 analyst, I want IOCs in the Incident Note defanged (for example `hxxps://evil[.]com`), so that nobody clicks them from the ticket.
59. As an L1 analyst, I want the Incident Note to state what was Not Checked and why, so that the ticket is honest about gaps.
60. As an L1 analyst, I want Recommended Actions in the Incident Note, chosen from a fixed list based on the Verdict and Findings, so that I have sensible next steps to carry out.
61. As an L1 analyst, I want the tool to only suggest Recommended Actions and never carry them out, so that I stay in control.
62. As someone integrating the tool, I want a `--json` option that prints the Triage Report, so that other tools can consume it.
63. As someone scripting the tool, I want the exit code to reflect the Verdict (0 clean, 1 suspicious, 2 malicious, 3 or higher for errors), so that scripts and the future alert queue can react without parsing text.

### Safety, data and portfolio

64. As the maintainer, I want API keys loaded from a git-ignored `.env` file, with a committed `.env.example`, so that secrets are never committed.
65. As the maintainer, I want public datasets (phishing_pot for phish, SpamAssassin ham for legitimate email) downloaded by a script into a git-ignored folder, so that raw samples with real people's addresses never land in the public repo.
66. As the maintainer, I want to run the tool across the dataset folder and see how many phish and ham emails get each Verdict, so that I can measure false positives and missed phish, and tune the weights.
67. As a portfolio reviewer, I want the safety rules (lookup only, nothing sent beyond attacker-side Observables, Unknown is not clean, clean requires evidence) visible in the docs and behaviour, so that I can see the author's analyst judgement.

## Implementation Decisions

- **Language and tooling:** Python 3.12+, managed with uv, tested with pytest, using a src layout.
- **Core and CLI split:** The triage logic is a core package with one public entry point: it takes the raw email bytes, the settings and a set of Providers, and returns a Triage Report. The core does no printing, no file saving and no reading of environment variables. The CLI is a thin wrapper. It reads the `.eml` file, loads settings and API keys, builds the real Providers, calls the core, prints the terminal view or JSON, saves the Triage Report and sets the exit code.
- **Pipeline stages inside the core:**
  1. Parse the email, or select the inner email when asked.
  2. Extract Observables.
  3. Make Reputation Lookups.
  4. Apply the rules to produce Findings.
  5. Score and reach a Verdict.
  6. Build the Triage Report.
  
  Incident Note generation is a pure function of the Triage Report, meaning it only reads the report and doesn't call out to anything else.
- **Provider interface:** Every Provider has the same small shape. It says which kinds of Observable it handles, and given one Observable it returns a lookup outcome (malicious with a detail such as engine count, suspicious with a detail, clean, Unknown, or Not Checked with a reason) plus raw evidence for the report. Providers are passed in to the core, never created inside it. The real Providers are VirusTotal, URLhaus, AbuseIPDB and RDAP (RDAP returns a registration date or unknown age).
- **Lookup-only rule (ADR 0001):** No code path may fetch a URL, follow a redirect, open or unpack an attachment, or call any Provider endpoint that submits or scans. Only attacker-side Observables are sent to Providers: URLs, domains, the Claimed Origin IP and attachment hashes.
- **Lookup orchestration:**
  - Observables are de-duplicated, and domains are looked up before URLs.
  - URL lookups are capped (default 10). Anything over the cap is Not Checked with the reason "over lookup cap".
  - Each Provider's rate limit is respected by waiting.
  - A missing API key makes that Provider return Not Checked with the reason "no API key". The run continues.
  - A Provider error is also Not Checked with a reason. It is never a crash.
- **Cache:** Reputation Lookup results are cached locally, keyed by Provider and Observable. Malicious results last 7 days, and Unknown or clean results last 24 hours. Not Checked is never cached. The clock is passed in so expiry can be tested. A switch bypasses the cache.
- **Findings:** Each rule is independent. It looks at the parsed email, its Observables and the lookup results, and returns zero or more Findings. Each Finding has a rule identifier, whether it is decisive, its points and human-readable evidence. The urgency rule is keyword and phrase based, behind the same rule interface, so a smarter checker could replace it later.
- **Verdict (ADR 0002):**
  - Any Decisive Finding means malicious.
  - Otherwise, the Score is the sum of the Finding points, capped at 100. The thresholds are 0–29 clean, 30–59 suspicious and 60+ malicious.
  - If any URL or attachment Observable is Not Checked, a clean Verdict is raised to suspicious, and the report records the reason.
- **Default points:**

  | Finding | Points |
  |---|---|
  | Reply-To mismatch | 20 |
  | Display-name brand impersonation | 25 |
  | Lookalike Domain | 30 |
  | DMARC fail | 20 |
  | SPF fail | 10 |
  | DKIM fail | 10 |
  | Domain registered in the last 30 days | 20 |
  | Urgency language | 10 |
  | URL shortener | 10 |
  | Risky, double-extension, archive or password-protected attachment | 25 |
  | VirusTotal detections below the decisive threshold | 15 |
  | High AbuseIPDB confidence on the Claimed Origin | 15 |

  These defaults, the thresholds, the decisive engine count (3), the URL cap (10), the domain-age limit (30 days), the Protected Domains list, the brand names, the urgency phrases, the shortener domains, the risky extensions and the Trusted Relays all live in one settings file.
- **Authentication results** are read from the recorded Authentication-Results header only, never re-checked. Each of SPF, DKIM and DMARC is pass, fail, another recorded value, or not recorded.
- **Received chain:** Parsed into ordered hops. The Claimed Origin is the earliest public IP, or the first hop added by a configured Trusted Relay when there is one. It is labelled unverified unless a Trusted Relay recorded it.
- **URL handling:**
  - URLs are collected from the plain-text and HTML parts.
  - Defanging, HTML entities and SafeLinks-style wrappers are decoded offline as text.
  - Shortener domains are recognised from the settings list. Shortened URLs are looked up as they are, never expanded.
- **Attachments:** Hashed whole (SHA-256, MD5 and SHA-1). The filename, declared type and size are recorded. Archive and password-protection detection uses only what can be read without unpacking (the file type and the zip's encryption flag).
- **Wrapper Emails:** If the email contains an attached email, the Triage Report carries a warning. The inner-email option selects the attached email as the one to triage.
- **Triage Report contents:**
  - report ID
  - analysis timestamp
  - tool version
  - format version (starting at 1)
  - SHA-256 of the source email
  - parsed headers summary
  - Received hops and Claimed Origin
  - authentication results
  - Observables, with their lookup outcomes per Provider
  - Findings
  - Score
  - Verdict, and the reason if it was capped
  - warnings
  - an empty tags list reserved for later ATT&CK mapping

  The format is defined in one place. Phase 1 saves each report as a JSON file in a reports folder, named by report ID.
- **Incident Note:** Plain text in five sections:
  1. Summary line (Verdict, Score, sender, subject)
  2. Key Findings with evidence
  3. Defanged IOCs
  4. Not Checked items and reasons
  5. Recommended Actions, chosen from a fixed list based on the Verdict and which Findings fired
- **CLI:**
  - Takes one positional `.eml` path.
  - Options: inner email, JSON output, no cache.
  - Exit codes: 0 clean, 1 suspicious, 2 malicious, 3 or higher for errors (an unreadable file or an unparseable email).
  - Shows progress during lookups.
- **Secrets:** API keys come only from the environment, via a git-ignored `.env`. A committed `.env.example` lists the variable names. The `.gitignore` covers `.env`, the samples folder, the reports folder, the cache and `.DS_Store`.
- **Datasets:** A script downloads phishing_pot and SpamAssassin ham into the git-ignored samples folder. A separate evaluation command runs the core across a folder and prints Verdict counts for phish and for ham.

## Testing Decisions

- **What makes a good test here:** Tests check external behaviour through the highest seam: given this email, these Provider answers and these settings, the Triage Report has this Verdict, these Findings, these Not Checked entries and this Incident Note content. Tests never call internal helpers directly or assert on internal data structures, so the inside can be reorganised freely.
- **Seam 1, the core entry point (most tests):**
  - Fixture `.eml` files plus fake Providers with canned answers. Areas covered:
    - each rule firing and not firing
    - Decisive Findings overriding the Score
    - the threshold boundaries (29/30 and 59/60)
    - Score capping
    - clean requires evidence
    - Unknown vs Not Checked
    - missing API keys
    - Provider errors
    - de-duplication
    - the URL cap
    - domains being looked up before URLs
    - offline URL decoding (defanged text, entities, SafeLinks)
    - shortened URLs never being expanded
    - attachment hashing and the attachment Findings
    - Authentication-Results parsing, including "not recorded"
    - Received-chain Claimed Origin, with and without Trusted Relays
    - Wrapper Email detection and inner selection
    - all Triage Report metadata fields
    - Incident Note sections, including defanged IOCs and Recommended Actions
  - Fake Providers count their calls (for the cache, de-duplication and cap tests) and can fail on demand (for the Not Checked tests).
  - A fake clock tests cache expiry: malicious lasts 7 days, Unknown and clean last 24 hours, and Not Checked is never cached.
  - A privacy test checks that fake Providers never receive recipient addresses, subject text or body text.
  - A safety test checks that no Provider is ever asked to submit or scan anything.
- **Seam 2, the CLI (a few tests):** Run with fake Providers. These check only the exit codes per Verdict and for errors, the JSON output matching the Triage Report, the inner-email option, the saved report file, and the clear error for an unparseable file. No rule logic is re-tested at this seam.
- **No network in any automated test.** Real Providers are not exercised by the test suite. Their response parsing is tested against saved real response bodies (fixtures) fed through a fake transport, to keep the real Provider code honest.
- **Fixtures:** A handful of small, hand-checked `.eml` samples, with recipient details replaced, are committed. The raw datasets are never committed.
- **Prior art:** None. This is a new codebase, and these tests set the pattern.

## Out of Scope

- Alert queue, web UI and dashboard (later phases will wrap the same core).
- MITRE ATT&CK mapping (the Triage Report reserves an empty tags list for it).
- Case notes, escalation and Recommended Actions being carried out automatically.
- Indicator blocklist (it will be built from IOCs only).
- Trends dashboard and any database storage (Phase 1 uses JSON files; moving to SQLite would be recorded in a later ADR).
- Expanding shortened URLs, by request or through a shortener's API.
- Unpacking archives or hashing files inside them.
- Submitting anything to any Provider for scanning.
- Re-checking SPF, DKIM or DMARC with live DNS.
- LLM-based urgency detection.
- Processing more than one email per CLI run (apart from the evaluation command over a dataset folder).
- Testing on real work emails.

## Further Notes

- The domain vocabulary is defined in `GLOSSARY.md`. Use its terms in code names, output text and tests.
- ADR 0001 (reputation lookups only) and ADR 0002 (points plus Decisive Findings) constrain this work. Any change that conflicts with them should be raised, not silently made.
- The default weights are a starting point. Tuning them against phishing_pot and SpamAssassin ham, and recording the false-positive rate before and after, is part of the portfolio story.
- Per the maintainer's global conventions, the first code change should also create `README.md`, `docs/ARCHITECTURE.md` (with a Mermaid diagram) and `docs/CONCEPTS.md`.
