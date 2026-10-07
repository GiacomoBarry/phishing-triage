# Phishing Triage

A command-line tool that triages one reported phishing email the way an L1 SOC analyst would. It reads a raw `.eml` file, reaches a **Verdict** (clean, suspicious or malicious) with a **Score**, saves a **Triage Report** and prints an **Incident Note** you can paste into a ticket.

## Why it exists

Triaging a reported email by hand is slow and easy to get wrong: reading raw headers, pasting every link into several threat-intel sites, and sometimes clicking a link "just to check". This tool does those steps consistently and safely. It only ever asks threat-intel services what they already know, and never visits a link or opens an attachment (see [ADR 0001](docs/adr/0001-reputation-lookups-only.md)).

It is also a learning and portfolio project on the path from service desk to SOC work.

## Status

Phase 1 is in progress. The tool parses an email, applies its red-flag rules to produce **Findings**, adds up their points into a **Score**, turns that into a **Verdict**, saves the Triage Report and prints the result. It pulls every link out of the email as an **Observable**, decoding obfuscated ones (defanged text, HTML entities, SafeLinks and Google redirect wrappers) as text, without ever visiting them. Each attachment is listed with its type, size and SHA-256, MD5 and SHA-1 hashes, worked out in memory without ever opening, unpacking or saving the file. So far there are five rules: a Reply-To on a different domain from the sender, a display name claiming a well-known brand, a sender or link domain imitating one, links through a URL shortener, and dangerous-looking attachments (risky or double extensions, hidden characters in the name, archives and password-protected ZIPs). Links and domains are looked up on **URLhaus**: a listed URL is a Decisive Finding, and a domain hosting listed URLs adds points ([ADR 0005](docs/adr/0005-urlhaus-domain-listings-are-not-decisive.md)). Links, domains and attachment hashes are also looked up on **VirusTotal**: 3 or more Engines flagging one as malicious is a Decisive Finding, and 1 or 2 adds points. Not listed or never seen means **Unknown**, never clean ([ADR 0006](docs/adr/0006-virustotal-clean-needs-an-engine-to-vouch.md)). See `.scratch/phase-1-email-triage/` for the spec and tickets.

## Getting started

You need [uv](https://docs.astral.sh/uv/), which installs the right Python (3.12+) for you.

```sh
uv sync                    # install the tool and its dev dependencies
cp .env.example .env       # then put your API keys in .env; it is never committed
```

### API keys

Reputation Lookups need free API keys, which go in `.env` (never in `.env.example`, which is committed):

| Variable | Provider | Get a key | Used from |
|---|---|---|---|
| `URLHAUS_AUTH_KEY` | URLhaus (abuse.ch) | [auth.abuse.ch](https://auth.abuse.ch/) | now |
| `VIRUSTOTAL_API_KEY` | VirusTotal | virustotal.com account (API key in your profile) | now |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | abuseipdb.com account | ticket 12 |

A missing key never stops a run: that Provider's lookups are marked **Not Checked** with the reason "no API key". abuse.ch limits accounts that send unusually many queries, and VirusTotal's free API allows 4 lookups a minute and 500 a day. Until rate-limit waiting (ticket 11) arrives, lookups over VirusTotal's limit are Not Checked ("rate limited by VirusTotal"), and until the cache (ticket 14) exists, don't triage huge batches in a loop.

## Running a Triage

```sh
uv run phishing-triage path/to/email.eml          # readable view
uv run phishing-triage path/to/email.eml --json   # print the Triage Report as JSON
```

Every run saves the Triage Report to `reports/<report-id>.json`. That folder is git-ignored.

In the readable view and the Incident Note, every URL and link domain is **defanged** (`hxxps://evil[.]com/login`) so nobody can click it by accident. The `--json` output keeps the real values, because it is meant for other programs.

### How the Verdict is reached

Each red-flag rule that fires adds a Finding worth some points. The points add up to a Score (capped at 100), and thresholds turn the Score into a Verdict: 0–29 clean, 30–59 suspicious, 60 or more malicious. A **Decisive Finding**, such as a confirmed malicious link, makes the Verdict malicious whatever the Score ([ADR 0002](docs/adr/0002-points-plus-decisive-findings.md)).

### Clean requires evidence

A **Verdict** can only be clean if every URL and attachment got a real answer from at least one Provider. If any was **Not Checked** (no key, the Provider was down or rate limited, or no Provider handles that kind), a clean Verdict is raised to suspicious. The report keeps the Verdict from before this cap and the reason, and the Incident Note's **Not Checked** section lists every gap.

### Tuning the settings

The points and thresholds live in [`src/phishing_triage/settings.toml`](src/phishing_triage/settings.toml). To tune them, copy that file, edit the copy and pass it in:

```sh
cp src/phishing_triage/settings.toml my-settings.toml
uv run phishing-triage path/to/email.eml --settings my-settings.toml
```

The `[brands]` section lists the **Protected Brands**: names attackers pretend to be, each with the domains that are genuinely theirs. Add your own organisation the same way, for example `"Acme" = ["acme.co.uk"]`. A display name naming a brand from any other domain is flagged, and so is a sender domain built to look like one of these domains, such as `paypa1.com` or `paypal-secure.xyz`.

The `[shorteners]` section lists URL shortener domains. A link through one is flagged because its real destination is hidden; it is never expanded.

The `[attachments]` section lists risky file extensions (programs, scripts, disk images, macro-enabled Office files, HTML and SVG). Archives and password-protected ZIPs are flagged whatever their name.

The `[virustotal]` section sets `decisive_engines`, how many VirusTotal Engines must flag something as malicious for a Decisive Finding (default 3, at least 1). Fewer, but at least one, adds the `virustotal_low_detections` points instead.

Your copy must keep every setting from the original. A missing or misspelt one stops the run with a clear error rather than being silently ignored ([ADR 0003](docs/adr/0003-settings-in-a-packaged-toml-file.md)).

### Exit codes

Scripts can react to the Verdict without reading any text:

| Code | Meaning |
|---|---|
| 0 | clean |
| 1 | suspicious |
| 2 | malicious |
| 3 | the file could not be read |
| 4 | the file is not a parseable email |
| 5 | the command was used wrongly (for example, no file given) |
| 6 | the Triage Report could not be saved (the Verdict is still printed) |
| 7 | the settings file is missing or invalid |

Code 2 always means malicious, so bad usage gets 5 instead of the usual 2.

## Running the tests

```sh
uv run pytest     # the test suite
uv run mypy       # type checking
```

## Learn more

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): the main parts and how data flows between them
- [docs/CONCEPTS.md](docs/CONCEPTS.md): the programming concepts used, and where
- [GLOSSARY.md](GLOSSARY.md): what the domain terms (Triage, Verdict, Observable…) mean
- [docs/adr/](docs/adr/): the significant decisions and why they were made
