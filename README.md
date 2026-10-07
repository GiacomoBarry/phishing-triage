# Phishing Triage

A command-line tool that triages one reported phishing email the way an L1 SOC analyst would. It reads a raw `.eml` file, reaches a **Verdict** (clean, suspicious or malicious) with a **Score**, saves a **Triage Report** and prints an **Incident Note** you can paste into a ticket.

## Why it exists

Triaging a reported email by hand is slow and easy to get wrong: reading raw headers, pasting every link into several threat-intel sites, and sometimes clicking a link "just to check". This tool does those steps consistently and safely. It only ever asks threat-intel services what they already know, and never visits a link or opens an attachment (see [ADR 0001](docs/adr/0001-reputation-lookups-only.md)).

It is also a learning and portfolio project on the path from service desk to SOC work.

## Status

Phase 1 is in progress. The tool parses an email, applies its red-flag rules to produce **Findings**, adds up their points into a **Score**, turns that into a **Verdict**, saves the Triage Report and prints the result. It pulls every link out of the email as an **Observable**, decoding obfuscated ones (defanged text, HTML entities, SafeLinks and Google redirect wrappers) as text, without ever visiting them. Each attachment is listed with its type, size and SHA-256, MD5 and SHA-1 hashes, worked out in memory without ever opening, unpacking or saving the file. So far there are five rules: a Reply-To on a different domain from the sender, a display name claiming a well-known brand, a sender or link domain imitating one, links through a URL shortener, and dangerous-looking attachments (risky or double extensions, hidden characters in the name, archives and password-protected ZIPs). Links and domains are looked up on **URLhaus**: a listed URL is a Decisive Finding, and a domain hosting listed URLs adds points ([ADR 0005](docs/adr/0005-urlhaus-domain-listings-are-not-decisive.md)). Links, domains and attachment hashes are also looked up on **VirusTotal**: 3 or more Engines flagging a link or attachment as malicious is a Decisive Finding, and 1 or 2 adds points. A flagged domain only ever adds points, because shared platforms collect detections too ([ADR 0007](docs/adr/0007-virustotal-domain-detections-are-not-decisive.md)). Not listed or never seen means **Unknown**, never clean ([ADR 0006](docs/adr/0006-virustotal-clean-needs-an-engine-to-vouch.md)). See `.scratch/phase-1-email-triage/` for the spec and tickets.

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

A missing key never stops a run: that Provider's lookups are marked **Not Checked** with the reason "no API key". If a Provider can't be reached, has no key or rejects it, says it's rate limited, or crashes, the rest of its lookups for that email are marked Not Checked with the same reason straight away, instead of each waiting out a timeout.

### Rate limits and waiting

VirusTotal's free API allows 4 lookups a minute (and 500 a day), and abuse.ch restricts accounts that send unusually many queries, so the tool paces itself: it waits between lookups to the same Provider (16.5 seconds for VirusTotal and 2.2 for URLhaus, which includes a 10% safety margin, [ADR 0008](docs/adr/0008-pace-providers-and-stop-asking-after-provider-wide-failures.md)) rather than being turned away. While it works, it shows progress on stderr, so `--json` output stays clean:

```
Looking up 2 of 4: VirusTotal, Domain malware[.]wicar[.]org
Waiting 14s for VirusTotal's rate limit...
```

An email with three links and an attachment takes about 100 seconds on a free VirusTotal key. Each email's domains are looked up first, then URLs (at most 10, see `[lookups]` below), then attachment hashes, and each one is looked up only once.

### The cache

Answers are cached in `.cache/lookups.json` (git-ignored), so triaging the same email again is near-instant and uses no quota. Malicious answers are reused for 7 days; suspicious, clean and Unknown ones for only 24 hours, so a link that has since been flagged isn't hidden for long. Not Checked is never cached. Cached answers are marked in the progress lines and the readable view (`(cached, fetched 2026-10-07T19:04:19Z)`) and in the Triage Report (`from_cache`, `cached_at`). Changing `decisive_engines` ignores old answers ([ADR 0009](docs/adr/0009-reputation-cache-keyed-on-the-decisive-engine-count.md)).

```sh
uv run phishing-triage path/to/email.eml --no-cache   # look everything up afresh (still saves the new answers)
```

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

The `[lookups]` section sets `url_cap`, the most URLs looked up per email (default 10). Any more are **Not Checked** ("over lookup cap"), so the email can't be called clean; their domains are still looked up.

The `[virustotal]` section sets `decisive_engines`, how many VirusTotal Engines must flag a link or attachment as malicious for a Decisive Finding (default 3, at least 1). Fewer, but at least one, adds the `virustotal_low_detections` points instead, as does a flagged domain however many Engines flag it.

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
