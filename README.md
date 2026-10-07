# Phishing Triage

A command-line tool that triages one reported phishing email the way an L1 SOC analyst would. It reads a raw `.eml` file, reaches a **Verdict** (clean, suspicious or malicious) with a **Score**, saves a **Triage Report** and prints an **Incident Note** you can paste into a ticket.

## Why it exists

Triaging a reported email by hand is slow and easy to get wrong: reading raw headers, pasting every link into several threat-intel sites, and sometimes clicking a link "just to check". This tool does those steps consistently and safely. It only ever asks threat-intel services what they already know, and never visits a link or opens an attachment (see [ADR 0001](docs/adr/0001-reputation-lookups-only.md)).

It is also a learning and portfolio project on the path from service desk to SOC work.

## Status

Phase 1 is in progress. The tool parses an email, applies its red-flag rules to produce **Findings**, adds up their points into a **Score**, turns that into a **Verdict**, saves the Triage Report and prints the result. So far there are three rules (a Reply-To on a different domain from the sender, a display name claiming a well-known brand, and a sender domain imitating one) and no Reputation Lookups yet. See `.scratch/phase-1-email-triage/` for the spec and tickets.

## Getting started

You need [uv](https://docs.astral.sh/uv/), which installs the right Python (3.12+) for you.

```sh
uv sync                    # install the tool and its dev dependencies
cp .env.example .env       # API keys go here later; .env is never committed
```

## Running a Triage

```sh
uv run phishing-triage path/to/email.eml          # readable view
uv run phishing-triage path/to/email.eml --json   # print the Triage Report as JSON
```

Every run saves the Triage Report to `reports/<report-id>.json`. That folder is git-ignored.

### How the Verdict is reached

Each red-flag rule that fires adds a Finding worth some points. The points add up to a Score (capped at 100), and thresholds turn the Score into a Verdict: 0–29 clean, 30–59 suspicious, 60 or more malicious. A **Decisive Finding**, such as a confirmed malicious link, makes the Verdict malicious whatever the Score ([ADR 0002](docs/adr/0002-points-plus-decisive-findings.md)).

### Tuning the settings

The points and thresholds live in [`src/phishing_triage/settings.toml`](src/phishing_triage/settings.toml). To tune them, copy that file, edit the copy and pass it in:

```sh
cp src/phishing_triage/settings.toml my-settings.toml
uv run phishing-triage path/to/email.eml --settings my-settings.toml
```

The `[brands]` section lists the **Protected Brands**: names attackers pretend to be, each with the domains that are genuinely theirs. Add your own organisation the same way, for example `"Acme" = ["acme.co.uk"]`. A display name naming a brand from any other domain is flagged, and so is a sender domain built to look like one of these domains, such as `paypa1.com` or `paypal-secure.xyz`.

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
