# Phishing Triage

A command-line tool that triages one reported phishing email the way an L1 SOC analyst would. It reads a raw `.eml` file, reaches a **Verdict** (clean, suspicious or malicious) with a **Score**, saves a **Triage Report** and prints an **Incident Note** you can paste into a ticket.

## Why it exists

Triaging a reported email by hand is slow and easy to get wrong: reading raw headers, pasting every link into several threat-intel sites, and sometimes clicking a link "just to check". This tool does those steps consistently and safely. It only ever asks threat-intel services what they already know, and never visits a link or opens an attachment (see [ADR 0001](docs/adr/0001-reputation-lookups-only.md)).

It is also a learning and portfolio project on the path from service desk to SOC work.

## Status

Phase 1 is in progress. The **walking skeleton** works: it parses an email, builds a Triage Report, saves it and prints the Verdict. There are no red-flag rules or Reputation Lookups yet, so every parseable email gets a clean Verdict for now. See `.scratch/phase-1-email-triage/` for the spec and tickets.

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
