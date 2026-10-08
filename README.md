# Phishing Triage

A command-line tool that triages one reported phishing email the way an L1 SOC analyst would. It reads a raw `.eml` file, reaches a **Verdict** (clean, suspicious or malicious) with a **Score**, saves a **Triage Report** and prints an **Incident Note** you can paste into a ticket.

## Why it exists

Triaging a reported email by hand is slow and easy to get wrong: reading raw headers, pasting every link into several threat-intel sites, and sometimes clicking a link "just to check". This tool does those steps consistently and safely. It only ever asks threat-intel services what they already know, and never visits a link or opens an attachment (see [ADR 0001](docs/adr/0001-reputation-lookups-only.md)).

It is also a learning and portfolio project on the path from service desk to SOC work.

## Status

Phase 1 is in progress. The tool parses an email, applies its red-flag rules to produce **Findings**, adds up their points into a **Score**, turns that into a **Verdict**, saves the Triage Report and prints the result. It pulls every link out of the email as an **Observable**, decoding obfuscated ones (defanged text, HTML entities, SafeLinks and Google redirect wrappers) as text, without ever visiting them. Each attachment is listed with its type, size and SHA-256, MD5 and SHA-1 hashes, worked out in memory without ever opening, unpacking or saving the file. So far there are ten rules: SPF, DKIM and DMARC fails and a high Abuse Confidence on the Claimed Origin (described below), **Urgency Phrases** such as "verify your account" or "within 24 hours" in the subject or body, a Reply-To on a different domain from the sender, a display name claiming a well-known brand, a sender or link domain imitating one, links through a URL shortener, and dangerous-looking attachments (risky or double extensions, hidden characters in the name, archives and password-protected ZIPs). Links and domains are looked up on **URLhaus**: a listed URL is a Decisive Finding, and a domain hosting listed URLs adds points ([ADR 0005](docs/adr/0005-urlhaus-domain-listings-are-not-decisive.md)). Links, domains and attachment hashes are also looked up on **VirusTotal**: 3 or more Engines flagging a link or attachment as malicious is a Decisive Finding, and 1 or 2 adds points. A flagged domain only ever adds points, because shared platforms collect detections too ([ADR 0007](docs/adr/0007-virustotal-domain-detections-are-not-decisive.md)). Not listed or never seen means **Unknown**, never clean ([ADR 0006](docs/adr/0006-virustotal-clean-needs-an-engine-to-vouch.md)). The sender's domain and every link domain are looked up with **RDAP** (asking the domain's registry, never the domain): one registered in the last 30 days adds points, and a registry that hides the date gives "unknown age", which never counts as old ([ADR 0010](docs/adr/0010-rdap-gives-facts-and-sender-domains-are-observables.md)). The tool also reads the **Authentication Results** the receiving server recorded (SPF, DKIM and DMARC, never re-checked): a recorded fail adds points (DMARC 20, SPF 10, DKIM 10), and a missing result is "not recorded", never a fail. It shows the Received chain hop by hop and the **Claimed Origin**, the IP the email appears to come from, labelled unverified unless one of your **Trusted Relays** recorded it ([ADR 0011](docs/adr/0011-trust-only-headers-added-after-the-email-reached-us.md)). The Claimed Origin is looked up on **AbuseIPDB**, and nothing else about the email is sent there. An **Abuse Confidence** of 75% or more adds 15 points, and the Finding says whether the IP could have been forged ([ADR 0012](docs/adr/0012-abuseipdb-reports-the-abuse-confidence-and-the-rule-applies-the-threshold.md)). An **Offline Evaluation** runs the rules over public phishing and legitimate-email datasets and reports the false-positive and missed-phish rates, and a **Live Evaluation** does the same over a small sample with the real Providers, to show what the lookups change (see "Evaluating the rules against public datasets" below). See `.scratch/phase-1-email-triage/` for the spec and tickets.

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
| `ABUSEIPDB_API_KEY` | AbuseIPDB | abuseipdb.com account (API key under your account's API tab) | now |
| (none) | RDAP (domain registries) | no key needed | now |

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

### Wrapper Emails and `--inner`

Users often report a phish by forwarding it "as an attachment", so the `.eml` you save is a **Wrapper Email**: their own email, with the real phish inside. Triaging that by mistake would judge your colleague's email, not the phish. When the email has an email attached (declared as `message/rfc822`, or a file ending in `.eml`), the Triage Report warns you that it may be a Wrapper Email, and the readable view adds a hint to use `--inner`:

```sh
uv run phishing-triage path/to/wrapper.eml --inner   # triage the email attached inside the Wrapper Email
```

With `--inner`, the attached email is triaged instead. The Triage Report's `source_sha256` is the attached email's, worked out from its bytes exactly as they sit inside the Wrapper Email (only a transfer encoding such as base64 is undone). So it matches its attachment hash in the Wrapper Email's Triage Report, and the hash of the same phish saved straight to disk as a `.eml` file. `taken_from_wrapper_sha256` records the Wrapper Email it came from, and a warning says it was taken from inside one. If several emails are attached, the first is triaged and the warnings say how many there were. `--inner` only looks one level deep ([ADR 0014](docs/adr/0014-attached-emails-are-message-rfc822-or-eml-files-one-level-deep.md)). If nothing is attached, it stops with exit code 8. If the attached email turns out not to be an email at all, it stops with exit code 4 and says it is the attached email that can't be read.

In the readable view and the Incident Note, every URL and domain is **defanged** (`hxxps://evil[.]com/login`) so nobody can click it by accident. The `--json` output keeps the real values, because it is meant for other programs.

### How the Verdict is reached

Each red-flag rule that fires adds a Finding worth some points. The points add up to a Score (capped at 100), and thresholds turn the Score into a Verdict: 0–29 clean, 30–59 suspicious, 60 or more malicious. A **Decisive Finding**, such as a confirmed malicious link, makes the Verdict malicious whatever the Score ([ADR 0002](docs/adr/0002-points-plus-decisive-findings.md)).

### Clean requires evidence

A **Verdict** can only be clean if every URL and attachment got a real answer from at least one Provider. If any was **Not Checked** (no key, the Provider was down or rate limited, or no Provider handles that kind), a clean Verdict is raised to suspicious. The report keeps the Verdict from before this cap and the reason, and the Incident Note's **Not Checked** section lists every gap.

### The Incident Note and Recommended Actions

The Incident Note has five sections, in order: a one-line summary (Verdict, Score, sender, subject), the key Findings with their evidence, the **IOCs** (Observables a Provider reported as malicious) followed by the other Observables, what was Not Checked and why, and **Recommended Actions**. Everything clickable is defanged, including the sender's address in the summary (`billing@evil[.]example`).

Recommended Actions are next steps for you, chosen from a fixed list based on the Verdict and which Findings fired ([ADR 0013](docs/adr/0013-recommended-actions-are-chosen-from-one-table.md)). The tool only suggests them: it never blocks, searches, resets or emails anything. The list, in the order it appears:

1. Block the malicious URLs, domains or attachment hashes (each listed, defanged), when a Provider reported any as malicious.
2. Block the sender domain, when the Verdict is malicious (unless it is already listed in action 1).
3. Search all mailboxes for copies of the email and remove them, when the Verdict is malicious or suspicious.
4. Check web proxy logs for anyone who visited the links (malicious or suspicious, with links).
5. Check whether anyone opened the attachment (malicious or suspicious, with attachments).
6. If a recipient entered their password, reset it and revoke their sessions (malicious or suspicious, with a link, and a Lookalike Domain, display-name impersonation or newly registered domain Finding).
7. Confirm with the apparent sender through a contact you already know, when there is a Reply-To mismatch or display-name impersonation.
8. Check the Not Checked items by hand before closing, when anything was Not Checked.
9. Close with no action and tell the reporter the email looks safe, when the Verdict is clean, nothing was Not Checked and no other action applies.

### Tuning the settings

The points and thresholds live in [`src/phishing_triage/settings.toml`](src/phishing_triage/settings.toml). To tune them, copy that file, edit the copy and pass it in:

```sh
cp src/phishing_triage/settings.toml my-settings.toml
uv run phishing-triage path/to/email.eml --settings my-settings.toml
```

The `[brands]` section lists the **Protected Brands**: names attackers pretend to be, each with the domains that are genuinely theirs. Add your own organisation the same way, for example `"Acme" = ["acme.co.uk"]`. A display name naming a brand from any other domain is flagged, and so is a sender domain built to look like one of these domains, such as `paypa1.com` or `paypal-secure.xyz`.

The `[urgency]` section lists the **Urgency Phrases**: wording that pressures the reader to act before thinking. Any of them in the subject or body adds the `urgency_language` points once, however many match. Matching ignores case, spacing and apostrophe style, and only whole words count ("act now" doesn't match "contact now"). Single words like "urgent" are left out on purpose, as genuine emails use them all the time; add them to your copy if you want them. The body is only read on your machine and never sent anywhere.

The `[shorteners]` section lists URL shortener domains. A link through one is flagged because its real destination is hidden; it is never expanded.

The `[attachments]` section lists risky file extensions (programs, scripts, disk images, macro-enabled Office files, HTML and SVG). Archives and password-protected ZIPs are flagged whatever their name.

The `[lookups]` section sets `url_cap`, the most URLs looked up per email (default 10). Any more are **Not Checked** ("over lookup cap"), so the email can't be called clean; their domains are still looked up.

The `[rdap]` section sets `new_domain_days`, how recently a sender or link domain must have been registered to add the `newly_registered_domain` points (default 30).

The `[virustotal]` section sets `decisive_engines`, how many VirusTotal Engines must flag a link or attachment as malicious for a Decisive Finding (default 3, at least 1). Fewer, but at least one, adds the `virustotal_low_detections` points instead, as does a flagged domain however many Engines flag it.

The `[received]` section lists your **Trusted Relays**: mail servers whose Received headers you believe, normally your own gateway (`trusted_relays = ["mx.acme.co.uk"]`, subdomains count too). Empty by default, so the Claimed Origin is labelled unverified, since the sender could have forged it. With your gateway listed, the Claimed Origin is the IP your gateway recorded.

The `[abuseipdb]` section sets `confidence_threshold`, the AbuseIPDB abuse confidence (1–100%) at or above which the Claimed Origin adds the `abuseipdb_high_confidence` points (default 75).

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
| 8 | `--inner` was given, but the email has no email attached |

Code 2 always means malicious, so bad usage gets 5 instead of the usual 2.

## Evaluating the rules against public datasets

To see how often the rules get things wrong, run them over thousands of emails whose answer is already known: **Phish** from [phishing_pot](https://github.com/rf-peixoto/phishing_pot) and **Ham** (legitimate email) from the [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/). Rerun it after changing any rule or weight, to catch false positives early.

### 1. Download the datasets

```sh
uv run python scripts/download_datasets.py
```

This fills the `samples/` folder:

```
samples/
  phish/phishing_pot/              over 12,000 phishing emails (a 1 GB download, so it takes a while)
  ham/spamassassin_easy_ham/       about 2,500 everyday legitimate emails
  ham/spamassassin_hard_ham/       about 250 legitimate emails that look like marketing or spam
```

`samples/` is git-ignored and must stay that way: the raw emails contain real people's addresses. Rerunning the script empties and refills each dataset's folder. You can add your own samples too: any file under `samples/phish/` counts as phish and any file under `samples/ham/` as ham (hidden files such as `.DS_Store` are skipped).

### 2. Run the Offline Evaluation

```sh
uv run phishing-triage-evaluate                              # evaluate samples/
uv run phishing-triage-evaluate --list                       # also list each sample's Verdict, Score and Findings
uv run phishing-triage-evaluate --settings my-settings.toml  # try out tuned weights
uv run phishing-triage-evaluate path/to/other-folder         # any folder with phish/ and ham/ inside
```

It prints a table like this (from the small test folder in `tests/fixtures/evaluation/`):

```
Label         clean   suspicious    malicious  unparseable        error        total
phish             1            1            2            1            0            5
ham               2            1            0            0            0            3

False-positive rate (ham not clean): 33.3% (1 of 3 ham)
Missed-phish rate (phish clean): 25.0% (1 of 4 phish)
```

- The **False-Positive Rate** is the share of ham that wasn't called clean: legitimate email an analyst would waste time on.
- The **Missed-Phish Rate** is the share of phish called clean: the dangerous mistake.
- **Unparseable** samples are files that aren't emails. **Error** samples are files that couldn't be read, or that the tool itself failed on: a non-zero error count usually means a bug in a rule, worth fixing. Both are counted and skipped, never fatal, and left out of both rates. `--list` shows why each one failed.
- Bad usage (an unknown option, say) exits with 5, as in the main CLI; a missing `phish/` or `ham/` folder with 3, and an invalid settings file with 7.

It is **offline**: no Providers are asked, so nothing touches the network and no API keys are needed. That means every URL and attachment is Not Checked, which would normally raise every clean Verdict to suspicious (see "Clean requires evidence" above). So the evaluation counts the Verdict from *before* that cap, which measures the rules and weights on their own ([ADR 0015](docs/adr/0015-offline-evaluation-counts-the-verdict-before-the-cap.md)). With real lookups, some missed phish would be caught.

To investigate mistakes, list everything and filter it, for example the ham that wasn't clean:

```sh
uv run phishing-triage-evaluate --list | grep -E '^ham +(suspicious|malicious)'
```

Each line shows the label, Verdict, Score, file and which rules fired, so you can open the email and see why. A full run over the datasets takes several minutes.

To try the rules on fewer emails, `--sample N` picks N phish and N ham at random, the same ones every time (`--seed N` picks a different set).

### 3. Run a Live Evaluation (optional, uses your API quotas)

To see how Reputation Lookups change the numbers, run the evaluation with the real Providers over a small sample:

```sh
uv run phishing-triage-evaluate --live              # 20 phish and 20 ham, picked at random
uv run phishing-triage-evaluate --live --sample 5   # a smaller sample, for fewer lookups
uv run phishing-triage-evaluate --live --list       # also list each sample
```

- It uses the API keys in `.env`, like the main CLI. A Provider with no key answers Not Checked, which can stop an email being called clean.
- **Before any lookup**, it prints on stderr the most lookups it could make for each Provider, and how long the rate limits make that take (VirusTotal's free tier allows 4 a minute and 500 a day). Press Ctrl-C if that's too many, and pick a smaller `--sample`.
- It keeps to each Provider's rate limit across the whole run, not just within one email, and once a Provider says to stop asking (a rejected key, a used-up quota) it isn't asked again in that run.
- It uses the same cache as the CLI (`.cache/lookups.json`), so a rerun of the same sample is fast and asks almost nothing again.
- The sample is the same every time for the same `--sample` and `--seed`, so a live run can be compared with an offline one: `uv run phishing-triage-evaluate --sample 20` gives the offline numbers for exactly the same emails.

It prints the same table and rates, but counts the **final** Verdicts (after the clean-requires-evidence cap), as an analyst would see them, then how many Observables were Not Checked, then the offline table for the same samples for comparison ([ADR 0016](docs/adr/0016-live-evaluation-paces-providers-across-the-whole-run.md)). Live numbers change as blocklists change, so treat them as a snapshot.

### Baseline (a dated snapshot)

> **Snapshot: 8 October 2026, commit `cfd7a17`.** These numbers will go stale as soon as a rule, a weight or a dataset changes. They are kept as the starting point to compare against, not as the current figures: rerun the evaluation for those.

The first run, with the default settings (12,271 phish, 2,750 ham). It predates the separate error column, so its one unparseable phish may have been either kind:

| | clean | suspicious | malicious | unparseable |
|---|---|---|---|---|
| phish | 11,382 | 870 | 18 | 1 |
| ham | 2,741 | 9 | 0 | 0 |

- False-positive rate: **0.3%** (9 of 2,750 ham).
- Missed-phish rate: **92.8%** (11,382 of 12,270 phish).

So the rules on their own almost never accuse a legitimate email, but miss most phish. Over half of the missed phish (6,463) did trip at least one rule, just not enough points to reach 30, and the links the Providers would catch aren't looked up offline. Tuning the weights against these numbers, and recording the before and after, is the next step.

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
