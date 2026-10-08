# Attached emails are message/rfc822 parts or .eml files, one level deep

Ticket 06 warns when the email being triaged is a **Wrapper Email** (a user's own email with the suspected phish attached), and `--inner` triages the attached email instead. That needs a clear answer to "what counts as an attached email?", "which one is the first?" and "which bytes are the attached email?". Five choices shape it.

**An attached email is a message/rfc822 part, or an attachment whose filename ends in `.eml`.**
- Forwarding "as attachment" in most mail programs attaches the email with the declared type `message/rfc822`. That is the standard way, and Python's email parser understands it.
- Some mail programs and webmail exports attach the email as an ordinary file called something like `phish.eml`, declared as `application/octet-stream`. An analyst would call that an attached email too, so it counts.
- Anything else, such as an Outlook `.msg` file, does not count. `.msg` is a different, binary format the tool can't read as an email.

**Only emails attached directly to the email count, never ones inside an attached email.** Finding attached emails uses the same walk over the parts as describing attachments (`attachment_parts()` in `core/attachments.py`), which deliberately never looks inside an attached email. So `--inner` goes exactly one level deep. If the attached email has an email attached too (a report of a report), the Triage Report says so and the analyst extracts it by hand.

**"First" means first in the order the parts appear in the email.** That is the order the attachments are listed in the Triage Report, so "the first attached email" is the first one the analyst sees there. When there are several, the warnings say how many, and that only the first was triaged.

**An attached email is its original bytes, exactly as they sit inside the Wrapper Email.** Both its attachment SHA-256 and, under `--inner`, the `source_sha256` (and the bytes that are parsed and triaged) are those original bytes, with only a transfer encoding such as base64 or quoted-printable undone. So the inner Triage Report's `source_sha256` matches the attachment's SHA-256 in the Wrapper Email's Triage Report, and also the hash of the same phish saved straight to disk as a `.eml` file. The Wrapper Email's own SHA-256 is kept in `taken_from_wrapper_sha256` (empty when the email wasn't taken from a Wrapper Email).
- Python's email parser can't give these bytes back: it turns an attached email into a parsed message, and turning that back into bytes rebuilds it (CRLF line endings become LF, encoded-word headers such as `=?utf-8?q?...?=` are decoded, long headers are refolded). Every one of those changes the hash.
- So attachments are found by walking the raw email instead (`attachment_parts()` in `core/attachments.py`): each part is parsed for its headers only, which leaves its body as the original bytes, and a multipart body is split on its boundary lines by hand, following RFC 2046 (the line break before a boundary line belongs to the boundary, not the part).
- An attached email should not have a transfer encoding, but some mail programs base64-encode it anyway. Undoing it, as for any other attachment, lets `--inner` read it.

**The core's warnings name no command-line flag.** The Triage Report says the email may be a Wrapper Email and that, if so, the attached email should be triaged instead. The CLI's readable view adds `Hint: Use --inner to triage the attached email instead.`, worked out from `TriageReport.attached_emails()`, and drops it once `--inner` has been used. The core is meant to be reused by a later web-based alert queue, where `--inner` would mean nothing.

## Considered Options

- **Only `message/rfc822` parts**: simplest, but misses emails attached as `.eml` files, which some reporting tools produce. The analyst would get no warning and triage the report by mistake.
- **Recognising an attached email by its content (does the attachment look like an email?)**: catches oddly named files, but means reading inside every attachment, which goes against keeping attachments unopened (ADR 0001). It would also mistake a text file that happens to start with "From:" for an email.
- **Searching every level, picking the deepest email**: guesses which email the analyst meant. A report can legitimately contain a forwarded conversation, so guessing could triage the wrong one silently. One level, with a warning, keeps the analyst in charge.
- **Triaging every attached email in one run**: out of scope for Phase 1, which triages one email per run.
- **Hashing the attached email as Python rebuilds it (`as_bytes()`)**: simplest, and was the first version, but the hash then matched nothing outside this tool, not even the same phish saved directly.
- **Recovering the original bytes by matching Python's parsed parts to slices of the raw email**: keeps the parsed walk, but relies on two different splitters agreeing on every malformed email. Walking the raw email once, and parsing each part's headers from it, has a single source of truth.
- **Naming `--inner` in the core's warnings**: shorter, but ties the core to one front end.

## Consequences

- A `.eml` attachment that isn't really an email makes `--inner` stop with exit code 4, and the error says it is the attached email that isn't parseable (`UnparseableAttachedEmailError`), not the Wrapper Email.
- A quoted-printable attached email comes back with LF line endings, because quoted-printable can't carry CRLF exactly. Its hash then matches the phish saved with LF endings. Base64 and unencoded attached emails keep their bytes exactly.
- The attachment walk now splits multipart bodies itself. It follows the same boundary rules as Python's parser, but a badly malformed email could be split slightly differently from how Python would have.
- `--inner` on an email with nothing attached stops with exit code 8, rather than quietly triaging the Wrapper Email.
- Wrapper Email detection reads only the parts' declared types and filenames, so it adds nothing to what is sent to Providers.
