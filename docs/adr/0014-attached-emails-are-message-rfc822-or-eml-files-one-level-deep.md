# Attached emails are message/rfc822 parts or .eml files, one level deep

Ticket 06 warns when the email being triaged is a **Wrapper Email** (a user's report with the suspected phish attached), and `--inner` triages the attached email instead. That needs a clear answer to "what counts as an attached email?" and "which one is the first?". Four choices shape it.

**An attached email is a message/rfc822 part, or an attachment whose filename ends in `.eml`.**
- Forwarding "as attachment" in most mail programs attaches the email with the declared type `message/rfc822`. That is the standard way, and Python's email parser understands it.
- Some mail programs and webmail exports attach the email as an ordinary file called something like `phish.eml`, declared as `application/octet-stream`. An analyst would call that an attached email too, so it counts.
- Anything else, such as an Outlook `.msg` file, does not count. `.msg` is a different, binary format the tool can't read as an email.

**Only emails attached directly to the email count, never ones inside an attached email.** Finding attached emails uses the same walk over the parts as describing attachments (`attachment_parts()` in `core/attachments.py`), which deliberately never looks inside an attached email. So `--inner` goes exactly one level deep. If the attached email has an email attached too (a report of a report), the Triage Report says so and the analyst extracts it by hand.

**"First" means first in the order the parts appear in the email.** That is the order the attachments are listed in the Triage Report, so "the first attached email" is the first one the analyst sees there. When there are several, the warnings say how many, and that only the first was triaged.

**The triaged email's SHA-256 is of the attached email's bytes, exactly as they are hashed as an attachment.** So `source_sha256` in the inner Triage Report matches the attachment's SHA-256 in the Wrapper Email's report, and the two reports can be linked. The Wrapper Email's own SHA-256 is kept in `taken_from_wrapper_sha256` (empty when the email wasn't taken from a Wrapper Email).

## Considered Options

- **Only `message/rfc822` parts**: simplest, but misses emails attached as `.eml` files, which some reporting tools produce. The analyst would get no warning and triage the report by mistake.
- **Recognising an attached email by its content (does the attachment look like an email?)**: catches oddly named files, but means reading inside every attachment, which goes against keeping attachments unopened (ADR 0001). It would also mistake a text file that happens to start with "From:" for an email.
- **Searching every level, picking the deepest email**: guesses which email the analyst meant. A report can legitimately contain a forwarded conversation, so guessing could triage the wrong one silently. One level, with a warning, keeps the analyst in charge.
- **Triaging every attached email in one run**: out of scope for Phase 1, which triages one email per run.

## Consequences

- A `.eml` attachment that isn't really an email makes `--inner` stop with the "not a parseable email" error (exit code 4), which is honest.
- `--inner` on an email with nothing attached stops with exit code 8, rather than quietly triaging the Wrapper Email.
- Wrapper Email detection reads only the parts' declared types and filenames, so it adds nothing to what is sent to Providers.
