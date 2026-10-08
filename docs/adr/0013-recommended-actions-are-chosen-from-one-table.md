# Recommended Actions are chosen from one table

Ticket 15 ends the Incident Note with **Recommended Actions**: next steps for the analyst, such as blocking the IOCs or searching mailboxes for copies. Four choices shape how they are picked.

**The whole choice is one table, `RECOMMENDED_ACTIONS`.**
- Each row pairs a condition on the Triage Report with the action's wording, and both are functions of the report. The rows are in the order the actions appear in the note.
- The conditions only look at the Verdict, which Findings fired, whether the email had links or attachments, the IOCs, and what was Not Checked. Choosing actions never changes the report, so, like the Incident Note, it is a pure function.
- Two groups of Findings are named at the top of the module, so they are easy to read and change:
  - **Credential-phishing signs** (suggest a password reset when the email has a link): Lookalike Domain, display-name impersonation and newly registered domain. Each points at a fake login page dressed up as someone trusted.
  - **Impersonation signs** (suggest confirming with the apparent sender by a known contact): Reply-To mismatch and display-name impersonation.

**"Close with no action" only when nothing else applies.** It needs a clean Verdict, nothing Not Checked, and no other row applying. A clean email with a Reply-To mismatch still says to confirm with the sender, and telling the analyst to close it in the same breath would contradict that.

**The sender domain is blocked on its own only if it isn't already an IOC.** A malicious email's sender domain is worth blocking even when no Provider flagged it. But if a Provider did flag it, it is already in the list of IOCs to block, and a second "block" line would be noise.

**Actions are only ever suggested.** Every action is text. No code path blocks, searches, resets or emails anything, in the same spirit as ADR 0001: the tool looks things up and reports, and the analyst decides what to do.

## Considered Options

- **A chain of `if` statements building the list**: works, but the rules for one action end up spread across the chain, and the order of the note is harder to see.
- **Actions decided by Score bands**: simpler, but a Score doesn't say what kind of attack it is. "Reset passwords" only makes sense when there was a link and a sign of a fake login page.
- **Carrying out the safe actions (such as searching mailboxes)**: would save time, but needs mailbox access and permission the tool shouldn't hold, and goes against ADR 0001.

## Consequences

- Adding an action is one new row, plus its condition if it needs a new question about the report.
- The close row asks every other row whether it applies, so a new action automatically stops a clean email from being closed when it fires.
- The Incident Note lists IOCs apart from the other Observables, using the same definition (an Observable a Provider reported as malicious), so the IOC section and the block action always agree.
