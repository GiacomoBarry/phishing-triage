"""Authentication results: what the receiving server recorded for SPF, DKIM and DMARC.

They are only ever read from the Authentication-Results header, never
re-checked with live DNS. By the time an email is reported, DNS records
may have changed, and the receiving server's decision at delivery time is
the one that mattered.
"""

import re
from dataclasses import dataclass
from email.message import EmailMessage

NOT_RECORDED = "not recorded"


@dataclass(frozen=True)
class AuthenticationCheck:
    """The recorded result of one check, such as SPF."""

    # "pass", "fail", another recorded value such as "softfail", or "not recorded".
    result: str
    # The check as the server wrote it, e.g. "spf=fail smtp.mailfrom=example.org",
    # or "" if it wasn't recorded.
    recorded: str


@dataclass(frozen=True)
class AuthenticationResults:
    """SPF, DKIM and DMARC as recorded by the receiving server."""

    # Whether there was an Authentication-Results header at all.
    header_found: bool
    # The server that recorded the results (the header's authserv-id), or ""
    # if the header doesn't name it, as Microsoft 365's doesn't.
    recorded_by: str
    spf: AuthenticationCheck
    dkim: AuthenticationCheck
    dmarc: AuthenticationCheck


# The start of a recorded check, e.g. "dkim=pass" or "SPF = fail".
CHECK = re.compile(r"(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)


def read_authentication_results(message: EmailMessage) -> AuthenticationResults:
    """Read SPF, DKIM and DMARC from the topmost Authentication-Results header.

    The topmost header is the one added last, by the server that delivered
    the email to the recipient. Headers lower down were added earlier, and
    may have been written by the sender. A check missing from the header (or
    no header at all) is "not recorded", which is not the same as a fail.
    """
    header = message.get("Authentication-Results")
    if header is None:
        return AuthenticationResults(
            header_found=False,
            recorded_by="",
            spf=AuthenticationCheck(NOT_RECORDED, ""),
            dkim=AuthenticationCheck(NOT_RECORDED, ""),
            dmarc=AuthenticationCheck(NOT_RECORDED, ""),
        )

    # The header is normally "authserv-id; check; check; ...", but some
    # servers leave out the authserv-id and start straight with a check.
    clauses = _split_clauses(" ".join(str(header).split()))
    recorded_by = ""
    if not CHECK.match(clauses[0]):
        first = clauses.pop(0)
        recorded_by = first.split()[0] if first.split() else ""

    found: dict[str, list[AuthenticationCheck]] = {}
    for clause in clauses:
        match = CHECK.match(clause)
        if match:
            method, result = match[1].lower(), match[2].lower()
            found.setdefault(method, []).append(AuthenticationCheck(result, clause))

    return AuthenticationResults(
        header_found=True,
        recorded_by=recorded_by,
        spf=_one_result(found.get("spf", [])),
        dkim=_one_result(found.get("dkim", [])),
        dmarc=_one_result(found.get("dmarc", [])),
    )


def _one_result(checks: list[AuthenticationCheck]) -> AuthenticationCheck:
    """Pick the result that stands for a check recorded zero or more times.

    An email can carry several DKIM signatures, and one passing is enough:
    that's also how DMARC treats them. Otherwise the first one recorded counts.
    """
    if not checks:
        return AuthenticationCheck(NOT_RECORDED, "")
    passes = [check for check in checks if check.result == "pass"]
    return passes[0] if passes else checks[0]


def _split_clauses(header: str) -> list[str]:
    """Split the header on semicolons, ignoring any inside (comments).

    A comment such as "(sender; checked)" belongs to its clause.
    """
    clauses = [""]
    depth = 0
    for character in header:
        if character == "(":
            depth += 1
        elif character == ")":
            depth = max(depth - 1, 0)
        if character == ";" and depth == 0:
            clauses.append("")
        else:
            clauses[-1] += character
    return [clause.strip() for clause in clauses]
