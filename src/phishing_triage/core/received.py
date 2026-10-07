"""The Received chain: the route an email took, one hop per mail server.

Each server that handles an email adds a Received header at the top, so
the bottom one is the earliest. The sender can write fake Received headers
before sending, but they can only ever sit below the real ones.
"""

import ipaddress
import re
from dataclasses import dataclass
from email.message import EmailMessage

# The words that start each part of a Received header, e.g. "from x by y with z".
KEYWORDS = frozenset({"from", "by", "via", "with", "id", "for"})

# An IP address in square brackets, as servers write the address they saw.
BRACKETED_IP = re.compile(r"\[(?:IPv6:)?([0-9a-f:.]+)\]", re.IGNORECASE)
# Anything that might be an IP address, checked properly by the ipaddress module.
IP_LIKE = re.compile(r"[0-9a-f:.]+", re.IGNORECASE)
# The name the sending server gave in its greeting (HELO), which it chose itself.
HELO = re.compile(r"\b(?:helo|ehlo)[=\s]+\S+", re.IGNORECASE)


@dataclass(frozen=True)
class ReceivedHop:
    """One server passing the email on, as that server recorded it."""

    # The name the sending server gave for itself, or "" if not recorded.
    from_name: str
    # The sending server's IP address as the receiving server saw it, or "".
    from_ip: str
    # The server that added this header (and received the email), lowercased.
    by_host: str
    # When it was received, as written, or "".
    received_at: str
    # The whole header, on one line, so the analyst can check the parsing.
    header: str


def read_received_chain(message: EmailMessage) -> list[ReceivedHop]:
    """Parse the Received headers into hops, earliest first (the order the email travelled)."""
    headers = message.get_all("Received") or []
    return [_parse_hop(" ".join(str(header).split())) for header in reversed(headers)]


def _parse_hop(header: str) -> ReceivedHop:
    """Parse one Received header, such as
    "from a.example (a.example [192.0.2.1]) by b.example with ESMTP id 12; Mon, 5 Oct 2026 ...".

    Real servers write these in many slightly different ways, so this is
    best effort: anything it can't find is left as "".
    """
    route, _, received_at = header.rpartition(";")
    if not route:  # No date: the whole header is the route.
        route, received_at = received_at, ""

    parts = _route_parts(route)
    from_parts = parts.get("from", [])
    from_name = from_parts[0] if from_parts and not from_parts[0].startswith("(") else ""
    by_parts = parts.get("by", [])
    by_host = by_parts[0].rstrip(".").lower() if by_parts else ""

    return ReceivedHop(
        from_name=from_name,
        from_ip=_observed_ip(from_parts),
        by_host=by_host,
        received_at=received_at.strip(),
        header=header,
    )


def _route_parts(route: str) -> dict[str, list[str]]:
    """Group the words of a route under the keyword they follow.

    "from a (b [192.0.2.1]) by c" gives {"from": ["a", "(b [192.0.2.1])"], "by": ["c"]}.
    A (comment) stays whole, so keywords inside it are ignored.
    """
    parts: dict[str, list[str]] = {}
    current: list[str] | None = None
    for word in _words_and_comments(route):
        keyword = word.lower()
        if keyword in KEYWORDS and keyword not in parts:
            current = parts[keyword] = []
        elif current is not None:
            current.append(word)
    return parts


def _words_and_comments(text: str) -> list[str]:
    """Split on spaces, keeping each (comment, even with spaces) as one piece."""
    pieces: list[str] = []
    current = ""
    depth = 0
    for character in text:
        if character.isspace() and depth == 0:
            if current:
                pieces.append(current)
            current = ""
            continue
        current += character
        if character == "(":
            depth += 1
        elif character == ")":
            depth = max(depth - 1, 0)
    if current:
        pieces.append(current)
    return pieces


def _observed_ip(from_parts: list[str]) -> str:
    """The IP the receiving server saw the sender connect from, or "".

    In "from evil.example (host.example [192.0.2.1])", the first name is
    whatever the sender claimed in its greeting. The (comment) holds what
    the receiving server saw, so it is searched first, and bracketed IPs
    before bare ones. Any greeting (helo=...) is ignored.
    """
    comments = HELO.sub("", " ".join(part for part in from_parts if part.startswith("(")))
    everything = HELO.sub("", " ".join(from_parts))
    for pattern in (BRACKETED_IP, IP_LIKE):
        for text in (comments, everything):
            for candidate in pattern.findall(text):
                if ip := _as_ip(candidate):
                    return ip
    return ""


def _as_ip(text: str) -> str:
    """`text` written as a standard IP address, or "" if it isn't one."""
    try:
        return str(ipaddress.ip_address(text.strip(".:")))
    except ValueError:
        return ""


@dataclass(frozen=True)
class ClaimedOrigin:
    """The IP address the email appears to have been sent from.

    Unverified unless a Trusted Relay recorded it, because the sender can
    forge every hop below the ones real servers added.
    """

    ip: str
    # The server whose Received header names this IP.
    recorded_by: str
    # True only when that server is a Trusted Relay.
    verified: bool


def find_claimed_origin(hops: list[ReceivedHop], trusted_relays: tuple[str, ...]) -> ClaimedOrigin | None:
    """Where the email appears to have come from, or None if no public IP was found.

    If a Trusted Relay recorded a public IP, that is the Claimed Origin, and
    it is verified. Otherwise it is the earliest public IP in the chain,
    unverified. Private and reserved addresses (10.x, 127.0.0.1, 192.0.2.x
    and so on) are skipped: they name machines inside a network, not where
    the email came from on the internet.
    """
    recorded_by_relay = _recorded_by_trusted_relay(hops, trusted_relays)
    if recorded_by_relay:
        return recorded_by_relay
    for hop in hops:
        if _is_public(hop.from_ip):
            return ClaimedOrigin(ip=hop.from_ip, recorded_by=hop.by_host, verified=False)
    return None


def _recorded_by_trusted_relay(
    hops: list[ReceivedHop], trusted_relays: tuple[str, ...]
) -> ClaimedOrigin | None:
    """The public IP a Trusted Relay recorded, or None.

    The walk starts at the latest (topmost) header a Trusted Relay added,
    which is real: forged headers can only sit below it, and stops at the
    first public IP a Trusted Relay recorded. It moves down past a trusted
    hop only when that hop shows the email came from the organisation's own
    servers: it recorded a private IP, or no sender at all (delivery within
    one server). Anything else, including a sender whose IP couldn't be
    read, stops the walk, because the next header down could have been
    written by the outside sender, even one claiming to be a Trusted Relay.
    """
    walking = False
    for hop in reversed(hops):  # Latest first.
        if not _is_trusted(hop.by_host, trusted_relays):
            if walking:
                return None
            continue  # Not reached a Trusted Relay yet.
        walking = True
        if _is_public(hop.from_ip):
            return ClaimedOrigin(ip=hop.from_ip, recorded_by=hop.by_host, verified=True)
        recorded_a_private_ip = hop.from_ip != ""  # Public IPs were dealt with above.
        recorded_no_sender = hop.from_name == "" and hop.from_ip == ""
        if not (recorded_a_private_ip or recorded_no_sender):
            return None
    return None


def _is_trusted(host: str, trusted_relays: tuple[str, ...]) -> bool:
    """Is `host` a Trusted Relay, or a subdomain of one? Case doesn't matter."""
    relays = (relay.lower() for relay in trusted_relays)
    return any(host == relay or host.endswith("." + relay) for relay in relays)


def _is_public(ip: str) -> bool:
    return bool(ip) and ipaddress.ip_address(ip).is_global
