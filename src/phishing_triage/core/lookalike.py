"""Spotting Lookalike Domains: domains built to be mistaken for a Protected Domain.

This works on domain names alone and knows nothing about emails, so any rule
can use it: sender domains now, link domains later. It uses a handful of
rules of thumb rather than a library (ADR 0004).

Each Protected Domain is compared by its name, the first label of the domain
(`paypal` for `paypal.co.uk`). So Protected Domains should be listed as the
domain the organisation registered, not a deep subdomain of someone else's.
"""

from collections.abc import Iterable
from dataclasses import dataclass

# Names shorter than this only match exactly or after a character swap, never
# by being one letter off. Otherwise `dhl` would match `dhs`, `del`, `ahl`...
MIN_LENGTH_FOR_ONE_LETTER_OFF = 5

# Characters, or pairs of characters, that look alike at a glance. Both sides
# of a comparison are reduced to these plain forms, so `paypa1`, `paypai` and
# `paypal` all become the same.
LOOKALIKE_CHARACTERS = {
    "rn": "m",
    "vv": "w",
    "cl": "d",
    "0": "o",
    "1": "l",
    "i": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    # Non-Latin letters that look identical to Latin ones (Cyrillic, Greek).
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "l",
    "ѕ": "s",
    "ԁ": "d",
    "ο": "o",
    "ν": "v",
}


@dataclass(frozen=True)
class Lookalike:
    """A domain found imitating a Protected Domain, and how it does it."""

    imitated: str  # The Protected Domain being imitated.
    technique: str  # The trick, worded to follow "it", e.g. "adds words to ...".


def is_genuine(domain: str, protected_domains: Iterable[str]) -> bool:
    """Is `domain` one of the Protected Domains, or a subdomain of one?"""
    domain = _normalise(domain)
    return any(
        domain == protected or domain.endswith("." + protected)
        for protected in (_normalise(p) for p in protected_domains)
    )


def imitated_domain(domain: str, protected_domains: Iterable[str]) -> Lookalike | None:
    """Return the Protected Domain that `domain` imitates, or None.

    A genuine Protected Domain, or a subdomain of one, never counts.
    """
    protected_list = [_normalise(p) for p in protected_domains]
    if is_genuine(domain, protected_list):
        return None

    parts = _parts(_normalise(domain))
    for protected in protected_list:
        name = protected.split(".")[0]
        for part in parts:
            technique = _technique(part, name)
            if technique:
                return Lookalike(imitated=protected, technique=technique)
    return None


def _normalise(domain: str) -> str:
    return domain.strip().strip(".").lower()


def _parts(domain: str) -> list[str]:
    """The pieces of a domain worth comparing with a brand name.

    That's each label (the bits between dots) and each word of a hyphenated
    label. Internationalised labels (`xn--...`) are decoded so their real
    letters can be compared.
    `secure-paypal.com.evil.net` gives secure-paypal, secure, paypal, com,
    evil and net.
    """
    parts: list[str] = []
    for label in domain.split("."):
        label = _decode_punycode(label)
        parts.append(label)
        if "-" in label:
            parts += [word for word in label.split("-") if word]
    return parts


def _decode_punycode(label: str) -> str:
    """Turn `xn--pypal-4ve` back into the letters it stands for."""
    if not label.startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except UnicodeError:
        return label


def _technique(part: str, name: str) -> str | None:
    """How `part` imitates the brand `name`, or None if it doesn't."""
    if part == name:
        return f"reuses the name {name}"
    if name in part.split("-"):
        return f"adds words to the name {name}"
    if _plain_form(part) == _plain_form(name):
        if not part.isascii():
            return f"uses non-Latin letters ({part}) to look like {name}"
        return f"swaps characters to look like {name}"
    if len(name) >= MIN_LENGTH_FOR_ONE_LETTER_OFF and _one_letter_off(part, name):
        return f"is one letter off from {name}"
    return None


def _plain_form(text: str) -> str:
    """Replace every lookalike character with the plain letter it imitates."""
    for lookalike, plain in LOOKALIKE_CHARACTERS.items():
        text = text.replace(lookalike, plain)
    return text


def _one_letter_off(a: str, b: str) -> bool:
    """Do `a` and `b` differ by one letter added, dropped, changed or swapped?

    (In other words, an edit distance of exactly 1, counting a swap of two
    neighbouring letters as one edit.)
    """
    if a == b:
        return False

    if len(a) == len(b):
        differences = [i for i in range(len(a)) if a[i] != b[i]]
        if len(differences) == 1:
            return True  # One letter changed: micrasoft.
        if len(differences) == 2:
            first, second = differences
            # Two neighbouring letters swapped: paypla.
            return second == first + 1 and a[first] == b[second] and a[second] == b[first]
        return False

    if abs(len(a) - len(b)) != 1:
        return False
    shorter, longer = sorted((a, b), key=len)
    # One letter added or dropped: paypall, amazn.
    return any(longer[:i] + longer[i + 1 :] == shorter for i in range(len(longer)))
