"""Finding the URLs in an email, decoding them offline, and defanging them for display.

Everything here works on text only. Nothing fetches, follows or expands a URL,
so an attacker never learns the email is being looked at (ADR 0001).
"""

import html
import re
from email.message import EmailMessage
from html.parser import HTMLParser
from urllib.parse import SplitResult, parse_qs, urlsplit

from phishing_triage.core.body import body_parts, text_of

# A URL starts with http(s):// or www. and runs until a space, angle bracket or quote.
URL_PATTERN = re.compile(r"\b(?:https?://|www\.)[^\s<>\"'`]+", re.IGNORECASE)

# Punctuation that usually ends the sentence around a URL rather than the URL itself.
TRAILING_PUNCTUATION = ".,;:!?)]}"

# Defanged forms analysts and attackers use to stop a URL being clickable,
# each with the text it stands for.
DEFANGED_FORMS = (
    (re.compile(r"\bhxxp(s?)(?=\[?:)", re.IGNORECASE), r"http\1"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[://\]"), "://"),
)

# Link wrappers that carry the real URL in a query parameter:
# (wrapper's domain, path or None for any path, parameter holding the real URL).
LINK_WRAPPERS = (
    ("safelinks.protection.outlook.com", None, "url"),  # Microsoft SafeLinks
    ("google.com", "/url", "q"),  # Google redirect links, often abused as open redirects
)

# A link wrapped more times than this is left as it is, so a crafted link
# can't keep the unwrapping loop busy.
MAX_UNWRAPS = 5


def find_urls(message: EmailMessage) -> list[str]:
    """Return every URL in the email's plain-text and HTML bodies, decoded, without repeats.

    Attachments are not read. In HTML, both link targets and visible text are
    searched; image addresses are not, as they are mostly tracking pixels.
    """
    urls: list[str] = []
    for part in body_parts(message):
        if part.get_content_type() == "text/html":
            pieces = _html_pieces(text_of(part))
        else:
            pieces = [text_of(part)]
        for piece in pieces:
            urls += [_unwrap(url) for url in _urls_in_text(piece)]
    return list(dict.fromkeys(urls))


def host_of(url: str) -> str:
    """Return a URL's host, lowercased, or "" if it has none."""
    parts = _split(url)
    return (parts.hostname or "") if parts else ""


def defang_url(url: str) -> str:
    """Make a URL unclickable for display: https://evil.com/a becomes hxxps://evil[.]com/a."""
    scheme, separator, rest = url.partition("://")
    if not separator:
        return defang_domain(url)
    host_end = min((rest.index(c) for c in "/?#" if c in rest), default=len(rest))
    host, after_host = rest[:host_end], rest[host_end:]
    return f"{re.sub('^http', 'hxxp', scheme)}://{defang_domain(host)}{after_host}"


def defang_domain(domain: str) -> str:
    """Make a domain unclickable for display: evil.com becomes evil[.]com."""
    return domain.replace(".", "[.]")


def defang_email_address(address: str) -> str:
    """Make an email address's domain unclickable for display: billing@evil.com becomes billing@evil[.]com."""
    local_part, at, domain = address.rpartition("@")
    return f"{local_part}{at}{defang_domain(domain)}"


class _HtmlPieces(HTMLParser):
    """Collects link targets and visible text from HTML, in document order.

    convert_charrefs=True makes the parser decode HTML entities such as
    &#46; in both text and attribute values.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.pieces: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.pieces += [value for name, value in attrs if name == "href" and value]

    def handle_data(self, data: str) -> None:
        self.pieces.append(data)


def _html_pieces(html_text: str) -> list[str]:
    parser = _HtmlPieces()
    parser.feed(html_text)
    parser.close()
    return parser.pieces


def _urls_in_text(text: str) -> list[str]:
    """Find URLs in a piece of text, after decoding entities and defanged forms."""
    text = html.unescape(text)
    for pattern, replacement in DEFANGED_FORMS:
        text = pattern.sub(replacement, text)
    found = (match.group().rstrip(TRAILING_PUNCTUATION) for match in URL_PATTERN.finditer(text))
    return [_normalise(url) for url in found]


def _normalise(url: str) -> str:
    """Give a URL a scheme and lowercase its scheme and host, so duplicates match."""
    if url.lower().startswith("www."):
        url = "http://" + url
    parts = _split(url)
    if parts is None:
        return url
    return parts._replace(scheme=parts.scheme.lower(), netloc=parts.netloc.lower()).geturl()


def _unwrap(url: str) -> str:
    """Return the real URL inside any link wrappers, reading it as text."""
    for _ in range(MAX_UNWRAPS):
        inner = _wrapped_url(url)
        if inner is None:
            break
        url = inner
    return url


def _wrapped_url(url: str) -> str | None:
    """If `url` is a link wrapper, return the URL it carries, otherwise None."""
    parts = _split(url)
    if parts is None:
        return None
    host = parts.hostname or ""
    for wrapper_domain, path, parameter in LINK_WRAPPERS:
        on_wrapper = host == wrapper_domain or host.endswith("." + wrapper_domain)
        if on_wrapper and (path is None or parts.path == path):
            # parse_qs also decodes %-escapes, turning https%3A%2F%2F back into https://.
            values = parse_qs(parts.query).get(parameter, [])
            if values and URL_PATTERN.fullmatch(values[0]):
                return _normalise(values[0])
    return None


def _split(url: str) -> SplitResult | None:
    """Split a URL into its parts, or return None if it's too malformed to split."""
    try:
        return urlsplit(url)
    except ValueError:
        return None
