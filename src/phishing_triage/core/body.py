"""Reading an email's body: its plain-text and HTML parts, never its attachments.

Everything here is done locally. Body text is never sent anywhere.
"""

from collections.abc import Iterator
from email.message import EmailMessage
from html.parser import HTMLParser

# HTML tags whose content is never shown to the reader.
HIDDEN_TAGS = frozenset({"script", "style", "head", "title"})

# HTML tags that start a new line or block, so the words either side of them
# shouldn't run together ("<p>Verify</p><p>now</p>" reads "Verify now").
BLOCK_TAGS = frozenset(
    {"p", "div", "br", "li", "ul", "ol", "tr", "td", "th", "table", "h1", "h2", "h3",
     "h4", "h5", "h6", "blockquote", "section", "article", "header", "footer", "hr"}
)


def body_parts(part: EmailMessage) -> Iterator[EmailMessage]:
    """Yield the plain-text and HTML body parts, skipping attachments entirely."""
    if part.is_attachment():
        return
    if part.is_multipart():
        for sub_part in part.iter_parts():
            assert isinstance(sub_part, EmailMessage)  # guaranteed by policy.default
            yield from body_parts(sub_part)
    elif part.get_content_type() in ("text/plain", "text/html"):
        yield part


def text_of(part: EmailMessage) -> str:
    """Return a body part's text, coping with a wrong or unknown character set."""
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
    except (LookupError, UnicodeError):
        pass
    payload = part.get_payload(decode=True)
    return payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else ""


def readable_text(message: EmailMessage) -> str:
    """The body as text: plain text, plus HTML with its tags removed.

    Scripts, styles and attachments are left out, and HTML entities such as
    &nbsp; are decoded. Text hidden with CSS (display:none) is kept: hidden
    wording is itself worth noticing, and working out what CSS hides would
    mean interpreting styles, which is out of reach for a text check.
    """
    texts = []
    for part in body_parts(message):
        text = text_of(part)
        texts.append(_visible_text(text) if part.get_content_type() == "text/html" else text)
    return "\n".join(texts)


class _VisibleText(HTMLParser):
    """Collects an HTML email's text, skipping scripts and styles.

    convert_charrefs=True makes the parser decode HTML entities for us.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.pieces: list[str] = []
        self._hidden_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in HIDDEN_TAGS:
            self._hidden_depth += 1
        elif tag in BLOCK_TAGS:
            self.pieces.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in HIDDEN_TAGS:
            self._hidden_depth = max(self._hidden_depth - 1, 0)
        elif tag in BLOCK_TAGS:
            self.pieces.append(" ")

    def handle_data(self, data: str) -> None:
        if not self._hidden_depth:
            self.pieces.append(data)


def _visible_text(html_text: str) -> str:
    parser = _VisibleText()
    parser.feed(html_text)
    parser.close()
    return "".join(parser.pieces)
