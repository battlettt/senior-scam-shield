"""Turn pasted text into a Message: headers, plain body, links, channel.

Everything here is treated as a claim. A "From:" line can be typed by
anyone, so it is only ever used to spot inconsistencies, never as proof.
"""

import re
from email.utils import parseaddr
from html import unescape
from html.parser import HTMLParser

from .models import Message
from .urls import extract_links

CHANNELS = ("sms", "email", "call")
HEADER_KEYS = {"from", "to", "subject", "reply-to", "date", "sender", "cc",
               "caller id", "number", "sent", "received"}
HEADER_LINE = re.compile(r"^\s*([A-Za-z][A-Za-z -]{0,14}):\s*(.*?)\s*$")
HTML_HINT = re.compile(r"<\s*(a|html|body|p|div|br|table|span)\b", re.I)
SPEAKER_LABELS = {"caller", "me", "agent", "operator", "representative", "rep",
                  "scammer", "officer", "voice", "recording", "them", "you", "i"}
SPEAKER_LINE = re.compile(r"^\s*([A-Z][\w .'()-]{0,24}):\s+\S", re.M)


class _HTMLText(HTMLParser):
    """Collect visible text and (text, href) pairs for every <a> tag."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.chunks = []
        self.anchors = []
        self._href = None
        self._anchor_text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._anchor_text = []
        elif tag in ("br", "p", "div", "tr", "li"):
            self.chunks.append("\n")

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.anchors.append((" ".join(self._anchor_text).strip(), self._href))
            self._href = None

    def handle_data(self, data):
        self.chunks.append(data)
        if self._href is not None:
            self._anchor_text.append(data.strip())


def html_to_text(html):
    parser = _HTMLText()
    parser.feed(html)
    parser.close()
    text = re.sub(r"[ \t]+", " ", "".join(parser.chunks))
    return re.sub(r"\n\s*\n+", "\n\n", text).strip(), parser.anchors


def split_headers(raw):
    """Leading 'Key: value' lines become headers; the rest is the body."""
    headers = {}
    lines = (raw or "").replace("\r\n", "\n").split("\n")
    index = 0
    while index < len(lines) and not lines[index].strip():
        index += 1
    while index < len(lines):
        match = HEADER_LINE.match(lines[index])
        if not match or match.group(1).strip().lower() not in HEADER_KEYS:
            break
        headers.setdefault(match.group(1).strip().lower(), match.group(2))
        index += 1
    return headers, "\n".join(lines[index:]).strip()


def looks_like_dialogue(body):
    """Two or more speakers, with a known speaker label or a repeated one."""
    labels = [m.group(1).strip().lower() for m in SPEAKER_LINE.finditer(body)]
    if len(set(labels)) < 2:
        return False
    repeated = len(labels) > len(set(labels))
    return repeated or any(label in SPEAKER_LABELS for label in labels)


def detect_channel(headers, body):
    sender = headers.get("from", "") or headers.get("sender", "")
    if "subject" in headers or "@" in parseaddr(sender)[1] or HTML_HINT.search(body):
        return "email"
    if "caller id" in headers or looks_like_dialogue(body):
        return "call"
    if re.search(r"(?i)\b(transcript|voicemail|voice mail)\b", body[:200]):
        return "call"
    return "sms"


def parse_message(raw, channel=None):
    """Parse pasted text. channel may be 'sms', 'email', 'call', or None/'auto'."""
    headers, body = split_headers(raw)
    anchors = []
    if HTML_HINT.search(body):
        body, anchors = html_to_text(body)
    else:
        body = unescape(body)
    if channel not in CHANNELS:
        channel = detect_channel(headers, body)
    sender = headers.get("from") or headers.get("sender") or headers.get("caller id") or headers.get("number") or ""
    name, address = parseaddr(sender) if "@" in sender else ("", "")
    reply_to = parseaddr(headers.get("reply-to", ""))[1]
    return Message(
        channel=channel,
        body=body,
        raw=raw or "",
        sender=sender.strip(),
        sender_name=name.strip(),
        sender_address=address.strip().lower(),
        reply_to=reply_to.strip().lower(),
        subject=headers.get("subject", "").strip(),
        links=extract_links(body, anchors),
    )


def sender_kind(message):
    """'email', 'short_code', 'phone', 'name', or 'unknown'."""
    if message.sender_address:
        return "email"
    sender = message.sender.strip()
    if not sender:
        return "unknown"
    digits = re.sub(r"\D", "", sender)
    if re.fullmatch(r"[\d\s()+.-]+", sender):
        if 4 <= len(digits) <= 6:
            return "short_code"
        if len(digits) >= 7:
            return "phone"
    return "name"


def full_text(message):
    """Everything a person would read: sender name, subject, and body."""
    return "\n\n".join(part for part in (message.sender_name, message.subject, message.body) if part)
