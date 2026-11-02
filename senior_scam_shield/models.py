"""Shared data shapes: a parsed message, a link, and a detected signal."""

from dataclasses import dataclass, field

# Signal weights. One VERY_SERIOUS signal alone is enough for LIKELY SCAM.
VERY_SERIOUS = 45
SERIOUS = 30
CAUTION = 15
MINOR = 8


@dataclass(frozen=True)
class Link:
    href: str
    text: str = ""  # what the reader sees, if it differs from the address


@dataclass(frozen=True)
class Signal:
    code: str
    weight: int
    reason: str  # one short plain-English sentence
    explain: str  # why it matters, in simple words
    evidence: str = ""  # what we found in the message
    advice: str = ""  # an extra "what to do" step, if any


@dataclass
class Message:
    channel: str  # "sms", "email", or "call"
    body: str  # plain text the person reads (HTML removed)
    raw: str = ""
    sender: str = ""  # as shown in the message; it may be fake
    sender_name: str = ""
    sender_address: str = ""  # email address, lower case
    reply_to: str = ""
    subject: str = ""
    links: list = field(default_factory=list)


def severity_label(weight):
    if weight >= VERY_SERIOUS:
        return "VERY SERIOUS"
    if weight >= SERIOUS:
        return "SERIOUS"
    if weight >= CAUTION:
        return "CAUTION"
    return "MINOR"
