"""Dangerous requests: money transfers, gift cards, codes, remote access,
passwords. These are what a scam is really after.

"We will never ask for your code" is a protective sentence and is ignored.
"""

from .models import SERIOUS, VERY_SERIOUS, Signal
from .text_signals import find_phrase

# Verbs that ask the reader to hand something over, unless aimed at "you"
# ("we will send you a code" is normal; "send us the code" is not).
# Verbs that ask the reader to hand something over, unless aimed at "you"
# ("we will send you a code" is normal; "send us the code" is not).
HAND_OVER = (r"\b(read|tell|give|send|text|share|reply with|forward|say|provide|"
             r"repeat|ask for|ask you for)\b(?!\s+(?:you|it to you)\b)")
TYPE_IN = r"\b(enter|type|confirm|verify|update|need)\b(?!\s+(?:you|it to you)\b)"

GIFT_CARDS = (
    r"\b(buy|purchase|get|pick up|pay (with|in|using)|send|load|use)\b[^.?!\n]{0,40}\b(gift ?cards?|itunes cards?|google play cards?|steam cards?|apple cards?|ebay cards?|vanilla (visa )?cards?|prepaid cards?)",
    r"\b(gift ?cards?|itunes|google play|steam|prepaid) cards?\b[^.?!\n]{0,50}\b(numbers?|pins?|codes?|back|claim)\b",
    r"\bgift ?cards?\b[^.?!\n]{0,50}\b(numbers?|pins?|codes?|back of the card|scratch)",
    r"\b(read|tell|give|send|text) (me|us)\b[^.?!\n]{0,50}\bgift ?cards?\b",
    r"\bscratch (off )?the (back|silver|strip)\b",
)
CODES = (
    HAND_OVER + r"[^.?!\n]{0,40}\b(code|otp|one[- ]time (pass)?code|passcode|verification number|security code|6[- ]digit)\b",
    r"\bwhat(?:'s| is) the (code|number) (we|you|that)\b",
)
REMOTE_ACCESS = (
    r"\b(anydesk|teamviewer|ultraviewer|logmein|rustdesk|supremo|screenconnect|connectwise|quick ?assist|zoho assist|splashtop|ammyy|gotoassist|remotepc)\b",
    r"\bremote (access|control|desktop|session|support (app|tool|program))\b",
    r"\b(access|control|into|see|connect to) your (computer|pc|laptop|screen|desktop)\b",
    r"\bshare your screen\b", r"\bscreen ?shar(e|ing)\b",
)
CREDENTIALS = (
    r"(" + HAND_OVER + "|" + TYPE_IN + r")[^.?!\n]{0,40}\b(password|passwords|pin( number)?|social security number|ssn|login details|username and password|online banking (login|details)|card number|cvv|security questions?|mother'?s maiden name|account number|medicare number)\b",
    r"\b(log ?in|sign ?in)\b[^.?!\n]{0,30}\bto (confirm|verify|unlock|restore)\b",
)
MONEY = (
    r"\bwire (transfer|the money|money|funds|it|\$)",
    r"\b(western union|moneygram|bitcoin|crypto(currency)? (atm|kiosk|wallet)|bitcoin atm)\b",
    r"(^|\b(you (need|have) to|you must|please|i need you to|we need you to|you should)\b)\s*(send|transfer|move|wire|withdraw)\b[^.?!\n]{0,40}\b(money|funds|cash|savings|\$\s?\d)",
    r"\b(safe|secure|protected|new) (account|wallet)\b[^.?!\n]{0,30}\b(move|transfer|keep|protect)|\b(move|transfer)\b[^.?!\n]{0,40}\b(safe|secure|protected) account\b",
    r"\b(processing|release|delivery|redelivery|customs|shipping|small|unlock|activation) fee\b",
    r"\bpay (a|the) (fee|fine|penalty)\b",
    r"\bcourier (will|to|is going to) (pick up|collect|come)\b",
    r"\b(by|with|through|over|via) (zelle|venmo|cash app)\b",
)


def _signal(found, code, weight, reason, explain, advice):
    return [Signal(code, weight, reason, explain, f'"{found}"', advice)] if found else []


def detect_gift_cards(text):
    return _signal(
        find_phrase(text, GIFT_CARDS), "gift_cards", VERY_SERIOUS,
        "It asks you to pay with gift cards.",
        "No real company, bank, or government office ever asks for payment "
        "in gift cards. This is always a scam.",
        "Do not buy any gift cards. If you already did, keep the receipt "
        "and call the card company's number on the back of the card.",
    )


def detect_code_request(text):
    return _signal(
        find_phrase(text, CODES), "code_request", VERY_SERIOUS,
        "It asks you to share a security code.",
        "A code sent to your phone is like a key to your account. Anyone "
        "who asks you to read it back is trying to get in.",
        "Never read or send a code to anyone, even if they say they are "
        "your bank.",
    )


def detect_remote_access(text):
    return _signal(
        find_phrase(text, REMOTE_ACCESS), "remote_access", VERY_SERIOUS,
        "It asks to get into your computer or phone.",
        "Programs like AnyDesk or TeamViewer let a stranger control your "
        "device and your bank account.",
        "Do not install anything. If you already did, turn off the device "
        "and ask a trusted helper to check it.",
    )


def detect_credentials(text):
    return _signal(
        find_phrase(text, CREDENTIALS), "credential_request", SERIOUS,
        "It asks for your password, PIN, or personal numbers.",
        "Real companies never ask for your password or PIN by text, email, "
        "or phone.",
        "Do not share passwords, PINs, or your Social Security number.",
    )


def detect_money_request(text):
    return _signal(
        find_phrase(text, MONEY), "money_request", SERIOUS,
        "It asks you to send money or pay a fee.",
        "Scammers ask for wire transfers, payment apps, crypto, cash, or "
        "small fees because the money cannot be gotten back.",
        "Do not send money. If you already did, call your bank right away.",
    )


def detect_dangerous_requests(text):
    return (detect_gift_cards(text) + detect_code_request(text)
            + detect_remote_access(text) + detect_credentials(text)
            + detect_money_request(text))
