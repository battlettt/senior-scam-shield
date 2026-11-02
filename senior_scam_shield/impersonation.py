"""Impersonation: the message claims to be a bank, agency, or brand, but
the sender, channel, or links do not fit that claim.

A matching sender never adds trust, because sender details can be faked.
Only mismatches are reported.
"""

from . import brands
from .message import full_text, sender_kind
from .models import CAUTION, SERIOUS, VERY_SERIOUS, Signal
from .urls import hostname_of, imitated_brand

DANGEROUS_CODES = {"gift_cards", "code_request", "remote_access",
                   "credential_request", "money_request"}


def describe(brand):
    return {"bank": "a bank", "government": "a government office"}.get(brand.kind, "a company")


def check_email_sender(message, brand):
    domain = message.sender_address.rsplit("@", 1)[-1]
    if not domain or brands.is_official_domain(brand, domain):
        return []
    shown = message.sender_address
    if brands.is_free_mailbox(domain):
        return [Signal(
            "sender_free_mailbox", SERIOUS,
            f"It claims to be {brand.name} but came from a free personal email account.",
            f"{brand.name} sends email from its own address, not from "
            "Gmail, Yahoo, Outlook, or similar free accounts.",
            f'sent from "{shown}"',
            f"Contact {brand.name} using the number on your card, bill, or statement.",
        )]
    if imitated_brand(domain):
        return [Signal(
            "sender_lookalike_domain", VERY_SERIOUS,
            f"It claims to be {brand.name} but the sender address is a fake copy.",
            f"The address uses the name {brand.name}, but {brand.name}'s real "
            f"email comes from {brand.domains[0]}.",
            f'sent from "{shown}"',
            f"Contact {brand.name} using the number on your card, bill, or statement.",
        )]
    return [Signal(
        "sender_wrong_domain", CAUTION,
        f"It claims to be {brand.name} but the sender address is not {brand.name}'s.",
        "The email address it came from belongs to someone else.",
        f'sent from "{shown}"',
    )]


def check_sms_sender(message, brand):
    kind = sender_kind(message)
    if kind == "phone" and brand.kind in ("bank", "government"):
        return [Signal(
            "sender_personal_number", CAUTION,
            f"It claims to be {brand.name} but came from a regular phone number.",
            "Banks and government offices usually text from short numbers "
            "(5 or 6 digits), not from a personal phone number.",
            f'sent from "{message.sender}"',
        )]
    if kind == "email":
        return check_email_sender(message, brand)
    return []


def check_reply_to(message):
    if not (message.reply_to and message.sender_address):
        return []
    sent_from = brands.registrable_domain(message.sender_address.rsplit("@", 1)[-1])
    reply_goes = brands.registrable_domain(message.reply_to.rsplit("@", 1)[-1])
    if sent_from == reply_goes:
        return []
    return [Signal(
        "reply_to_mismatch", CAUTION,
        "Replies would go to a different address than the sender.",
        "If you press Reply, your answer goes to someone else. Scammers do "
        "this to catch your reply.",
        f'from "{message.sender_address}", replies go to "{message.reply_to}"',
    )]


def check_links_for(message, brand):
    """Links in a message that claims to be this brand, but go elsewhere."""
    for link in message.links:
        host = hostname_of(link.href)
        if not host or brands.is_official_domain(brand, host) or imitated_brand(host):
            continue  # official, or already reported as a lookalike
        return [Signal(
            "link_not_official", SERIOUS,
            f"It claims to be {brand.name}, but its link does not go to {brand.name}'s website.",
            f"{brand.name}'s real website is {brand.domains[0]}. This link "
            "goes somewhere else.",
            f'link goes to "{host}"',
            f"Do not use the link. Type {brand.domains[0]} yourself, or call "
            "the number on your card.",
        )]
    return []


def check_request_fits_brand(message, brand, other_codes):
    """Real banks and agencies never ask for these things."""
    asked = other_codes & DANGEROUS_CODES
    if not asked or brand.kind not in ("bank", "government"):
        return []
    if brand.kind == "government":
        reason = f"It claims to be {brand.name} and asks for money or private details."
        explain = ("Government offices do not call, text, or email to demand "
                   "payment, codes, or gift cards.")
    else:
        reason = f"It claims to be {brand.name} and asks for something a real bank never asks for."
        explain = ("Real banks never ask for codes, passwords, gift cards, or "
                   "for money to be moved to keep it safe.")
    return [Signal(
        "impersonation_request", SERIOUS, reason, explain,
        f'claims to be {describe(brand)}: {brand.name}',
        f"Hang up or stop replying. Call {brand.name} yourself using a number you trust.",
    )]


def main_claimed_brand(message):
    """The brand the message mainly claims to be, or None."""
    claimed = brands.find_claimed_brands(full_text(message) + "\n" + message.sender_address)
    sender_domain = message.sender_address.rsplit("@", 1)[-1]
    for brand in claimed:
        if sender_domain and brands.is_official_domain(brand, sender_domain):
            return brand
    return claimed[0] if claimed else None


def detect_impersonation(message, other_codes=frozenset()):
    """Signals for the brand claimed, plus any reply-to trick."""
    signals = check_reply_to(message)
    brand = main_claimed_brand(message)
    if not brand:
        return signals
    if message.channel == "email":
        signals += check_email_sender(message, brand)
    elif message.channel == "sms":
        signals += check_sms_sender(message, brand)
    signals += check_links_for(message, brand)
    signals += check_request_fits_brand(message, brand, set(other_codes))
    return signals
