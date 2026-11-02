from senior_scam_shield.impersonation import detect_impersonation
from senior_scam_shield.message import parse_message


def codes(raw, channel=None, other=()):
    return {s.code for s in detect_impersonation(parse_message(raw, channel), set(other))}


def email(sender, body, extra=""):
    return f"From: {sender}\n{extra}Subject: Notice\n\n{body}"


def test_bank_from_free_mailbox():
    assert "sender_free_mailbox" in codes(email("Chase <chase.alerts@gmail.com>", "Chase notice."))


def test_bank_from_lookalike_domain():
    assert "sender_lookalike_domain" in codes(email("Chase <alerts@chase-secure.com>", "Chase notice."))


def test_bank_from_unrelated_domain():
    assert "sender_wrong_domain" in codes(email("Chase <info@mailer-co.example>", "Chase notice."))


def test_official_sender_and_link_add_nothing():
    raw = email("Chase <no-reply@alertsp.chase.com>", "Chase: sign in at https://www.chase.com")
    assert codes(raw) == set()


def test_faked_official_sender_with_wrong_link_is_still_caught():
    raw = email("Chase <no-reply@chase.com>", "Chase: sign in at https://docs-viewer.top/s")
    assert "link_not_official" in codes(raw)


def test_bank_sms_from_personal_number():
    assert "sender_personal_number" in codes("From: +1 213 555 0187\n\nWells Fargo: card locked.")
    assert codes("From: 93557\n\nWells Fargo: card locked.") == set()


def test_bank_sms_from_email_address():
    assert "sender_free_mailbox" in codes("From: wf.alerts@yahoo.com\n\nWells Fargo: card locked.", "sms")


def test_reply_to_goes_elsewhere():
    raw = email("PayPal <service@paypal.com>", "PayPal receipt.", "Reply-To: help@paypal-help.example\n")
    assert "reply_to_mismatch" in codes(raw)


def test_government_asking_for_money():
    raw = "From: +1 202 555 0100\n\nIRS: you owe back taxes."
    assert "impersonation_request" in codes(raw, other={"money_request"})
    assert "impersonation_request" not in codes(raw)


def test_bank_call_asking_for_code():
    raw = "Caller: This is Capital One security.\nMe: Ok."
    assert "impersonation_request" in codes(raw, other={"code_request"})


def test_no_claim_means_no_impersonation():
    assert codes(email("friend@gmail.com", "Lunch on Sunday?")) == set()


def test_brand_named_only_in_sender_address_is_a_claim():
    raw = email("amazon@amazon-support.help", "You are eligible for a refund.")
    assert "sender_lookalike_domain" in codes(raw)
