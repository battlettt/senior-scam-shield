"""Adversarial pairs: each legitimate message has a spoofed twin.

The twin is built from the legitimate text by a few replacements, so the
two differ only in the scam signals. The legitimate one must come back
LOOKS SAFE; the twin must come back LIKELY SCAM.
"""

from senior_scam_shield import LIKELY_SCAM, LOOKS_SAFE, analyze

PAIRS = [
    ("chase-fraud-alert-sms", "sms", """\
From: 24273

Chase Fraud Alert: Did you use card ending 4417 for $89.99 at BESTBUY on
Nov 1? Reply YES or NO. Reply STOP to end texts.
""", [
        ("From: 24273", "From: +1 (213) 555-0187"),
        ("Reply YES or NO.", "If not, verify now at https://chase-secure-verify.com/login "
                             "or your account will be locked within 24 hours."),
    ]),
    ("chase-one-time-code-sms", "sms", """\
From: 24273

Chase: Your one-time code is 482913. Don't share it with anyone. We'll never
call you to ask for this code.
""", [
        ("We'll never\ncall you to ask for this code.",
         "Our fraud agent will call you now. Read this code to the agent to stop the charge."),
    ]),
    ("chase-statement-email", "email", """\
From: Chase <no-reply@alertsp.chase.com>
Subject: Your statement is ready

Your October statement for account ending 4417 is ready. To view it, sign in
at https://www.chase.com or open the Chase Mobile app. We will never ask for
your password or one-time code by email.
""", [
        ("no-reply@alertsp.chase.com", "chase.alerts.team@gmail.com"),
        ("https://www.chase.com", '<a href="http://203.0.113.7:8080/chase/login">https://www.chase.com</a>'),
    ]),
    ("bofa-html-email-faked-sender", "email", """\
From: Bank of America <onlinebanking@ealerts.bankofamerica.com>
Subject: Your documents are available

<p>Your new tax documents are available. View them at
<a href="https://www.bankofamerica.com/documents">www.bankofamerica.com</a>.</p>
<p>Bank of America will never ask for your Online ID or passcode by email.</p>
""", [
        # Sender left untouched on purpose: it is faked to look real.
        ("https://www.bankofamerica.com/documents", "https://docs-viewer.top/s/88"),
    ]),
    ("paypal-receipt-email", "email", """\
From: PayPal <service@paypal.com>
Subject: Receipt for your payment

You sent a payment of $25.00 USD to Jane Doe. View the details at
https://www.paypal.com/myaccount/activity
""", [
        ("https://www.paypal.com/myaccount/activity",
         "https://www.paypal.com.account-review.info/activity"),
        ("Jane Doe.", "Jane Doe. If you did not make this payment, call us right away "
                      "so we can help you install AnyDesk to secure your account."),
    ]),
    ("amazon-order-email-at-trap", "email", """\
From: Amazon.com <shipment-tracking@amazon.com>
Subject: Your order has shipped

Your order of 2 items has shipped. Track it at
https://www.amazon.com/gp/your-orders
""", [
        ("https://www.amazon.com/gp/your-orders",
         "https://www.amazon.com@198.51.100.4/gp/your-orders"),
    ]),
    ("apple-receipt-email-punycode", "email", """\
From: Apple <no_reply@email.apple.com>
Subject: Your receipt from Apple

Thank you for your purchase of iCloud+ 50GB for $0.99. Manage your
subscriptions at https://www.apple.com/account
""", [
        ("https://www.apple.com/account", "https://www.xn--pple-43d.com/account"),
        ("Thank you for", "Payment failed. Confirm your password today to keep"),
    ]),
    ("usps-delivered-sms-shortener", "sms", """\
From: 28777

USPS: Your package 9400 1000 0000 0000 0000 00 was delivered today at 2:14 pm.
Details: https://tools.usps.com/go/TrackConfirmAction
""", [
        ("was delivered today at 2:14 pm.", "is on hold. Pay a $1.99 redelivery fee:"),
        ("https://tools.usps.com/go/TrackConfirmAction", "https://bit.ly/3usps-redeliver"),
    ]),
    ("medicare-card-sms", "sms", """\
From: 63342

Medicare: Your new Medicare card was mailed this week. Learn more at
https://www.medicare.gov/basics/your-medicare-card
""", [
        ("https://www.medicare.gov/basics/your-medicare-card",
         "https://medicare-gov.help/renew"),
        ("was mailed this week.", "will be cancelled. You must pay a processing fee."),
    ]),
    ("wells-fargo-call", "call", """\
Caller ID: Wells Fargo
Caller: Hello, this is Wells Fargo calling about a recent card purchase of
$64.20 at a gas station. Did you make this purchase?
Me: I'm not sure.
Caller: No problem. Please hang up and call the number on the back of your
card. We will never ask for your PIN, password, or a one-time code.
""", [
        ("No problem. Please hang up and call the number on the back of your\ncard.",
         "Do not hang up. Your account is compromised. Do not tell anyone at the branch."),
        ("We will never ask for your PIN, password, or a one-time code.",
         "Read me the one-time code we just sent, then move your savings to a safe account."),
    ]),
    ("irs-letter-call", "call", """\
Caller ID: IRS
Caller: Hello, this is the IRS returning your call about the letter you
received. You can view your account any time at https://www.irs.gov.
Me: Thank you.
""", [
        ("returning your call about the letter you\nreceived.",
         "calling because a warrant has been issued for your arrest. Pay with "
         "Google Play cards today."),
    ]),
]


def make_twin(legit, replacements):
    twin = legit
    for old, new in replacements:
        assert old in twin, f"replacement text not found: {old!r}"
        twin = twin.replace(old, new)
    return twin


def test_every_pair_has_a_real_difference():
    for name, _channel, legit, replacements in PAIRS:
        assert make_twin(legit, replacements) != legit, name


def test_legitimate_messages_look_safe():
    for name, channel, legit, _ in PAIRS:
        for chosen in (channel, None):  # with the flag and with auto-detect
            result = analyze(legit, chosen)
            assert result.verdict == LOOKS_SAFE, (name, chosen, result.verdict,
                                                  [s.code for s in result.signals])


def test_spoofed_twins_are_caught():
    for name, channel, legit, replacements in PAIRS:
        for chosen in (channel, None):
            result = analyze(make_twin(legit, replacements), chosen)
            assert result.verdict == LIKELY_SCAM, (name, chosen, result.verdict,
                                                   [s.code for s in result.signals])


def test_auto_detect_finds_the_right_channel():
    for name, channel, legit, replacements in PAIRS:
        assert analyze(legit).message.channel == channel, name
        assert analyze(make_twin(legit, replacements)).message.channel == channel, name


def test_legitimate_messages_have_no_serious_reasons():
    for name, channel, legit, _ in PAIRS:
        heavy = [s.code for s in analyze(legit, channel).signals if s.weight >= 15]
        assert heavy == [], (name, heavy)
