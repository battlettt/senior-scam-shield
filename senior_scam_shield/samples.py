"""Built-in demo messages: a clear scam and a legitimate message per channel,
plus one short, unclear text that shows honest uncertainty.

All names, numbers, and web addresses are made up or use documentation
ranges. Expected verdicts are checked by the tests.
"""

SAMPLES = {
    "sms-scam": ("sms", "LIKELY SCAM", """\
From: +1 (213) 555-0187

USPS: Your package is on hold due to an incomplete address. Pay a $1.99
redelivery fee within 24 hours or it will be returned: https://bit.ly/3usps-redeliver
"""),
    "sms-legit": ("sms", "LOOKS SAFE", """\
From: 24273

Chase Fraud Alert: Did you use card ending 4417 for $89.99 at BESTBUY on
Nov 1? Reply YES or NO. We will never ask for your PIN or a code by text.
Reply STOP to end texts.
"""),
    "sms-unsure": ("sms", "LOOKS SAFE", """\
From: +1 (646) 555-0142

Hi, is this still your number? Text me back.
"""),
    "email-scam": ("email", "LIKELY SCAM", """\
From: PayPal Service <service.paypal.team@gmail.com>
Subject: Your account has been limited

Dear customer, we noticed unusual activity. Your account has been limited.
Confirm your identity within 24 hours or your account will be closed:
<a href="https://www.paypal.com.account-review.info/login">https://www.paypal.com</a>
"""),
    "email-legit": ("email", "LOOKS SAFE", """\
From: Chase <no-reply@alertsp.chase.com>
Subject: Your statement is ready

Your October statement for account ending 4417 is ready. To view it, sign in
at https://www.chase.com or open the Chase Mobile app. We will never ask for
your password or one-time code by email.
"""),
    "call-scam": ("call", "LIKELY SCAM", """\
Caller ID: Microsoft Support
Caller: Hello, this is Microsoft Windows Support. Your computer has been
infected with a virus and your bank account is at risk.
Me: Oh no. What do I do?
Caller: Do not hang up. Please download AnyDesk so I can fix your computer.
Then buy two $500 Target gift cards and read me the numbers on the back.
Don't tell anyone at the store what they are for.
"""),
    "call-legit": ("call", "LOOKS SAFE", """\
Caller ID: Riverside Pharmacy
Caller: Hello, this is Riverside Pharmacy calling for Margaret. Your
prescription refill is ready for pickup at the counter.
Me: Thank you. When are you open?
Caller: We are open until 8 pm today and 9 to 5 on Sunday. Have a nice day.
"""),
}


def sample_names():
    return list(SAMPLES)


def get_sample(name):
    """(channel, expected_verdict, text) for a built-in sample."""
    return SAMPLES[name]
