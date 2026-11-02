# Senior Scam Shield

A scam checker built for older adults. Paste a text message (SMS), an
email, or a phone call transcript. You get:

1. **A verdict**: `LIKELY SCAM`, `SUSPICIOUS`, or `LOOKS SAFE`
2. **How sure we are**: High, Medium, or Low, plus what we could not check
3. **Why**: plain-English reasons, most serious first
4. **What to do now**: simple next steps
5. **A share sheet**: a short summary to hand to a family member or friend

It runs **fully offline**. Nothing you paste is sent, stored, or logged.
Every web address in the output is "defanged" (`hxxps://example[.]com`)
so it cannot be clicked by accident.

Needs Python 3.9 or newer. No packages to install.

## Commands

```sh
python -m senior_scam_shield message.txt          # check a saved message
python -m senior_scam_shield < message.txt        # or pipe it in
python -m senior_scam_shield                      # paste, then press Ctrl-D
python -m senior_scam_shield --channel call t.txt # say what it is: sms, email, call
python -m senior_scam_shield --demo               # run all built-in samples
python -m senior_scam_shield --demo call-scam     # run one sample
python -m senior_scam_shield --list-demos         # list samples
python -m senior_scam_shield msg.txt --share-only # only the share sheet
python -m senior_scam_shield msg.txt --html report.html  # printable page
python -m senior_scam_shield msg.txt --save report.txt   # text copy
```

Files are written **only** when you ask with `--html` or `--save`.

## What to paste

Paste the message as you see it. Optional header lines at the top help:

```text
From: Chase <chase.alerts@gmail.com>
Subject: Your account is locked

Your account will be locked within 24 hours...
```

- **SMS**: `From: 24273` (or a phone number), a blank line, then the text.
- **Email**: `From:`, `Subject:`, optional `Reply-To:`, then the body.
  Pasted HTML is fine: link text and real link targets are compared.
- **Call**: optional `Caller ID:` line, then lines like `Caller: ...` and `Me: ...`.

The channel is detected automatically (a `Subject:` or email address means
email, two speakers means a call, otherwise SMS). Use `--channel` to override.

Sender details are **never trusted**. Anyone can type a fake `From:` line,
so a real-looking sender never makes a message look safer. Only mismatches
count against it.

## Example

```text
$ python -m senior_scam_shield --demo sms-scam

  VERDICT:  LIKELY SCAM
   This message is very likely a scam. Do not act on it.

  HOW SURE WE ARE:  High

  WHY  (most serious first)
   1. [SERIOUS] It asks you to send money or pay a fee.
   2. [SERIOUS] It claims to be USPS, but its link does not go
      to USPS's website.
      What we found: link goes to "bit[.]ly"
   ...

  WHAT TO DO NOW
   * Do not reply, call back, or click anything in this message.
   ...

  SHARE SHEET - for a family member or friend I trust
   ...
```

## How it decides

Each check adds a signal with a weight. Weights are added up:
45 or more is `LIKELY SCAM`, 15 or more is `SUSPICIOUS`, below that is
`LOOKS SAFE`. One very serious signal (like a gift card request) is enough
on its own for `LIKELY SCAM`.

| Check | Examples | Module |
|---|---|---|
| Text classification | rushing you, threats of arrest, "keep this secret", prizes, "your account is locked" | `text_signals.py` |
| Dangerous requests | gift cards, sharing a code, AnyDesk/TeamViewer, passwords/PINs, wire transfers, crypto ATMs, "safe account" | `dangerous_requests.py` |
| Link analysis | punycode and lookalike letters, `@` tricks, number-only addresses, short links, link text that differs from the real link, odd ports, sign-in pages without https, brand names in fake addresses | `urls.py` |
| Impersonation | claims to be a bank, agency, or brand but sent from a free mailbox, a lookalike domain, a personal phone number, with a different Reply-To, or linking somewhere else | `impersonation.py` |

Protective sentences are not counted: "We will **never** ask for your code"
is how real banks talk, and it does not trigger the code-request check.

**Honest uncertainty.** Confidence drops when the message is very short,
the sender is unknown or a regular number, caller ID was given (it can be
faked), or there is a link we cannot check offline. When confidence is Low,
or the verdict is `SUSPICIOUS`, the report says so and suggests a person
check it. `LOOKS SAFE` always says it is not a promise.

## Reports

- **Text** (default): large-print style, short lines, clear headings.
- **HTML** (`--html`): one self-contained page with big type, no scripts,
  no links, no outside files. It prints cleanly; the share sheet prints
  on its own page.
- **Share sheet** (`--share-only`): what was received, what the tool found,
  what to do. Made to hand to someone you trust.

## Tests

pytest is optional. Tests are plain asserts.

```sh
python -m tests       # no pytest needed
python -m pytest      # if pytest is installed
```

- **Adversarial pairs** (`tests/test_adversarial.py`): 11 real-looking
  messages from banks, PayPal, Amazon, Apple, USPS, Medicare, and the IRS.
  Each has a spoofed twin built from it by a few text replacements. Every
  real one must be `LOOKS SAFE`; every twin must be `LIKELY SCAM`.
- **Safety** (`tests/test_safety.py`): analysis runs with sockets blocked,
  no files are written per run, output has no clickable links, and the
  source is scanned for network and storage code.
- Unit tests for each detector, the verdict engine, reports, and the CLI.

## Layout

```text
senior_scam_shield/
  message.py             parse headers, HTML, links; detect channel
  text_signals.py        pressure, threats, secrecy, prizes, account problems
  dangerous_requests.py  money, gift cards, codes, remote access, passwords
  urls.py                link checks and defanging (urllib.parse only)
  brands.py              known banks, agencies, brands, and their domains
  impersonation.py       claims versus sender, channel, and links
  verdict.py             combine signals into a verdict and next steps
  report.py              text report, HTML report, share sheet
  samples.py             built-in demo messages
  cli.py                 command line
tests/                   plain-assert tests; run with python -m tests
```

## Limits

This tool reads text only. It cannot visit websites, look up phone numbers,
or know who really sent a message. It can miss new tricks and can be wrong.
When in doubt, call the company using the number on your card or bill, and
talk to someone you trust.
