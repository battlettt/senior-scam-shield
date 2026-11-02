# CLAUDE.md - Senior Scam Shield

## What this is
A multi-channel scam detector built for seniors: paste an SMS, an email,
or a phone call transcript and get a plain-English verdict, the signals
behind it, and what to do. Designed for older adults first: large print,
simple language, printable reports, and a share sheet for a trusted
family member.

## Principles
- Local-only. Nothing pasted is sent, stored, or logged anywhere.
- Multi-signal, not one trick: text classification, URL analysis,
  impersonation detection, pressure language, and dangerous request types
  (money, gift cards, codes, remote access) combined into one verdict.
- Honest uncertainty: when unsure, say so and suggest a human check.
- No streaks, no gamification, no pressure mechanics of any kind.
- Python standard library only for the core. No dependencies to install.

## Build, test, run
- Run: `python -m senior_scam_shield` (see README for commands)
- Tests: plain asserts, runnable with or without pytest:
  `python -m pytest`
- Keep the signal detectors, the verdict engine, and the report
  formatting separate so each can be tested alone.

## Conventions
- Small functions, clear names, minimal abstraction.
- Every feature ships with tests and a README section.
- Adversarial tests required: legitimate bank messages must not
  false-positive, and spoofed versions of them must be caught.
