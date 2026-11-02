"""The verdict engine: combine every signal into one plain verdict.

Verdicts: LIKELY SCAM, SUSPICIOUS, LOOKS SAFE. Each comes with a
confidence (High, Medium, Low) and honest notes on what we could not check.
"""

from dataclasses import dataclass

from .dangerous_requests import detect_dangerous_requests
from .impersonation import detect_impersonation, main_claimed_brand
from .message import full_text, parse_message, sender_kind
from .text_signals import detect_text_signals
from . import brands
from .urls import analyze_links, hostname_of

LIKELY_SCAM = "LIKELY SCAM"
SUSPICIOUS = "SUSPICIOUS"
LOOKS_SAFE = "LOOKS SAFE"
VERDICTS = (LIKELY_SCAM, SUSPICIOUS, LOOKS_SAFE)

SCAM_SCORE = 45
SUSPICIOUS_SCORE = 15
SHORT_MESSAGE_WORDS = 12

NOT_SURE = ("We are not sure about this one. Please ask a person you trust "
            "to look at it before you do anything.")


@dataclass
class Analysis:
    verdict: str
    confidence: str
    score: int
    signals: list
    next_steps: list
    uncertainty: list
    message: object
    claimed_brand: str = ""


def merge_signals(signals):
    """One entry per signal code, keeping the heaviest; most serious first."""
    best = {}
    for signal in signals:
        if signal.code not in best or signal.weight > best[signal.code].weight:
            best[signal.code] = signal
    return sorted(best.values(), key=lambda s: -s.weight)


def collect_signals(message):
    text = full_text(message)
    signals = detect_text_signals(text) + detect_dangerous_requests(text)
    signals += analyze_links(message.links)
    codes = {signal.code for signal in signals}
    signals += detect_impersonation(message, codes)
    return merge_signals(signals)


def pick_verdict(score):
    if score >= SCAM_SCORE:
        return LIKELY_SCAM
    if score >= SUSPICIOUS_SCORE:
        return SUSPICIOUS
    return LOOKS_SAFE


def uncertainty_notes(message):
    """Things we could not check, said plainly."""
    notes = []
    if len(full_text(message).split()) < SHORT_MESSAGE_WORDS:
        notes.append("The message is very short, so there is little to go on.")
    kind = sender_kind(message)
    if kind == "unknown":
        notes.append("We could not see who sent it.")
    elif kind == "phone" and message.channel != "call":
        notes.append("It came from a regular phone number we cannot check.")
    if message.channel == "call" and kind != "unknown":
        notes.append("Caller ID can be faked, so the caller may not be who they say.")
    unknown_links = [link for link in message.links
                     if not brands.official_brand_for(hostname_of(link.href))]
    if unknown_links:
        notes.append("It has a link to a website we cannot check without going online.")
    return notes


def pick_confidence(verdict, score, signals, notes):
    strong = [s for s in signals if s.weight >= 30]
    if verdict == LIKELY_SCAM:
        return "High" if score >= 70 or len(strong) >= 2 else "Medium"
    if verdict == SUSPICIOUS:
        return "Medium" if score >= 30 else "Low"
    if signals or len(notes) >= 2:
        return "Low" if len(notes) >= 2 or score >= 10 else "Medium"
    return "Medium" if notes else "High"


BASE_STEPS = {
    LIKELY_SCAM: [
        "Do not reply, call back, or click anything in this message.",
        "Do not send money, gift cards, codes, or passwords.",
        "If you already did, call your bank right away using the number on your card.",
        "Show this report to someone you trust.",
        "In the US, you can forward scam texts to 7726 and report fraud at reportfraud.ftc.gov.",
    ],
    SUSPICIOUS: [
        "Do not click links or call numbers in this message yet.",
        "Check it yourself: call the company using the number on your card, bill, or statement.",
        "Ask someone you trust to look at it with you.",
    ],
    LOOKS_SAFE: [
        "We did not find common scam signs in this message.",
        "Still, never share passwords or codes, and never pay with gift cards.",
        "If anything feels wrong, trust that feeling and ask someone before you act.",
    ],
}


MAX_SIGNAL_STEPS = 3


def plan_next_steps(verdict, signals):
    """The first general step, the advice for the top signals, then the rest."""
    steps = list(BASE_STEPS[verdict][:1])
    if verdict != LOOKS_SAFE:
        advice = [s.advice for s in signals if s.advice]
        for step in advice:
            if step not in steps and len(steps) <= MAX_SIGNAL_STEPS:
                steps.append(step)
    for step in BASE_STEPS[verdict][1:]:
        if step not in steps:
            steps.append(step)
    return steps


def analyze(raw, channel=None):
    """Analyze pasted text. Pure function: no network, no files, no logs."""
    message = parse_message(raw, channel)
    signals = collect_signals(message)
    score = sum(signal.weight for signal in signals)
    verdict = pick_verdict(score)
    notes = uncertainty_notes(message)
    confidence = pick_confidence(verdict, score, signals, notes)
    uncertainty = list(notes)
    if confidence == "Low" or verdict == SUSPICIOUS:
        uncertainty.append(NOT_SURE)
    brand = main_claimed_brand(message)
    return Analysis(
        verdict=verdict,
        confidence=confidence,
        score=score,
        signals=signals,
        next_steps=plan_next_steps(verdict, signals),
        uncertainty=uncertainty,
        message=message,
        claimed_brand=brand.name if brand else "",
    )
