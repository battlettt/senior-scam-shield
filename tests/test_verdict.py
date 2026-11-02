from senior_scam_shield import LIKELY_SCAM, LOOKS_SAFE, SUSPICIOUS, analyze
from senior_scam_shield.models import Signal
from senior_scam_shield.samples import get_sample, sample_names
from senior_scam_shield.verdict import (NOT_SURE, VERDICTS, merge_signals,
                                        pick_verdict)


def test_verdict_names_are_fixed():
    assert VERDICTS == ("LIKELY SCAM", "SUSPICIOUS", "LOOKS SAFE")
    assert pick_verdict(0) == LOOKS_SAFE
    assert pick_verdict(15) == SUSPICIOUS
    assert pick_verdict(45) == LIKELY_SCAM


def test_one_very_serious_request_is_enough():
    assert analyze("Go buy gift cards and read me the numbers.").verdict == LIKELY_SCAM


def test_single_pressure_signal_is_only_suspicious():
    result = analyze("Please respond within 24 hours about your appointment time.")
    assert result.verdict == SUSPICIOUS
    assert NOT_SURE in result.uncertainty


def test_reasons_are_most_serious_first():
    raw = ("From: +1 213 555 0187\n\nChase: unusual activity. Act now and "
           "read me the code at https://chase-verify.top/x")
    weights = [s.weight for s in analyze(raw).signals]
    assert weights == sorted(weights, reverse=True) and len(weights) >= 4


def test_merge_keeps_one_signal_per_code():
    merged = merge_signals([Signal("a", 5, "r", "e"), Signal("a", 9, "r", "e"), Signal("b", 7, "r", "e")])
    assert [(s.code, s.weight) for s in merged] == [("a", 9), ("b", 7)]


def test_honest_uncertainty_for_short_unknown_messages():
    result = analyze("Hi, is this still your number?")
    assert result.verdict == LOOKS_SAFE
    assert result.confidence == "Low"
    assert NOT_SURE in result.uncertainty


def test_unknown_link_lowers_confidence():
    result = analyze("From: 24273\n\nYour garden club newsletter is out. Read it "
                     "at https://riverside-garden-club.example.org/news this week.")
    assert result.verdict == LOOKS_SAFE and result.confidence == "Medium"
    assert any("cannot check" in note for note in result.uncertainty)


def test_next_steps_always_present_and_plain():
    for name in sample_names():
        channel, _, text = get_sample(name)
        steps = analyze(text, channel).next_steps
        assert 3 <= len(steps) <= 8, name
        assert all(len(step) < 140 for step in steps), name


def test_demo_samples_match_expected_verdicts():
    channels = set()
    for name in sample_names():
        channel, expected, text = get_sample(name)
        assert analyze(text, channel).verdict == expected, name
        assert analyze(text).verdict == expected, name  # auto-detect too
        channels.add((channel, expected))
    for channel in ("sms", "email", "call"):
        assert (channel, LIKELY_SCAM) in channels and (channel, LOOKS_SAFE) in channels


def test_analysis_is_deterministic():
    _, _, text = get_sample("email-scam")
    first, second = analyze(text), analyze(text)
    assert (first.verdict, first.score, first.signals) == (second.verdict, second.score, second.signals)
