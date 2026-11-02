from senior_scam_shield import analyze
from senior_scam_shield.report import WIDTH, render_html, render_share_sheet, render_text
from senior_scam_shield.samples import get_sample


def sample(name):
    channel, _, text = get_sample(name)
    return analyze(text, channel)


def test_text_report_sections_in_required_order():
    text = render_text(sample("sms-scam"))
    order = ["VERDICT:", "HOW SURE WE ARE:", "WHY", "WHAT TO DO NOW", "SHARE SHEET"]
    positions = [text.index(word) for word in order]
    assert positions == sorted(positions)


def test_text_report_lines_are_short_for_large_print():
    for name in ("sms-scam", "email-scam", "call-scam", "email-legit"):
        for line in render_text(sample(name)).splitlines():
            # long web addresses are never split, everything else wraps
            assert len(line) <= WIDTH or "hxxp" in line or "[.]" in line, line


def test_reasons_show_severity_labels():
    text = render_text(sample("call-scam"))
    assert "1. [VERY SERIOUS]" in text and "[SERIOUS]" in text


def test_share_sheet_covers_received_found_and_todo():
    sheet = render_share_sheet(sample("email-scam"))
    for part in ("WHAT I RECEIVED", "WHAT THE TOOL FOUND", "WHAT TO DO",
                 "LIKELY SCAM", "It says it is from: PayPal", "can be faked"):
        assert part in sheet, part
    assert len(sheet.splitlines()) < 45


def test_safe_report_still_says_it_is_not_a_promise():
    text = render_text(sample("email-legit"))
    assert "LOOKS SAFE" in text and "not a promise" in text


def test_low_confidence_report_says_not_sure():
    text = " ".join(render_text(sample("sms-unsure")).split())
    assert "We are not sure" in text and "person you trust" in text


def test_html_is_self_contained_and_printable():
    page = render_html(sample("email-scam"))
    assert page.startswith("<!DOCTYPE html>") and "@media print" in page
    for banned in ("<script", "<a ", "href=", "src=", "<link", "@import", "url("):
        assert banned not in page.lower(), banned
    assert "LIKELY SCAM" in page and "Share sheet" in page


def test_html_escapes_message_content():
    page = render_html(analyze('From: x@example.com\nSubject: <script>alert(1)</script>\n\nhi'))
    assert "<script>" not in page
