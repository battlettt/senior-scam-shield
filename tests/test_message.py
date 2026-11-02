from senior_scam_shield.message import parse_message, sender_kind


def test_email_headers_and_channel():
    m = parse_message("From: Chase <alerts@chase.com>\nSubject: Hi\n\nBody text.")
    assert m.channel == "email"
    assert m.sender_address == "alerts@chase.com"
    assert m.sender_name == "Chase"
    assert m.subject == "Hi"
    assert m.body == "Body text."


def test_sms_channel_and_sender_kinds():
    assert parse_message("From: 24273\n\nYour code is 1234.").channel == "sms"
    assert sender_kind(parse_message("From: 24273\n\nHi")) == "short_code"
    assert sender_kind(parse_message("From: +1 (213) 555-0187\n\nHi")) == "phone"
    assert sender_kind(parse_message("Hi there")) == "unknown"


def test_call_transcript_detected_from_speakers():
    m = parse_message("Caller: Hello there.\nMe: Who is this?\nCaller: Your bank.")
    assert m.channel == "call"


def test_channel_flag_overrides_detection():
    assert parse_message("Caller: a\nMe: b", channel="sms").channel == "sms"


def test_html_email_anchors_are_extracted():
    raw = ('From: x@example.com\nSubject: s\n\n<p>Hello <a href="https://evil.example/x">'
           'www.chase.com</a></p>')
    m = parse_message(raw)
    assert "<a" not in m.body and "www.chase.com" in m.body
    assert [(l.text, l.href) for l in m.links] == [("www.chase.com", "https://evil.example/x")]


def test_reply_to_is_parsed():
    m = parse_message("From: a@chase.com\nReply-To: b@gmail.com\nSubject: s\n\nx")
    assert m.reply_to == "b@gmail.com"


def test_empty_input_does_not_crash():
    m = parse_message("")
    assert m.body == "" and m.links == []
