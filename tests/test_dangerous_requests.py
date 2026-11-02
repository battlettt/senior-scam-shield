from senior_scam_shield.dangerous_requests import detect_dangerous_requests


def codes(text):
    return {s.code for s in detect_dangerous_requests(text)}


def test_gift_cards():
    assert "gift_cards" in codes("Go buy three Google Play cards and call me back.")
    assert "gift_cards" in codes("Read me the numbers on the back of the gift card.")
    assert "gift_cards" in codes("Scratch off the silver strip and send a photo.")


def test_verification_codes():
    assert "code_request" in codes("Please read me the 6-digit code we just sent.")
    assert "code_request" in codes("Reply with the verification code to cancel the order.")
    assert "code_request" in codes("What is the code you just received?")


def test_remote_access_tools():
    for tool in ("AnyDesk", "TeamViewer", "UltraViewer", "LogMeIn", "Quick Assist"):
        assert "remote_access" in codes(f"Please install {tool} now."), tool
    assert "remote_access" in codes("Let me connect to your computer to fix it.")


def test_credentials():
    assert "credential_request" in codes("Please confirm your online banking login details.")
    assert "credential_request" in codes("Tell me your Social Security number.")
    assert "credential_request" in codes("Enter your password at the page below.")


def test_money_transfers():
    assert "money_request" in codes("You must move your savings to a safe account.")
    assert "money_request" in codes("Send it by Zelle to our agent.")
    assert "money_request" in codes("Pay at the nearest Bitcoin ATM.")
    assert "money_request" in codes("A courier will pick up the cash at your door.")
    assert "money_request" in codes("Wire the money today.")


def test_protective_sentences_are_not_requests():
    assert codes("We will never ask you to pay with gift cards.") == set()
    assert codes("Never share this code with anyone. We won't call to ask for it.") == set()
    assert codes("We will never ask you to install AnyDesk or TeamViewer.") == set()
    assert codes("We never ask for your password or PIN.") == set()
    assert codes("Medicare will never ask you to wire money.") == set()


def test_normal_banking_wording_is_not_a_request():
    assert codes("We will send you a code to sign in.") == set()
    assert codes("Enter this code in the app to sign in.") == set()
    assert codes("Your transfer of $500 to savings is complete.") == set()
    assert codes("Your Target gift card balance is $25.") == set()
    assert codes("Your autopay of $50 is scheduled.") == set()


def test_negation_does_not_hide_a_later_request():
    assert "code_request" in codes("Don't worry, just read me the code.")
    assert "secrecy" not in codes("Don't tell anyone, just read me the code.")  # other detector
