from senior_scam_shield.text_signals import detect_text_signals, is_negated, sentences


def codes(text):
    return {s.code for s in detect_text_signals(text)}


def test_pressure_language():
    assert "pressure" in codes("Act now or lose access.")
    assert "pressure" in codes("You must respond within 24 hours.")
    assert "pressure" in codes("Do not hang up. Stay on the line with me.")
    assert "pressure" in codes("FINAL NOTICE: your plan ends.")


def test_threats():
    assert "threat" in codes("A warrant has been issued for your arrest.")
    assert "threat" in codes("Police officers will come to your home tonight.")
    assert "threat" in codes("Your Social Security number has been suspended.")


def test_secrecy():
    assert "secrecy" in codes("Do not tell anyone about this call.")
    assert "secrecy" in codes("Keep this between us, the bank teller may be involved.")
    assert "secrecy" in codes("If the teller asks, say it is for a family gift.")


def test_prize_and_lottery():
    assert "prize" in codes("Congratulations! You have won the national lottery.")
    assert "prize" in codes("Claim your reward today.")


def test_account_problem_claims():
    assert "account_problem" in codes("Your account has been locked.")
    assert "account_problem" in codes("We noticed unusual activity on your card.")
    assert "account_problem" in codes("Your computer has been infected.")


def test_protective_bank_wording_is_not_flagged():
    assert codes("We will never threaten you with arrest.") == set()
    assert codes("Do not tell anyone your PIN.") == set()
    assert codes("Your statement is ready. Sign in to view it.") == set()
    assert codes("Your one-time code is 123456. It expires in 10 minutes.") == set()


def test_negation_is_limited_to_its_own_clause():
    sentence = "Don't worry, you have won a prize"
    assert not is_negated(sentence, sentence.index("won"))
    sentence = "We will never say you have won"
    assert is_negated(sentence, sentence.index("won"))


def test_sentences_join_wrapped_lines_and_split_speakers():
    text = "Caller: Your computer has been\ninfected.\nMe: Oh no."
    assert sentences(text) == ["Caller: Your computer has been infected.", "Me: Oh no."]
    assert sentences("Pay $1.99 at usps.com now.") == ["Pay $1.99 at usps.com now."]


def test_grandparent_scam_secrecy():
    assert "secrecy" in codes("I am in jail and need bail money. Please do not tell mom.")
