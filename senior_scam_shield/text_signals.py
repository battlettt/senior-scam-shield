"""Text classification: pressure, threats, secrecy, prizes, account problems.

Each category is a short list of phrases. A match inside a protective
sentence ("we will never ask you to ...") is ignored, so real warnings from
banks do not count against them.
"""

import re

from .models import CAUTION, MINOR, SERIOUS, Signal

NEGATION = re.compile(r"(?i)\b(never|not|don'?t|won'?t|cannot|can'?t|no one|nobody)\b|n't\b")
CLAUSE_BREAK = re.compile(r"(?i)[,;:]|\b(?:but|just|instead|so|then|and|now)\b")
SENTENCE = re.compile(r"(?:[^.!?\n]|[.!?](?=[^\s.!?]))+[.!?]*")


def sentences(text):
    """Split into sentences; line breaks inside a sentence are joined."""
    paragraphs = re.split(r"\n\s*\n|\n(?=\s*[A-Z][\w .'()-]{0,24}:\s)", text or "")
    found = []
    for paragraph in paragraphs:
        flat = " ".join(paragraph.split())
        found += [s.strip() for s in SENTENCE.findall(flat) if s.strip()]
    return found


def is_negated(sentence, start):
    """True when the words just before the match say never/not/don't."""
    clause = CLAUSE_BREAK.split(sentence[:start])[-1]
    return bool(NEGATION.search(clause))


def short(sentence, limit=110):
    sentence = " ".join(sentence.split())
    return sentence if len(sentence) <= limit else sentence[: limit - 3].rstrip() + "..."


def find_phrase(text, patterns, allow_negated=False):
    """First sentence with a non-negated match, or '' if none."""
    for sentence in sentences(text):
        for pattern in patterns:
            for match in re.finditer(pattern, sentence, re.I):
                if allow_negated or not is_negated(sentence, match.start()):
                    return short(sentence)
    return ""


PRESSURE = (
    r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"\bright away\b", r"\bact now\b",
    r"\bwithin \d+ ?(hours?|hrs?|minutes?|mins?|days?)\b", r"\btoday only\b",
    r"\bexpires? (today|tonight)\b", r"\bfinal (notice|warning|reminder)\b",
    r"\blast (chance|warning)\b", r"\b(don'?t|do not) (hang up|delay|wait|wait any longer)\b",
    r"\bstay on the (line|phone)\b", r"\btime is running out\b", r"\btoo late\b",
    r"\blimited time\b", r"\brespond (now|today|immediately)\b", r"\bbefore it'?s too late\b",
)
THREATS = (
    r"\barrest(ed)?\b", r"\bwarrant\b", r"\blawsuit\b", r"\blegal action\b",
    r"\bpolice (will|are|officers?)\b", r"\b(jail|prison)\b", r"\bdeport(ed|ation)?\b",
    r"\bcriminal charges?\b", r"\b(prosecuted|sued)\b",
    r"\byou will be (fined|charged|penali[sz]ed)\b",
    r"\b(benefits|social security( number)?|license) (will be|has been|is being) (suspended|cancell?ed|terminated|revoked|frozen)\b",
)
SECRECY = (
    r"\b(don'?t|do not|never) (tell|talk to|discuss (this|it) with|mention (this|it) to|inform|call) (anyone|anybody|(your )?(mom|mum|dad|parents|grandma|grandpa)|your (family|bank|wife|husband|son|daughter|children|kids|friends)|the (bank|teller|police))\b(?!\s+(your|the)\s+(pin|password|code))",
    r"\bkeep (this|it) (a )?(secret|confidential|between us|private|quiet)\b",
    r"\bconfidential (investigation|matter|case)\b",
    r"\b(bank|teller|bank staff|bank employees?) (is|are|may be|might be) (involved|in on it|part of)\b",
    r"\bif (anyone|the teller|the bank|they) asks?,? (just )?(say|tell them)\b",
    r"\bgag order\b",
)
PRIZE = (
    r"\byou('ve| have)? (won|been selected|been chosen)\b", r"\bwinner\b",
    r"\blottery\b", r"\bsweepstakes?\b", r"\bjackpot\b", r"\bprize\b",
    r"\bclaim your (reward|prize|gift|money|funds|refund)\b",
    r"\bunclaimed (funds|money|package|inheritance)\b", r"\binheritance\b",
    r"\bfree (gift|iphone|ipad|vacation|cruise)\b", r"\bcash reward\b",
    r"\bgrant money\b", r"\beligible for a (refund|grant|rebate)\b",
)
ACCOUNT_PROBLEM = (
    r"\b(unusual|suspicious) (activity|sign-?in|log-?in|transaction|charge)s?\b",
    r"\baccount (has been|was|will be|is|may be) (locked|suspended|limited|closed|frozen|compromised|disabled|on hold|restricted|hacked|deactivated)\b",
    r"\b(verify|confirm|validate) your (account|identity|information|details|billing)\b",
    r"\bupdate your (payment|billing|account|card) (info|information|details|method)\b",
    r"\bpayment (failed|was declined|declined|was unsuccessful)\b",
    r"\bproblem with your (account|payment|order|delivery|package)\b",
    r"\b(computer|device|phone) (is|has been|was) (infected|hacked|compromised)\b",
    r"\bvirus(es)? (detected|found)\b",
    r"\b(package|parcel|delivery) (is on hold|could not be delivered|was not delivered|failed)\b",
)


def detect_pressure(text):
    found = find_phrase(text, PRESSURE, allow_negated=True)
    return [Signal(
        "pressure", CAUTION,
        "It tries to rush you.",
        "Scammers want you to act before you have time to think or ask "
        "someone. Real companies give you time.",
        f'"{found}"',
        "Slow down. Nothing real will be lost by taking a day to check.",
    )] if found else []


def detect_threats(text):
    found = find_phrase(text, THREATS)
    return [Signal(
        "threat", SERIOUS,
        "It threatens you with arrest, legal trouble, or losing benefits.",
        "Government offices and banks do not threaten people by text, "
        "email, or phone. Threats are used to scare you into paying.",
        f'"{found}"',
        "Hang up or delete it. No real agency arrests people over the phone.",
    )] if found else []


def detect_secrecy(text):
    found = find_phrase(text, SECRECY, allow_negated=True)
    return [Signal(
        "secrecy", SERIOUS,
        "It asks you to keep this secret.",
        "Real companies never ask you to hide things from your family or "
        "your bank. Scammers do, so no one can warn you.",
        f'"{found}"',
        "Tell someone you trust about it right now.",
    )] if found else []


def detect_prize(text):
    found = find_phrase(text, PRIZE)
    return [Signal(
        "prize", SERIOUS,
        "It says you won a prize, money, or a reward.",
        "If you did not enter a contest, you did not win one. Real prizes "
        "never ask you to pay first.",
        f'"{found}"',
    )] if found else []


def detect_account_problem(text):
    found = find_phrase(text, ACCOUNT_PROBLEM)
    return [Signal(
        "account_problem", MINOR,
        "It says there is a problem with your account, card, or device.",
        "Scammers often say this to worry you. Real companies say it too, "
        "so check it yourself without using the message.",
        f'"{found}"',
    )] if found else []


def detect_text_signals(text):
    return (detect_pressure(text) + detect_threats(text) + detect_secrecy(text)
            + detect_prize(text) + detect_account_problem(text))
