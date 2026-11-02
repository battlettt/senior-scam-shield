"""Known banks, government agencies, and brands that scammers pretend to be.

Each brand lists the words that show a message claims to be from it, the
real web domains it uses, and short host tokens used to spot lookalikes.
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    name: str
    kind: str  # "bank", "government", or "company"
    pattern: str  # regex that finds a claim in text
    domains: tuple  # real registrable domains
    tokens: tuple  # words a lookalike web address would contain


BRANDS = (
    Brand("Chase", "bank", r"\bChase\b|\bCHASE\b|JPMorgan", ("chase.com", "jpmorganchase.com", "jpmorgan.com"), ("chase", "jpmorgan")),
    Brand("Bank of America", "bank", r"(?i)\bbank of america\b|\bBofA\b", ("bankofamerica.com", "bofa.com"), ("bankofamerica", "bofa")),
    Brand("Wells Fargo", "bank", r"(?i)\bwells fargo\b", ("wellsfargo.com", "wf.com"), ("wellsfargo",)),
    Brand("Citibank", "bank", r"\bCiti(?:bank)?\b", ("citi.com", "citibank.com"), ("citibank", "citi")),
    Brand("Capital One", "bank", r"(?i)\bcapital one\b", ("capitalone.com",), ("capitalone",)),
    Brand("PayPal", "company", r"(?i)\bpaypal\b", ("paypal.com",), ("paypal",)),
    Brand("Zelle", "company", r"(?i)\bzelle\b", ("zellepay.com",), ("zelle",)),
    Brand("Venmo", "company", r"(?i)\bvenmo\b", ("venmo.com",), ("venmo",)),
    Brand("Amazon", "company", r"(?i)\bamazon\b", ("amazon.com", "amazon.co.uk", "amazon.ca"), ("amazon",)),
    Brand("Apple", "company", r"\bApple\b|\biCloud\b|(?i:\bapple id\b)", ("apple.com", "icloud.com"), ("apple", "icloud")),
    Brand("Microsoft", "company", r"(?i)\bmicrosoft\b|\bwindows support\b", ("microsoft.com", "live.com", "microsoftonline.com"), ("microsoft",)),
    Brand("Netflix", "company", r"(?i)\bnetflix\b", ("netflix.com",), ("netflix",)),
    Brand("Geek Squad", "company", r"(?i)\bgeek ?squad\b", ("geeksquad.com", "bestbuy.com"), ("geeksquad",)),
    Brand("Norton", "company", r"\bNorton\b", ("norton.com",), ("norton",)),
    Brand("McAfee", "company", r"(?i)\bmcafee\b", ("mcafee.com",), ("mcafee",)),
    Brand("USPS", "government", r"(?i)\bUSPS\b|\bpostal service\b", ("usps.com", "usps.gov"), ("usps",)),
    Brand("UPS", "company", r"\bUPS\b", ("ups.com",), ("ups",)),
    Brand("FedEx", "company", r"(?i)\bfedex\b", ("fedex.com",), ("fedex",)),
    Brand("IRS", "government", r"\bIRS\b|(?i:internal revenue service)", ("irs.gov",), ("irs",)),
    Brand("Social Security", "government", r"(?i)social security administration|\bSSA\b|social security office", ("ssa.gov",), ("ssa", "socialsecurity")),
    Brand("Medicare", "government", r"(?i)\bmedicare\b", ("medicare.gov", "cms.gov"), ("medicare",)),
    Brand("FBI", "government", r"\bFBI\b", ("fbi.gov",), ("fbi",)),
)

FREE_MAILBOXES = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "hotmail.com",
    "outlook.com", "aol.com", "icloud.com", "me.com", "proton.me",
    "protonmail.com", "gmx.com", "gmx.net", "mail.com", "mail.ru",
    "yandex.com", "zoho.com", "msn.com", "comcast.net",
})

# Second-level suffixes where the registrable domain has three labels.
MULTI_PART_SUFFIXES = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "gov.au",
    "co.nz", "co.jp", "com.br", "co.in", "com.mx", "co.za",
})


def registrable_domain(host):
    """'secure.alerts.chase.com' -> 'chase.com'. Approximate, no network."""
    host = (host or "").lower().rstrip(".")
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def find_claimed_brands(text):
    """Brands the text claims to come from, in order of first mention."""
    found = []
    for brand in BRANDS:
        match = re.search(brand.pattern, text or "")
        if match:
            found.append((match.start(), brand))
    return [brand for _, brand in sorted(found, key=lambda pair: pair[0])]


def is_official_domain(brand, host):
    domain = registrable_domain(host)
    return domain in brand.domains


def official_brand_for(host):
    """The brand that really owns this host, if we know it."""
    for brand in BRANDS:
        if is_official_domain(brand, host):
            return brand
    return None


def is_free_mailbox(domain):
    return registrable_domain(domain) in FREE_MAILBOXES


# Words scammers glue onto a brand name: "chasebank", "mypaypal", "apple1".
LOOKALIKE_AFFIXES = frozenset({
    "", "bank", "online", "secure", "support", "login", "verify", "id",
    "help", "service", "services", "account", "accounts", "alert", "alerts",
    "us", "usa", "pay", "my", "web", "gov", "team", "center", "update",
})


def part_imitates_token(part, token):
    if part.startswith(token):
        rest = part[len(token):]
        return rest in LOOKALIKE_AFFIXES or rest.isdigit()
    if part.endswith(token):
        return part[:-len(token)] in LOOKALIKE_AFFIXES
    return False


def host_mentions_brand(host, brand):
    """True when a label of the host is a brand name, alone or with affixes."""
    parts = re.split(r"[.\-_]", (host or "").lower())
    return any(
        part_imitates_token(part, token)
        for token in brand.tokens
        for part in parts
    )
