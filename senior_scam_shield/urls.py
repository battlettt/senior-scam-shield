"""Find web links in a message, check them for tricks, and defang them.

Hosts are always read with urllib.parse, never with a regex. Nothing here
opens a connection: a link is only inspected as text.
"""

import ipaddress
import re
from urllib.parse import urlsplit

from . import brands
from .models import CAUTION, MINOR, SERIOUS, VERY_SERIOUS, Link, Signal

KNOWN_TLDS = frozenset("""
com net org gov edu mil int info biz io co us uk ca au nz de fr es it nl be
ch at se no dk fi pl ru cn jp in br mx za ie eu me app dev xyz top click link
online site shop store live help support vip club tv ly gl gd cc ws pw su
tk ml ga cf gq icu buzz zip mov rest cfd sbs win bid loan work mobi asia
""".split())

RISKY_TLDS = frozenset("""
xyz top click link tk ml ga cf gq icu buzz zip mov rest cfd sbs win bid loan
work support help live vip ru su
""".split())

SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
    "s.id", "v.gd", "bl.ink", "lnkd.in",
})

LOGIN_WORDS = ("login", "log-in", "signin", "sign-in", "logon", "verify",
               "account", "password", "secure", "banking", "update", "confirm")

# Letters and digits that look like Latin letters ("paypa1", "аpple").
CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "3": "e", "5": "s", "@": "a",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "ј": "j", "ӏ": "l", "ԁ": "d", "ɡ": "g",
    "ո": "n", "ս": "u", "α": "a", "ο": "o", "ν": "v", "ı": "i",
})

EDGE_PUNCTUATION = "\"'()[]{}<>,;!?.:*"


# ----- finding links -------------------------------------------------------

def has_scheme(text):
    return bool(re.match(r"(?i)^[a-z][a-z0-9+.-]*://", text))


def split_url(url):
    """urlsplit with a default scheme so bare 'example.com/x' parses."""
    return urlsplit(url if has_scheme(url) else "http://" + url)


def hostname_of(url):
    try:
        return (split_url(url).hostname or "").rstrip(".")
    except ValueError:
        return ""


def strip_edges(token):
    return token.strip(EDGE_PUNCTUATION)


def looks_like_url(token):
    """A token a person could click or type as a web address."""
    if not token or " " in token:
        return False
    if has_scheme(token):
        return token.lower().startswith(("http://", "https://"))
    if "@" in token and "/" not in token:
        return False  # an email address, handled separately
    host = hostname_of(token)
    if "." not in host:
        return False
    if is_ip_literal(host) and token.lower().startswith(host):
        return True
    tld = host.rsplit(".", 1)[-1]
    return tld in KNOWN_TLDS or host.startswith("www.") or tld.startswith("xn--")


def looks_like_email(token):
    if token.count("@") != 1 or has_scheme(token):
        return False
    local, domain = token.split("@")
    return bool(local) and looks_like_url(domain)


def find_bare_urls(text):
    found = []
    for raw in re.findall(r"\S+", text or ""):
        token = strip_edges(raw)
        if looks_like_url(token) and token not in found:
            found.append(token)
    return found


MARKDOWN_LINK = re.compile(r"\[([^\]\n]{1,200})\]\(([^)\s]+)\)")
ANGLE_LINK = re.compile(r"(\S+)\s*<((?:https?://)[^>\s]+)>", re.I)


def extract_links(text, html_anchors=()):
    """All links: HTML anchors, [text](url), 'text <url>', and bare URLs."""
    links = [Link(href=href.strip(), text=label.strip()) for label, href in html_anchors]
    remaining = text or ""
    for link in links:  # the shown text of an anchor is not a second link
        if link.text:
            remaining = remaining.replace(link.text, " ")
    for pattern in (MARKDOWN_LINK, ANGLE_LINK):
        for label, href in pattern.findall(remaining):
            links.append(Link(href=href, text=strip_edges(label)))
        remaining = pattern.sub(" ", remaining)
    seen = {link.href for link in links}
    for href in find_bare_urls(remaining):
        if href not in seen:
            links.append(Link(href=href))
            seen.add(href)
    return links


# ----- checking a link -----------------------------------------------------

def is_ip_literal(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def decode_host(host):
    """Turn punycode labels ('xn--pple-43d') back into the letters shown."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def fold_lookalikes(text):
    return text.lower().translate(CONFUSABLES).replace("rn", "m").replace("vv", "w")


def imitated_brand(host):
    """A brand this host pretends to be, if it is not that brand's real site."""
    if not host or is_ip_literal(host) or brands.official_brand_for(host):
        return None
    shown = decode_host(host)
    for brand in brands.BRANDS:
        if brands.host_mentions_brand(shown, brand):
            return brand
        if brands.host_mentions_brand(fold_lookalikes(shown), brand):
            return brand
    return None


def check_userinfo_trap(parts, url):
    if "@" not in (parts.netloc or ""):
        return []
    fake = parts.netloc.rsplit("@", 1)[0]
    return [Signal(
        "url_at_trap", VERY_SERIOUS,
        "A link uses a hidden trick with the @ sign.",
        "Everything before the @ is ignored. The link really goes to the "
        "website after the @, not the one you see first.",
        f'"{url}" looks like "{fake}" but goes to "{parts.hostname}"',
    )]


def check_host(host, url):
    signals = []
    if is_ip_literal(host):
        signals.append(Signal(
            "url_ip_address", SERIOUS,
            "A link goes to a bare number address instead of a website name.",
            "Real companies use their name in web addresses. Number-only "
            "addresses are a common way to hide a fake website.",
            f'"{url}"',
        ))
        return signals
    shown = decode_host(host)
    brand = imitated_brand(host)
    if shown != host or any(ord(ch) > 127 for ch in shown):
        if brand:
            signals.append(Signal(
                "url_lookalike_letters", VERY_SERIOUS,
                f"A link uses lookalike letters to pretend to be {brand.name}.",
                "Some foreign letters look exactly like normal ones. The "
                "address looks real but is a different website.",
                f'"{url}" is shown as "{shown}"',
            ))
        else:
            signals.append(Signal(
                "url_foreign_letters", SERIOUS,
                "A link uses special foreign letters in the website name.",
                "These letters can imitate normal ones, so the address may "
                "not be what it seems.",
                f'"{url}" is shown as "{shown}"',
            ))
    elif brand:
        signals.append(Signal(
            "url_brand_lookalike", VERY_SERIOUS,
            f"A link pretends to be {brand.name}, but it is not their real website.",
            f"The address uses the name {brand.name}, but the real "
            f"{brand.name} website is {brand.domains[0]}.",
            f'"{url}" goes to "{brands.registrable_domain(host)}"',
        ))
    if brands.registrable_domain(host) in SHORTENERS or host in SHORTENERS:
        signals.append(Signal(
            "url_shortener", CAUTION,
            "A link is hidden behind a short link service.",
            "Short links hide where they really go. You cannot see the real "
            "website until it is too late.",
            f'"{url}"',
        ))
    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        signals.append(Signal(
            "url_risky_ending", MINOR,
            f'A link ends in ".{tld}", an ending often used by scam websites.',
            "Banks and government offices rarely use these endings.",
            f'"{url}"',
        ))
    return signals


def check_port(parts, url):
    try:
        port = parts.port
    except ValueError:
        port = -1
    if port in (None, 80, 443):
        return []
    return [Signal(
        "url_odd_port", CAUTION,
        "A link uses an unusual technical setting (a port number).",
        "Normal websites do not need this. It is often a sign of a "
        "home-made or fake website.",
        f'"{url}"',
    )]


def check_insecure(parts, url, scheme_given):
    if not scheme_given or parts.scheme.lower() != "http":
        return []
    path = (parts.path + "?" + parts.query).lower()
    if any(word in path for word in LOGIN_WORDS):
        return [Signal(
            "url_insecure_login", SERIOUS,
            "A link asks you to sign in on a page that is not secure.",
            "Real sign-in pages always start with https. This one does not, "
            "so anything you type could be stolen.",
            f'"{url}"',
        )]
    return [Signal(
        "url_not_secure", MINOR,
        "A link goes to a page that is not secure (no https).",
        "Information sent to this page is not protected.",
        f'"{url}"',
    )]


def check_link_text(link):
    """Shown text says one website, but the link really goes to another."""
    if not link.text:
        return []
    shown_tokens = [strip_edges(t) for t in link.text.split()]
    shown_urls = [t for t in shown_tokens if looks_like_url(t)]
    real_host = hostname_of(link.href)
    for shown in shown_urls:
        shown_host = hostname_of(shown)
        if brands.registrable_domain(shown_host) != brands.registrable_domain(real_host):
            return [Signal(
                "url_text_mismatch", VERY_SERIOUS,
                "A link shows one website but really goes to a different one.",
                "Scammers show a real company's address as the link text, "
                "but the link itself leads to their own website.",
                f'shows "{shown}" but really goes to "{real_host}"',
            )]
    return []


def analyze_link(link):
    """All warning signals for one link. Never opens the link."""
    url = link.href
    scheme_given = has_scheme(url)
    try:
        parts = split_url(url)
        host = (parts.hostname or "").rstrip(".")
    except ValueError:
        return [Signal(
            "url_malformed", CAUTION,
            "A link is broken or written in a strange way.",
            "Odd-looking links are often used to trick filters and people.",
            f'"{url}"',
        )]
    signals = check_userinfo_trap(parts, url)
    signals += check_host(host, url)
    signals += check_port(parts, url)
    signals += check_insecure(parts, url, scheme_given)
    signals += check_link_text(link)
    return signals


def analyze_links(links):
    signals = []
    for link in links:
        signals.extend(analyze_link(link))
    return signals


# ----- defanging -----------------------------------------------------------

def defang_url(url):
    """'https://evil.com/x' -> 'hxxps://evil[.]com/x' so it cannot be clicked."""
    url = re.sub(r"(?i)^http", "hxxp", url)
    url = re.sub(r"(?i)^ftp", "fxp", url)
    return url.replace(".", "[.]")


def defang_token(raw):
    core = strip_edges(raw)
    if "[.]" in core or not (looks_like_url(core) or looks_like_email(core) or has_scheme(core)):
        return raw
    start = raw.find(core)
    return raw[:start] + defang_url(core) + raw[start + len(core):]


def defang_text(text):
    """Defang every link, website name, and email address in free text."""
    return re.sub(r"\S+", lambda match: defang_token(match.group()), text or "")
