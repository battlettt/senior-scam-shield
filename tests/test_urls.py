from senior_scam_shield.models import Link
from senior_scam_shield.urls import (analyze_link, defang_text, defang_url,
                                     extract_links, find_bare_urls, hostname_of,
                                     imitated_brand)


def codes_for(href, text=""):
    return {s.code for s in analyze_link(Link(href=href, text=text))}


def test_official_links_have_no_signals():
    assert codes_for("https://www.chase.com/statements") == set()
    assert codes_for("https://secure.alerts.chase.com/x") == set()
    assert codes_for("https://www.paypal.com/activity") == set()


def test_punycode_lookalike_is_caught():
    # "xn--pple-43d" is "аpple" written with a Cyrillic "а".
    assert "url_lookalike_letters" in codes_for("https://www.xn--pple-43d.com/id")


def test_raw_unicode_lookalike_is_caught():
    assert "url_lookalike_letters" in codes_for("https://www.аpple.com/id")


def test_all_cyrillic_apple_homograph_is_caught():
    # "xn--80ak6aa92e" shows as "аррӏе": every letter is Cyrillic.
    assert "url_lookalike_letters" in codes_for("https://xn--80ak6aa92e.com/")


def test_foreign_letters_without_brand_still_warned():
    # "xn--e1afmkfd" is the Russian word for "example".
    assert "url_foreign_letters" in codes_for("https://xn--e1afmkfd.com/")


def test_at_sign_trap_is_caught_and_real_host_named():
    signals = analyze_link(Link("https://www.amazon.com@198.51.100.4/orders"))
    trap = [s for s in signals if s.code == "url_at_trap"]
    assert trap and "198.51.100.4" in trap[0].evidence
    assert "url_ip_address" in {s.code for s in signals}


def test_ip_literal_hosts():
    assert "url_ip_address" in codes_for("http://203.0.113.7/login")
    assert "url_ip_address" in codes_for("http://[2001:db8::1]/login")


def test_shortener():
    assert "url_shortener" in codes_for("https://bit.ly/3abc")
    assert "url_shortener" in codes_for("tinyurl.com/xyz")


def test_odd_port():
    assert "url_odd_port" in codes_for("https://example.com:8443/")
    assert "url_odd_port" not in codes_for("https://example.com:443/")


def test_http_login_page():
    assert "url_insecure_login" in codes_for("http://example.com/account/login")
    assert "url_not_secure" in codes_for("http://example.com/recipes")
    assert codes_for("https://example.com/account/login") == set()


def test_brand_name_in_fake_host():
    assert "url_brand_lookalike" in codes_for("https://www.paypal.com.account-review.info/")
    assert "url_brand_lookalike" in codes_for("https://chase-secure-verify.com/login")
    assert "url_brand_lookalike" in codes_for("https://paypa1-support.com/")  # digit 1 for l


def test_brand_lookalike_avoids_common_words():
    assert imitated_brand("pineapple.com") is None
    assert imitated_brand("applebees.com") is None
    assert imitated_brand("citizensbank.com") is None
    assert imitated_brand("firstfinancial.com") is None


def test_link_text_mismatch_html_markdown_and_angle():
    assert "url_text_mismatch" in codes_for("https://docs-viewer.top/s/1", "www.bankofamerica.com")
    links = extract_links("See [www.chase.com](https://evil.example.net/x) and "
                          "www.wellsfargo.com <https://wf-help.example.org/y>")
    assert {(l.text, l.href) for l in links} == {
        ("www.chase.com", "https://evil.example.net/x"),
        ("www.wellsfargo.com", "https://wf-help.example.org/y"),
    }
    for link in links:
        assert "url_text_mismatch" in {s.code for s in analyze_link(link)}


def test_link_text_matching_host_is_fine():
    assert codes_for("https://www.chase.com/a", "www.chase.com") == set()
    assert codes_for("https://www.chase.com/a", "View your statement") == set()


def test_url_finder_ignores_money_abbreviations_and_emails():
    found = find_bare_urls("Pay $89.99 e.g. now. Mail me at jo@example.com or visit example.com/help.")
    assert found == ["example.com/help"]


def test_hosts_come_from_urllib_parse():
    assert hostname_of("HTTPS://WWW.Chase.COM:443/x") == "www.chase.com"
    assert hostname_of("https://user:pw@evil.example/x") == "evil.example"
    assert hostname_of("http://[bad") == ""


def test_malformed_url_is_reported_not_crashed():
    assert "url_malformed" in codes_for("http://[bad/login")


def test_defang_url_and_text():
    assert defang_url("https://evil.com/a.b") == "hxxps://evil[.]com/a[.]b"
    out = defang_text('Go to "www.chase.com", or https://bit.ly/x. Mail a@b.com.')
    assert out == 'Go to "www[.]chase[.]com", or hxxps://bit[.]ly/x. Mail a@b[.]com.'
    assert defang_text(out) == out  # safe to run twice
    assert defang_text("Pay $1.99 by Nov. 3") == "Pay $1.99 by Nov. 3"
