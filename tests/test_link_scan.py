import asyncio

import pytest

from app import config
from app.link_scan import InvalidUrlError, analyze_url, normalize_url
from app.redis_store import redis_store
from app.summary import LINK_OFFICIAL, LINK_SUSPICIOUS, LINK_UNVERIFIED


def scan(url: str):
    async def _run():
        await redis_store.initialize()
        return await analyze_url(url, use_llm=False)
    return asyncio.run(_run())


@pytest.mark.parametrize("raw, expected_host", [
    ("portal.westbrook.edu/login", "portal.westbrook.edu"),
    ("  https://GitHub.com/settings  ", "github.com"),
    ("<https://www.paypal.com/x>", "www.paypal.com"),
])
def test_normalize_accepts_and_cleans(raw, expected_host):
    normalized, host, userinfo = normalize_url(raw)
    assert host == expected_host
    assert normalized.startswith(("https://", "http://"))
    assert userinfo is None


@pytest.mark.parametrize("raw", ["", "   ", "not a url", "javascript:alert(1)", "mailto:a@b.com", "localhost",
                                 "ftp://files.example.com", "https://", "x" * 3000])
def test_normalize_rejects_with_readable_message(raw):
    with pytest.raises(InvalidUrlError) as err:
        normalize_url(raw)
    assert str(err.value)  # message is shown next to the field


def test_unicode_host_becomes_punycode():
    _, host, _ = normalize_url("https://pаypal.com/login")  # Cyrillic 'а'
    assert host.startswith("xn--")


def test_trusted_list_domain_is_official():
    r = scan("https://docs.github.com/en/authentication")
    assert r.label == LINK_OFFICIAL
    assert r.risk_score == 0
    assert r.summary.tone == "ok"
    assert [a.kind for a in r.summary.actions] == ["scan_another"]


def test_generic_university_lookalike_without_any_campus_configured():
    r = scan("https://westbrook.edu-verify.com/login")
    assert r.label == LINK_SUSPICIOUS
    assert r.impersonated == "westbrook.edu"
    assert "dressed up as a university address" in r.summary.finding
    assert [a.kind for a in r.summary.actions] == ["scan_another"]  # no portal button: no campus configured


def test_dash_edu_lookalike():
    r = scan("https://lakesidetech-edu.com/sso")
    assert r.label == LINK_SUSPICIOUS
    assert r.impersonated == "lakesidetech.edu"


def test_real_university_domain_is_not_flagged_as_lookalike():
    r = scan("https://portal.westbrook.edu/login")
    assert r.label == LINK_UNVERIFIED  # not on the trusted list, but no red flag either
    assert r.impersonated is None


def test_configured_campus_uses_spec_wording_and_portal_button(monkeypatch):
    monkeypatch.setattr(config, "CAMPUS_NAME", "Westbrook University")
    monkeypatch.setattr(config, "CAMPUS_DOMAINS", ["westbrook.edu"])
    monkeypatch.setattr(config, "CAMPUS_PORTAL_URL", "https://portal.westbrook.edu")
    r = scan("https://westbr0ok.edu/login")
    assert r.label == LINK_SUSPICIOUS
    assert r.summary.finding == "This domain looks similar to the official campus login domain (westbrook.edu)."
    assert [a.kind for a in r.summary.actions] == ["open_portal", "scan_another"]
    assert r.summary.actions[0].label == "Open official campus portal"
    assert r.summary.actions[0].url == "https://portal.westbrook.edu"


def test_at_sign_disguise_is_suspicious():
    r = scan("https://portal.westbrook.edu@evil-site.com/login")
    assert r.label == LINK_SUSPICIOUS
    assert r.domain == "evil-site.com"
    assert "evil-site.com" in r.summary.finding


def test_unknown_login_page_is_unverified_not_suspicious():
    r = scan("https://canvas.instructure.com/login")
    assert r.label == LINK_UNVERIFIED
    assert r.summary.tone == "caution"


def test_unknown_benign_site_is_unverified_low_risk():
    r = scan("https://en.wikipedia.org/wiki/Phishing")
    assert r.label == LINK_UNVERIFIED
    assert r.risk_score == 0


@pytest.mark.parametrize("url", [
    "https://username.github.io/portfolio/",
    "https://raw.githubusercontent.com/user/repo/main/README.md",
    "https://storage.googleapis.com/bucket/file.pdf",
    "https://www.google.co.id/search?q=beasiswa",
    "https://www.pinstripes.com/",
])
def test_real_brand_domains_and_unrelated_words_are_not_lookalikes(url):
    r = scan(url)
    assert r.label != LINK_SUSPICIOUS, r.summary.finding
    assert r.impersonated is None


def test_microsoft_365_sign_in_is_official():
    r = scan("https://login.microsoftonline.com/common/oauth2/authorize?client_id=abc")
    assert r.label == LINK_OFFICIAL


@pytest.mark.parametrize("url, brand", [
    ("https://paypa1-secure.com/signin", "paypal.com"),
    ("https://paypalsecurity-center.com/login", "paypal.com"),
    ("https://accounts.google.com.evil.com/login", "google.com"),
    ("https://micros0ft-office365.com/verify", "microsoft.com"),
    ("https://rnicrosoft-support.com/account", "microsoft.com"),
])
def test_brand_lookalikes_still_caught(url, brand):
    r = scan(url)
    assert r.label == LINK_SUSPICIOUS
    assert r.impersonated == brand


@pytest.mark.parametrize("url, uni", [
    ("https://ui.ac.id-login.com/sso", "ui.ac.id"),
    ("https://sso.ui.ac.id.verify-account.com/login", "ui.ac.id"),
    ("https://ui-ac-id.com/login", "ui.ac.id"),
    ("https://itb.ac.id-login.com/sso", "itb.ac.id"),
])
def test_short_university_names_are_caught(url, uni):
    r = scan(url)
    assert r.label == LINK_SUSPICIOUS
    assert r.impersonated == uni


def test_suspicious_label_always_means_high_risk():
    r = scan("https://free-laptop-giveaway.xyz/")
    assert r.label == LINK_SUSPICIOUS
    assert r.risk_score >= 60 and r.risk_level.value in ("HIGH", "CRITICAL")


def test_brand_lookalike_next_step_names_the_real_site():
    r = scan("https://paypa1-secure.com/signin")
    assert any("type paypal.com" in s for s in r.summary.next_steps)
    assert not any("university" in s for s in r.summary.next_steps[:2])


@pytest.mark.parametrize("raw, expected", [
    ("github.com.", "https://github.com/"),
    ("https://github.com).", "https://github.com/"),
    ("(https://github.com/x)", "https://github.com/x"),
    ("https://github.com/x).", "https://github.com/x"),
    ("https://en.wikipedia.org/wiki/Python_(programming_language)",
     "https://en.wikipedia.org/wiki/Python_(programming_language)"),
])
def test_chat_punctuation_is_stripped_but_url_brackets_kept(raw, expected):
    assert normalize_url(raw)[0] == expected


def test_ip_link_registrable_domain_is_the_ip():
    assert scan("http://192.168.10.5/login.php").registrable_domain == "192.168.10.5"


def test_link_scan_reports_llm_status_without_key():
    r = scan("github.com")
    assert r.llm_status.value == "SKIPPED_BY_REQUEST"
    assert r.llm_status_message
