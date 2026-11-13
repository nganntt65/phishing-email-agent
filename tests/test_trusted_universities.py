"""The built-in trusted list is real universities plus a few student services, and Taiwan, Korea, HK etc. work."""

import asyncio
import re

import pytest

from app.domains import is_academic_domain, registrable_domain
from app.link_scan import analyze_url
from app.redis_store import DEFAULT_TRUSTED_DOMAINS, redis_store

DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
STUDENT_SERVICES = {"microsoftonline.com", "microsoft.com", "accounts.google.com", "github.com"}


def scan(url):
    async def go():
        await redis_store.initialize()
        return await analyze_url(url, use_llm=False)
    return asyncio.run(go())


def test_default_list_is_universities_plus_a_few_services():
    universities = {d for d in DEFAULT_TRUSTED_DOMAINS if d not in STUDENT_SERVICES}
    assert len(universities) >= 100
    assert STUDENT_SERVICES <= set(DEFAULT_TRUSTED_DOMAINS)
    assert all(DOMAIN.match(d) for d in DEFAULT_TRUSTED_DOMAINS)
    # Non-university entries that used to be built in, and places anyone can host a page on.
    for removed in ("paypal.com", "stripe.com", "acme-corp.internal", "google.com", "docs.google.com", "github.io"):
        assert removed not in DEFAULT_TRUSTED_DOMAINS


@pytest.mark.parametrize("domain", ["ntpu.edu.tw", "ntu.edu.tw", "ui.ac.id", "mit.edu", "ox.ac.uk", "nus.edu.sg", "snu.ac.kr", "hku.hk"])
def test_well_known_universities_are_listed(domain):
    assert domain in DEFAULT_TRUSTED_DOMAINS


def test_taiwan_style_domains_are_understood():
    assert registrable_domain("sso.ntpu.edu.tw") == "ntpu.edu.tw"
    assert is_academic_domain("ntpu.edu.tw") and is_academic_domain("www.snu.ac.kr")


@pytest.mark.parametrize("url", [
    "https://sso.ntpu.edu.tw/", "https://www.ntpu.edu.tw/", "https://ecampus.ntu.edu.tw/", "https://sso.ui.ac.id/cas/login",
    "https://www.ntu.edu.sg/", "https://login.microsoftonline.com/", "https://github.com/",
])
def test_real_university_portals_are_official(url):
    r = scan(url)
    assert r.summary.label == "Official domain match" and r.risk_score == 0


@pytest.mark.parametrize("url", [
    "https://ntpu.edu.tw.verify-login.com/sso", "https://ntpu-edu-tw.com/login", "https://portal.ntpu.edu.tw.evil.com/",
    "https://ntpu.edu.tw-secure.com/", "https://evil-ntu.edu.tw.cn/", "https://mit.edu.verify-account.net/login",
])
def test_lookalikes_of_listed_universities_are_suspicious(url):
    r = scan(url)
    assert r.summary.label == "Suspicious link" and r.risk_score >= 60


@pytest.mark.parametrize("url", ["https://www.nchc.edu.tw/", "https://example.org/", "https://docs.google.com/forms/d/abc/viewform"])
def test_unlisted_real_sites_are_unverified_not_flagged(url):
    r = scan(url)
    assert r.summary.label == "Unverified domain" and r.risk_score < 60
