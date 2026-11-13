"""The detection rules added on 2026-11-13: known scam scripts with a minimum score, sender verification,
first-party links, and the new link checks. Rules mode only (no Gemini)."""

import asyncio
import base64

import pytest

from app.domains import academic_typo, lure_domain_strength, recipient_lookalike, trusted_lookalike
from app.link_scan import analyze_url
from app.orchestrator import PhishingAgentOrchestrator
from app.redis_store import DEFAULT_TRUSTED_DOMAINS, redis_store

orchestrator = PhishingAgentOrchestrator()


def auth(domain, spf="pass", dkim="pass", dmarc="pass"):
    return (f"Authentication-Results: mx.example.edu; spf={spf} smtp.mailfrom={domain}; "
            f"dkim={dkim} header.i=@{domain}; dmarc={dmarc} header.from={domain}")


def eml(from_, subject, body, auth_line=None, reply_to=None, to="student@westbrook.edu"):
    enc = base64.encodebytes(body.encode("utf-8")).decode()
    lines = [f"From: {from_}", f"To: {to}", f"Subject: {subject}", "Date: Thu, 12 Nov 2026 08:30:00 +0800"]
    if reply_to:
        lines.append(f"Reply-To: {reply_to}")
    if auth_line:
        lines.append(auth_line)
    lines += ["MIME-Version: 1.0", 'Content-Type: text/plain; charset="UTF-8"', "Content-Transfer-Encoding: base64", "", enc]
    return "\n".join(lines)


def scan_email(raw):
    async def go():
        await redis_store.initialize()
        return await orchestrator.analyze_raw_eml(raw, use_llm=False, record_memory=False)
    return asyncio.run(go())


def scan_link(url):
    async def go():
        await redis_store.initialize()
        return await analyze_url(url, use_llm=False)
    return asyncio.run(go())


# ---------------------------------------------------------------- scam scripts get a floor of 60

def test_gift_card_request_from_professor_on_gmail_is_high():
    r = scan_email(eml('"Prof. Omar Sutanto" <prof.sutanto5@gmail.com>', "Are you available?",
                       "Hi, I need a favor. Can you buy 4 Apple gift cards for a student award today? I will reimburse you.",
                       auth("gmail.com")))
    assert r.risk_score >= 60 and "Gift-card request" in r.score_breakdown.patterns
    assert r.score_breakdown.pattern_floor == 60
    assert r.sender_integrity.display_name_spoofing and r.sender_integrity.is_free_webmail
    assert "gift cards" in r.summary.finding


def test_fee_to_release_scholarship_is_high():
    r = scan_email(eml("Grant Office <grants@education-award-office.org>", "Release your scholarship funds",
                       "You were selected for a $1,200 grant. A processing fee of $45 is required to release the funds.",
                       auth("education-award-office.org", "none", "none", "none")))
    assert r.risk_score >= 60 and "Fee to release money" in r.score_breakdown.patterns


def test_changed_bank_details_with_reply_to_elsewhere_is_high():
    r = scan_email(eml('"Harbor Catering Accounts" <billing@harbor-supply.co>', "Updated banking details",
                       "We have changed our bank account details. Please update your records before paying the overdue invoice.",
                       auth("harbor-supply.co", "softfail", "pass", "none"), reply_to="ap-desk@harbor-payments.net"))
    assert r.risk_score >= 60 and "Change of bank details" in r.score_breakdown.patterns


def test_bec_opener_from_webmail_without_links_is_high():
    r = scan_email(eml("Samuel Hartono <samuel.hartono.uni@gmail.com>", "Quick question",
                       "Hi, I need your help with something small for the department. Reply when you see this. Samuel",
                       auth("gmail.com")))
    assert r.risk_score >= 60 and "'Are you available?' opener" in r.score_breakdown.patterns


def test_friendly_personal_mail_from_gmail_stays_low():
    r = scan_email(eml("Kenji Fischer <kenji93@gmail.com>", "study group tomorrow?",
                       "Hey! Are we still meeting at the library at 3? - Kenji", auth("gmail.com")))
    assert r.risk_score < 30 and not r.score_breakdown.patterns


def test_mailbox_quota_lure_with_raw_ip_link_is_high():
    r = scan_email(eml("Email Quota Team <admin@webmail-upgrade-center.com>", "Your mailbox is 98% full",
                       "Dear user, your mailbox has exceeded its storage limit. Click here to upgrade your storage: "
                       "http://45.83.164.69/webmail/login", auth("webmail-upgrade-center.com", "none", "none", "none")))
    assert r.risk_score >= 60
    assert "built from words scam sites use" in " ".join(r.sender_integrity.findings)


def test_missed_delivery_with_shortened_link_is_high():
    r = scan_email(eml("Parcel Notifications <notify@parcel-alerts-center.com>", "Delivery attempt failed",
                       "We tried to deliver your package but nobody was available. Reschedule delivery: https://bit.ly/4fTr2Lm",
                       auth("parcel-alerts-center.com", "pass", "pass", "none")))
    assert r.risk_score >= 60 and "Missed-delivery notice" in r.score_breakdown.patterns
    assert any("Shortened link" in reason for v in r.url_scan.url_verdicts for reason in v.reasons)


def test_job_offer_asking_for_direct_deposit_details_is_high():
    r = scan_email(eml("Research Placement Team <hello@research-assistant-jobs.org>", "You have been shortlisted",
                       "Congratulations, you have been shortlisted. Please complete the short form with your student ID and "
                       "direct deposit details so we can set up payroll. Open the form: https://research-assistant-jobs.org/form",
                       auth("research-assistant-jobs.org")))
    assert r.risk_score >= 60 and "Asks for ID or banking details" in r.score_breakdown.patterns


# ---------------------------------------------------------------- verified senders and first-party links get no floor

def test_real_university_password_reset_stays_low():
    r = scan_email(eml("Westbrook IT Services <no-reply@westbrook.edu>", "Password reset requested",
                       "We received a request to reset your password. The link expires within 24 hours. "
                       "Reset password: https://portal.westbrook.edu/password/reset?token=abc", auth("westbrook.edu")))
    assert r.risk_score < 30 and r.score_breakdown.pattern_floor == 0
    assert r.sender_integrity.verified_institution and r.sender_integrity.verified
    assert r.url_scan.url_verdicts[0].first_party and r.url_scan.component_score == 0


def test_course_reminder_with_urgent_words_from_university_is_capped():
    r = scan_email(eml('"Dr. Sofia Sutanto" <sofia.sutanto@westbrook.edu>', "Assignment due tonight",
                       "This is a reminder that the assignment is due tonight. Submit immediately if you have not yet. "
                       "Late work will lose points. Course page: https://learn.westbrook.edu/courses/econ305", auth("westbrook.edu")))
    assert r.risk_score < 30 and not r.sender_integrity.display_name_spoofing
    assert r.score_breakdown.psychological_content_score <= 4


def test_bank_alert_linking_to_its_own_domain_stays_low_even_without_headers():
    body = ("We noticed unusual activity on your debit card. If this wasn't you, sign in to review it. "
            "Review transaction: https://harborview-bank.com/login")
    with_headers = scan_email(eml("Harborview Bank <alerts@harborview-bank.com>", "Unusual activity", body, auth("harborview-bank.com")))
    without = scan_email("From: Harborview Bank <alerts@harborview-bank.com>\nSubject: Unusual activity\n\n" + body)
    assert with_headers.risk_score < 60 and without.risk_score < 60
    assert with_headers.url_scan.url_verdicts[0].first_party and without.url_scan.url_verdicts[0].first_party


def test_same_text_from_unknown_sender_to_other_domain_is_high():
    r = scan_email(eml("Harborview Bank <alerts@harborview-bank.com>", "Unusual activity",
                       "We noticed unusual activity on your debit card. Sign in to review it: https://harborview-secure-login.com/login",
                       auth("harborview-bank.com", "fail", "none", "fail")))
    assert r.risk_score >= 60


def test_spoofed_trusted_sender_still_gets_floor():
    r = scan_email(eml("GitHub <noreply@github.com>", "Verify your account",
                       "Your account will be suspended. Verify your account now: https://github-verify-center.com/login",
                       auth("github.com", "fail", "fail", "fail")))
    assert r.risk_score >= 60 and not r.sender_integrity.verified


# ---------------------------------------------------------------- recipient's own university

def test_sender_imitating_the_recipients_university_is_a_lookalike():
    r = scan_email(eml("Student Accounts Office <registrar@harrowgate-it.help>", "Your grades are on hold",
                       "Our records show your account needs attention. Log in to access your course materials. "
                       "If you do not act immediately your access will be locked. Sign in to the student portal",
                       None, to="priya.osei@harrowgate.ac.uk"))
    assert r.sender_integrity.is_lookalike_domain and r.sender_integrity.impersonated_brand == "harrowgate.ac.uk"
    assert r.risk_score >= 60


def test_recipient_lookalike_needs_a_lure_word():
    assert recipient_lookalike("harrowgate-it.help", "priya@harrowgate.ac.uk") == "harrowgate.ac.uk"
    assert recipient_lookalike("harrowgate-portal.net", "priya@harrowgate.ac.uk") == "harrowgate.ac.uk"
    assert recipient_lookalike("harrowgte.ac.uk", "priya@harrowgate.ac.uk") == "harrowgate.ac.uk"
    assert recipient_lookalike("cedarridge-housing.com.cn", "alex@cedarridge.edu") == "cedarridge.edu"  # fake campus office
    assert recipient_lookalike("cedarridge-exams.top", "alex@cedarridge.edu") == "cedarridge.edu"
    assert recipient_lookalike("campus-housing.org", "alex@cedarridge.edu") is None  # no university name in it
    assert recipient_lookalike("lakesidetech-robotics.org", "a@lakesidetech.edu") is None  # a club, not a login lure
    assert recipient_lookalike("portal.harrowgate.ac.uk", "priya@harrowgate.ac.uk") is None
    assert recipient_lookalike("harrowgate-it.help", "priya@gmail.com") is None


# ---------------------------------------------------------------- link checks

@pytest.mark.parametrize("url", ["https://westbr0ok.edu/signin", "https://harr0wgate.ac.uk/signin", "https://1akesidetech.edu/signin"])
def test_digit_in_university_name_is_suspicious(url):
    r = scan_link(url)
    assert r.summary.label == "Suspicious link" and r.risk_score >= 60 and "digit" in r.summary.finding


def test_academic_typo_helper():
    assert academic_typo("westbr0ok.edu") == "westbrook.edu"
    assert academic_typo("cs50.edu") is None and academic_typo("web3.ac.uk") is None and academic_typo("ntpu.edu.tw") is None


@pytest.mark.parametrize("url", ["https://bit.ly/3Kx9qPz", "https://tinyurl.com/uni-grades"])
def test_shortened_links_are_suspicious(url):
    r = scan_link(url)
    assert r.summary.label == "Suspicious link" and "shortened" in r.summary.finding


@pytest.mark.parametrize("url", ["https://drive-docs-shared.com/login", "https://wallet-verify-center.com/wallet", "https://secure-docs-share.net/view?doc=1"])
def test_domains_built_from_security_words_are_suspicious(url):
    r = scan_link(url)
    assert r.summary.label == "Suspicious link" and "words scam sites use" in r.summary.finding


@pytest.mark.parametrize("url", ["https://campus-film-society.org/schedule", "https://harborview-bank.com/login",
                                 "https://canvas.instructure.com/login", "https://parcelway-delivery.com/track/1"])
def test_ordinary_hyphenated_or_login_domains_stay_unverified(url):
    r = scan_link(url)
    assert r.summary.label == "Unverified domain" and r.risk_score < 60


def test_lure_word_strength():
    assert lure_domain_strength("webmail-upgrade-center.com")[0] == "strong"
    assert lure_domain_strength("fastmail-secure.net")[0] == "weak"
    assert lure_domain_strength("harborview-bank.com")[0] == ""
    assert lure_domain_strength("docs.google.com")[0] == ""  # brand-owned domains are never lure domains


@pytest.mark.parametrize("url,imitates", [("https://ntpu-login.com/sso", "ntpu.edu.tw"), ("https://ntpu.edu.tvv/", "ntpu.edu.tw"),
                                          ("https://harvrad.edu/login", "harvard.edu"), ("https://mit-secure.net/", "mit.edu")])
def test_lookalikes_of_trusted_universities(url, imitates):
    assert trusted_lookalike(url.split("/")[2], DEFAULT_TRUSTED_DOMAINS) == imitates
    r = scan_link(url)
    assert r.summary.label == "Suspicious link" and r.impersonated == imitates


def test_real_neighbouring_universities_are_not_lookalikes():
    for host in ("nthu.edu.tw", "ntnu.edu.tw", "ncku.edu.tw", "ntpu-robotics.org"):
        assert trusted_lookalike(host, DEFAULT_TRUSTED_DOMAINS) is None


# ---------------------------------------------------------------- NTPU-style cases (2026-11-13)

@pytest.mark.parametrize("url,meant", [("https://ssa.ntpu.edu.tw/", "sso.ntpu.edu.tw"), ("https://ss0.ntpu.edu.tw/login", "sso.ntpu.edu.tw"),
                                       ("https://logn.ntpu.edu.tw/", "login.ntpu.edu.tw")])
def test_misspelled_sign_in_page_on_real_domain_is_a_caution_not_official(url, meant):
    r = scan_link(url)
    assert r.summary.label == "Unverified domain" and 30 <= r.risk_score < 60  # caution, never a scam verdict
    assert meant in r.summary.finding and "misspelling" in r.summary.finding


@pytest.mark.parametrize("url", ["https://www.ntpu.edu.tw/", "https://my.ntpu.edu.tw/", "https://lms.ntpu.edu.tw/",
                                 "https://cof.ntpu.edu.tw/", "https://iso.ntpu.edu.tw/", "https://sso.ntpu.edu.tw/"])
def test_real_ntpu_subdomains_stay_official(url):
    r = scan_link(url)
    assert r.summary.label == "Official domain match" and r.risk_score == 0


def test_official_subdomain_wording_is_honest():
    assert "not whether this page exists" in scan_link("https://lms.ntpu.edu.tw/").summary.finding


@pytest.mark.parametrize("url", ["https://ntpu.com/login", "https://sso.ntpu.com/", "https://sso.ntpu.tw/", "https://sso.ntpuedu.tw/"])
def test_same_university_name_elsewhere_with_sign_in_is_suspicious(url):
    r = scan_link(url)
    assert r.summary.label == "Suspicious link" and r.risk_score >= 60


@pytest.mark.parametrize("url", ["https://ntpu.net/", "https://www.columbia.com/", "https://yale.com/", "https://harvard.com/books"])
def test_same_name_without_sign_in_is_only_a_caution(url):
    r = scan_link(url)  # columbia.com is a clothing brand, yale.com sells locks: never call them scams
    assert r.summary.label == "Unverified domain" and r.risk_score < 60 and "different ending" in r.summary.finding


def test_real_neighbouring_university_is_not_flagged():
    assert scan_link("https://sso.nptu.edu.tw/").summary.label == "Unverified domain"  # NPTU is a real university
