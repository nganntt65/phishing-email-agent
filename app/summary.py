"""Plain-language result cards for the student-facing CampusGuard AI view.

Both link scans and email scans (PDF, .eml, pasted text) produce the same `ScanSummary` shape:
what we found, why it matters, and what to do next. Wording is generic (any university); a
configured campus (see app/config.py) only adds its name and an "Open official campus portal" button.
"""

import re
from typing import List, Optional

from app import config
from app.domains import BRAND_NAMES, is_academic_domain, is_login_like, university_lookalike
from app.evidence import PAYMENT_RE, SIGNIN_RE, URGENCY_TERMS, email_text
from app.schemas import (
    RiskLevel,
    SanitizedEmailPayload,
    ScanSummary,
    SenderIntegrityResult,
    SingleUrlScanVerdict,
    SummaryAction,
    UrlScanToolResult,
)

LINK_OFFICIAL = "Official domain match"
LINK_SUSPICIOUS = "Suspicious link"
LINK_UNVERIFIED = "Unverified domain"

EMAIL_LABELS = {
    RiskLevel.CRITICAL: ("Likely scam", "danger"),
    RiskLevel.HIGH: ("Suspicious email", "danger"),
    RiskLevel.MEDIUM: ("Unverified sender", "caution"),
    RiskLevel.LOW: ("No red flags found", "ok"),
}

STEP_SIGN_IN_YOURSELF = "If you need to sign in, type your university's website address yourself instead of using the link."
STEP_SIGN_IN_GENERIC = "If you need to sign in somewhere, type that site's address yourself instead of using the link."
STEP_REPORT = "Report it to your university's IT help desk."


def _sign_in_step(impersonated: Optional[str], university_related: bool, login_like: bool) -> Optional[str]:
    """Name the real site to go to, instead of always saying 'your university'."""
    if impersonated and impersonated in BRAND_NAMES:
        return f"If you need to sign in to {BRAND_NAMES[impersonated]}, type {impersonated} into your browser yourself."
    if university_related:
        return STEP_SIGN_IN_YOURSELF
    if login_like:
        return STEP_SIGN_IN_GENERIC
    return None


def _portal_action() -> Optional[SummaryAction]:
    if not config.CAMPUS_PORTAL_URL:
        return None
    return SummaryAction(kind="open_portal", label="Open official campus portal", url=config.CAMPUS_PORTAL_URL)


def _scan_another() -> SummaryAction:
    return SummaryAction(kind="scan_another", label="Scan another")


def _paste_link() -> SummaryAction:
    return SummaryAction(kind="paste_link", label="Paste the link to check it")


def _is_campus(domain: Optional[str]) -> bool:
    return bool(domain) and domain in config.CAMPUS_DOMAINS


def _is_university(domain: Optional[str]) -> bool:
    return bool(domain) and is_academic_domain(domain)


# ---------------------------------------------------------------- link scans

def link_finding(verdict: SingleUrlScanVerdict, label: str, trusted_category: Optional[str],
                 impersonated: Optional[str], userinfo_host: Optional[str],
                 trusted_domain: Optional[str] = None, misspelling_of: Optional[str] = None) -> str:
    domain = verdict.domain
    reasons = " ".join(verdict.reasons).lower()
    if misspelling_of:
        return (f"{domain} belongs to {trusted_domain}, but it isn't the usual sign-in page: it looks like a "
                f"misspelling of {misspelling_of}.")
    if label == LINK_OFFICIAL:
        if trusted_category and trusted_category.startswith("Official campus domain"):
            return f"{domain} is an official {config.CAMPUS_NAME} domain."
        if trusted_domain and domain != trusted_domain:
            what = f" ({trusted_category})" if trusted_category else ""
            return f"{domain} belongs to {trusted_domain}{what}. We checked the address, not whether this page exists."
        if trusted_category:
            return f"{domain} is on the trusted list: {trusted_category}."
        return f"{domain} is on the trusted list."
    if userinfo_host:
        return f"The part before the '@' is a disguise. This link really opens {userinfo_host}."
    if _is_campus(impersonated):
        return f"This domain looks similar to the official campus login domain ({impersonated})."
    if "digit in place of a letter" in reasons and impersonated:
        return f"This address looks like {impersonated} but has a digit where a letter should be."
    if _is_university(impersonated):
        return f"This address is dressed up as a university address ({impersonated}) but isn't one."
    if impersonated:
        return f"This domain imitates {impersonated} but isn't it."
    if "shortened link" in reasons:
        return "This is a shortened link, so you can't see where it really goes."
    if "same name as" in reasons:
        same = re.search(r"same name as '([^']+)'", " ".join(verdict.reasons))
        return (f"This address has the same name as {same.group(1)} but a different ending, so it isn't that university's site."
                if same else "This address copies a university's name with a different ending.")
    if "built from words scam sites use" in reasons:
        words = re.search(r"built from words scam sites use \(([^)]+)\)", " ".join(verdict.reasons))
        if words:
            return f"This address is made of words scam sites use ({words.group(1)}) and isn't a site we know."
        return "This address is made of words scam sites use and isn't a site we know."
    if "ipv4" in reasons:
        return "This link uses a raw IP address instead of a named website."
    if "punycode" in reasons:
        return "This address uses look-alike characters from other alphabets."
    if "high-risk abused tld" in reasons:
        tld = domain.rsplit(".", 1)[-1]
        return f"This link uses a domain ending (.{tld}) that scammers use often."
    if "credential/authentication path" in reasons:
        return "This link goes to a login page on a site we can't verify."
    if "unencrypted http" in reasons:
        return "This link isn't encrypted (http), so anything you type could be read by others."
    if "safe browsing" in reasons:
        return "Google Safe Browsing lists this link as dangerous."
    return f"{domain} isn't on our list of official or known domains."


def build_link_summary(
    *,
    url: str,
    verdict: SingleUrlScanVerdict,
    label: str,
    trusted_category: Optional[str],
    impersonated: Optional[str],
    userinfo_host: Optional[str],
    trusted_domain: Optional[str] = None,
    misspelling_of: Optional[str] = None,
) -> ScanSummary:
    login_like = is_login_like(url)
    university_related = _is_campus(impersonated) or _is_university(impersonated)
    finding = link_finding(verdict, label, trusted_category, impersonated, userinfo_host, trusted_domain, misspelling_of)

    if label == LINK_OFFICIAL:
        tone = "ok"
        why = "Links on official domains are run by the real organization."
        steps = ["This link goes where it says. You can open it."]
    elif label == LINK_SUSPICIOUS:
        tone = "danger"
        if login_like or university_related:
            why = "Fake login pages steal passwords. Typing yours here could give someone else access to your account."
        else:
            why = "Scam links often hide where they really go or point to throwaway sites."
        steps = ["Don't open the link or enter any password or personal details."]
        sign_in = _sign_in_step(impersonated, university_related, login_like)
        if sign_in:
            steps.append(sign_in)
        steps.append("Report the message that contained this link to your university's IT help desk.")
    elif misspelling_of:
        tone = "caution"
        why = "A one-letter slip can take you to a different page than the sign-in page you meant to open."
        steps = [f"Check the spelling. The sign-in page is probably {misspelling_of}.",
                 "Type the address yourself instead of using this link."]
    else:
        tone = "caution"
        if login_like:
            why = "Fake login pages look exactly like real ones. If this isn't a site you already use, your password could end up with someone else."
        else:
            why = "We can't tell who runs this site, so be careful with passwords and personal details."
        steps = [
            "Only continue if you were expecting this link from someone you know.",
            "Never sign in through a link you can't verify. Type the address yourself.",
        ]

    actions: List[SummaryAction] = []
    portal = _portal_action()
    if portal and label != LINK_OFFICIAL and (login_like or university_related):
        actions.append(portal)
    actions.append(_scan_another())
    return ScanSummary(label=label, tone=tone, checked=verdict.domain, finding=finding,
                       why_it_matters=why, next_steps=steps, actions=actions)


# ---------------------------------------------------------------- email scans

def _why_email(level: RiskLevel, payload: SanitizedEmailPayload, sender: SenderIntegrityResult,
               urls: UrlScanToolResult, injection: bool, pattern_why: Optional[str] = None) -> str:
    text = email_text(payload).lower()
    if level == RiskLevel.LOW:
        if sender.in_trusted_domains_redis and sender.verified:
            return "The sender is on the trusted list, passed authentication, and the links go to known domains."
        if sender.verified_institution:
            return "The sender is a real university address that passed authentication, and the links stay on its own domain."
        return "We didn't find the warning signs scams usually have."
    if sender.is_lookalike_domain and sender.impersonated_brand:
        target = sender.impersonated_brand
        if _is_campus(target):
            return f"The sender's address imitates the official campus domain ({target}) but isn't it."
        if _is_university(target):
            return f"The sender's address is dressed up as a university address ({target}) but isn't one."
        return f"The sender's address imitates {target} but isn't it."
    if any(v.verdict == "MALICIOUS" for v in urls.url_verdicts) or payload.anchor_mismatches:
        return "Its link doesn't go where it claims to. That's how fake login pages and malware are delivered."
    if urls.high_risk_attachments:
        return "Opening that file could install malware on your computer."
    if injection:
        return "Scammers add hidden text like this to slip past security filters."
    if pattern_why:
        return pattern_why
    if sender.dmarc_status == "fail" or sender.spf_status == "fail":
        return "The message failed the checks that confirm who really sent it."
    if PAYMENT_RE.search(text):
        return "Real offices don't ask for payment changes or gift cards by email."
    if sender.reply_to_mismatch:
        return "Your reply would go to a different address than the one it appears to come from."
    if any(term in text for term in URGENCY_TERMS):
        return "It pushes you to act quickly, which is how scams stop people from double-checking."
    return "We couldn't confirm who sent it, so treat its links and requests with care."


def build_email_summary(
    *,
    level: RiskLevel,
    finding: str,
    payload: SanitizedEmailPayload,
    sender: SenderIntegrityResult,
    urls: UrlScanToolResult,
    injection: bool,
    link_unrecovered: bool,
    has_signals: bool = False,
    pattern_why: Optional[str] = None,
) -> ScanSummary:
    label, tone = EMAIL_LABELS[level]
    if level == RiskLevel.LOW and has_signals and not sender.verified:
        label = "Low risk"  # some warning signs were found, so "No red flags" would be untrue
    text = email_text(payload)
    asks_signin = bool(SIGNIN_RE.search(text))
    university_related = bool(
        _is_campus(sender.impersonated_brand) or _is_university(sender.impersonated_brand)
        or any(university_lookalike(v.domain) for v in urls.url_verdicts if v.domain)
    )
    login_links = any(is_login_like(v.url) for v in urls.url_verdicts if v.verdict != "CLEAN")

    if level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        steps = ["Don't click its links, open its attachments, or reply."]
        if PAYMENT_RE.search(text):
            steps.append("Confirm any payment request by calling the person on a number you already know.")
        sign_in = _sign_in_step(sender.impersonated_brand, university_related, asks_signin or login_links)
        if sign_in:
            steps.append(sign_in)
        steps.append(f"{STEP_REPORT[:-1]}, then delete it.")
    elif level == RiskLevel.MEDIUM:
        steps = [
            "Check the sender's address carefully before you reply or click.",
            "Open websites by typing the address yourself instead of using the email's links.",
        ]
    elif label == "Low risk":
        steps = [
            "It doesn't look like a scam, but don't sign in or pay through its links. Go to the site yourself.",
            "If you weren't expecting it, check the sender before replying.",
        ]
    else:
        steps = ["Nothing else to do. Stay alert if anything about it still feels off."]

    if link_unrecovered:
        steps.append("We couldn't recover the link from this file. Paste it below to check it separately.")

    actions: List[SummaryAction] = []
    portal = _portal_action()
    if portal and level != RiskLevel.LOW and (asks_signin or university_related or login_links):
        actions.append(portal)
    if link_unrecovered:
        actions.append(_paste_link())
    actions.append(_scan_another())

    why = _why_email(level, payload, sender, urls, injection, pattern_why)
    if label == "Low risk":
        why = "Signs like these also show up in ordinary emails, and nothing else here points to a scam."

    hdr = payload.headers
    checked = hdr.from_address or "Sender unknown"
    if hdr.subject:
        checked = f"{checked} · {hdr.subject}"

    return ScanSummary(
        label=label,
        tone=tone,
        checked=re.sub(r"\s+", " ", checked)[:160],
        finding=finding,
        why_it_matters=why,
        next_steps=steps,
        actions=actions,
        link_unrecovered=link_unrecovered,
    )
