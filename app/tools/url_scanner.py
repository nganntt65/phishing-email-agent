import hashlib
import os
import re
from typing import List, Optional
from urllib.parse import urlparse

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

from app import config
from app.domains import (
    brand_lookalike,
    find_trusted,
    first_party,
    has_strong_login_hint,
    is_academic_domain,
    is_shortener,
    lure_domain_strength,
    recipient_lookalike,
    registrable_domain,
    trusted_lookalike,
    trusted_name_other_ending,
    university_lookalike,
)
from app.redis_store import redis_store
from app.schemas import SanitizedEmailPayload, SenderIntegrityResult, SingleUrlScanVerdict, UrlScanToolResult
from app.tools.sender_integrity import HOMOGLYPH_TRANSLATION, PROTECTED_BRAND_KEYWORDS

SUSPICIOUS_TLDS = (".xyz", ".top", ".zip", ".mov", ".click", ".loan", ".work", ".gq", ".tk", ".ml", ".cf")
CREDENTIAL_PATH_KEYWORDS = (
    "/login", "/signin", "/verify", "/secure", "/account-update",
    "/password", "/auth", "/confirm", "/webscr", "/token", "/wallet"
)
IPV4_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Bump when the scanning rules change, so verdicts cached in a persistent Redis are not reused.
SCANNER_VERSION = "2026-11-13.2"
SAFE_BROWSING_UNREACHABLE = "Google Safe Browsing could not be reached, so this link was checked with local rules only."


def _cache_key(url: str, trusted_domains: dict) -> str:
    """A cached verdict is only valid for the exact rules and trusted list that produced it."""
    context = "|".join([
        SCANNER_VERSION,
        ",".join(sorted(trusted_domains)),
        ",".join(config.CAMPUS_DOMAINS),
        "sb" if os.getenv("SAFE_BROWSING_API_KEY", "").strip() else "nosb",
    ])
    return hashlib.sha256(f"{url}\n{context}".encode("utf-8")).hexdigest()


async def _query_google_safe_browsing(url: str, api_key: str) -> Optional[List[str]]:
    """Optional live integration with Google Safe Browsing v4 ThreatMatches API.

    Returns the list of matches ([] = checked and clean), or None when the service could not be
    reached. None must be reported to the user, never treated as "clean".
    """
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "phishing-email-agent", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    if httpx is None:
        return None
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(endpoint, json=payload)
        if resp.status_code != 200:
            return None
        matches = resp.json().get("matches", [])
        return [f"Google Safe Browsing match: {m.get('threatType')}" for m in matches]
    except Exception:
        return None


async def _scan_single_url(url: str, trusted_domains: dict) -> SingleUrlScanVerdict:
    url_hash = _cache_key(url, trusted_domains)
    cached = await redis_store.get_cached_url_scan(url_hash)
    if cached:
        cached["source"] = "REDIS_CACHE"
        return SingleUrlScanVerdict(**cached)

    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    domain = host[4:] if host.startswith("www.") else host
    path_and_query = f"{parsed.path or ''}?{parsed.query or ''}".lower()

    reasons: List[str] = []
    unavailable: List[str] = []  # checks that should have run but couldn't (reported, never hidden)
    verdict = "CLEAN"
    source = "HEURISTIC_THREAT_SCANNER"
    risk_pts = 0

    trusted_match = find_trusted(domain, trusted_domains) if domain else None
    is_trusted = bool(domain in trusted_domains or trusted_match)
    if is_trusted:
        matched = domain if domain in trusted_domains else trusted_match[0]
        if matched == domain:
            reasons.append(f"Domain '{domain}' is verified in Trusted Domains Redis DB.")
        else:
            reasons.append(f"Domain '{domain}' is a subdomain of '{matched}', which is verified in Trusted Domains Redis DB.")
    else:
        # 1. Optional Google Safe Browsing live check
        sb_key = os.getenv("SAFE_BROWSING_API_KEY", "").strip()
        if sb_key:
            sb_hits = await _query_google_safe_browsing(url, sb_key)
            if sb_hits is None:
                unavailable.append(SAFE_BROWSING_UNREACHABLE)
            elif sb_hits:
                reasons.extend(sb_hits)
                verdict = "MALICIOUS"
                source = "GOOGLE_SAFE_BROWSING"
                risk_pts = 30

        # 2. Brand lookalike / homoglyph domain check (whole-word match; brand-owned domains excluded)
        canonical = brand_lookalike(domain, PROTECTED_BRAND_KEYWORDS) if domain else None
        if canonical:
            reasons.append(f"Lookalike phishing domain '{domain}' spoofing '{canonical}'.")
            verdict = "MALICIOUS"
            risk_pts = max(risk_pts, 30)

        # 2b. Dressed up as a university address, a digit swapped into a university name, or a lookalike of a
        #     configured campus domain or of any domain on the trusted list
        imitated = (trusted_lookalike(domain, trusted_domains) or university_lookalike(domain)) if domain else None
        if imitated:
            if imitated in config.CAMPUS_DOMAINS:
                reasons.append(
                    f"Domain '{domain}' looks similar to the official campus domain '{imitated}' ({config.CAMPUS_NAME})."
                )
            elif is_academic_domain(domain) and is_academic_domain(imitated):
                reasons.append(f"Domain '{domain}' has a digit in place of a letter; it looks like '{imitated}'.")
            elif is_academic_domain(imitated):
                reasons.append(f"Domain '{domain}' is dressed up as a university address ('{imitated}') but isn't one.")
            else:
                reasons.append(f"Domain '{domain}' looks like '{imitated}' but isn't it.")
            verdict = "MALICIOUS"
            risk_pts = max(risk_pts, 30)

        # 2b'. Same name as a listed university, different ending (ntpu.com, ntpu.tw). Strong only with a sign-in hint.
        same_name = trusted_name_other_ending(domain, trusted_domains) if domain and not imitated else None
        if same_name:
            if has_strong_login_hint(url):
                reasons.append(f"Domain '{domain}' has the same name as '{same_name}' but a different ending, and it asks you to sign in.")
                verdict = "MALICIOUS"
                risk_pts = max(risk_pts, 30)
            else:
                reasons.append(f"Domain '{domain}' has the same name as '{same_name}' but a different ending, so it isn't that university (weak signal).")
                verdict = "SUSPICIOUS" if verdict == "CLEAN" else verdict
                risk_pts = max(risk_pts, 12)

        # 2c. Shortened link: the real destination is hidden
        if domain and is_shortener(domain):
            reasons.append(f"Shortened link ('{domain}') hides its real destination.")
            verdict = "SUSPICIOUS" if verdict == "CLEAN" else verdict
            risk_pts = max(risk_pts, 22)

        # 2d. A domain name built from the words scam sites use (webmail-upgrade-center.com, drive-docs-shared.com)
        lure_strength, lure_words = lure_domain_strength(domain) if domain else ("", [])
        if lure_strength == "strong":
            reasons.append(f"Domain '{domain}' is built from words scam sites use ({', '.join(lure_words)}).")
            verdict = "SUSPICIOUS" if verdict == "CLEAN" else verdict
            risk_pts = max(risk_pts, 22)
        elif lure_strength == "weak":
            reasons.append(f"Domain '{domain}' contains a word scam sites often use ('{lure_words[0]}') (weak signal).")
            verdict = "SUSPICIOUS" if verdict == "CLEAN" else verdict
            risk_pts = max(risk_pts, 12)

        # 3. Raw IP address or Punycode IDN homograph check
        if IPV4_REGEX.match(domain):
            reasons.append(f"URL uses raw IPv4 literal ('{domain}') instead of a domain name.")
            verdict = "MALICIOUS"
            risk_pts = max(risk_pts, 28)

        if "xn--" in domain:
            reasons.append(f"URL uses Punycode IDN encoding ('{domain}'), common in homograph attacks.")
            verdict = "SUSPICIOUS" if verdict == "CLEAN" else verdict
            risk_pts = max(risk_pts, 20)

        # 4. High-risk TLD check
        if domain.endswith(SUSPICIOUS_TLDS):
            reasons.append(f"Domain uses high-risk abused TLD ('{domain}').")
            verdict = "SUSPICIOUS" if verdict == "CLEAN" else verdict
            risk_pts = max(risk_pts, 18)

        # 5. Credential harvesting path keywords on untrusted domain
        matched_paths = [kw for kw in CREDENTIAL_PATH_KEYWORDS if kw in path_and_query]
        if matched_paths:
            reasons.append(
                f"Untrusted domain '{domain}' hosts credential/authentication path ({', '.join(matched_paths[:2])})."
            )
            if verdict == "MALICIOUS" or domain.endswith(SUSPICIOUS_TLDS):
                verdict = "MALICIOUS"
                risk_pts = max(risk_pts, 30)
            else:
                verdict = "SUSPICIOUS"
                risk_pts = max(risk_pts, 18)

        if parsed.scheme == "http":
            reasons.append("URL uses unencrypted HTTP protocol.")
            if verdict == "CLEAN":
                verdict = "SUSPICIOUS"
            risk_pts = max(risk_pts, 10)

    if not reasons:
        reasons.append("No malicious indicators detected on URL.")

    result = SingleUrlScanVerdict(
        url=url,
        domain=domain,
        verdict=verdict,
        source=source,
        reasons=reasons,
        risk_Contribution=risk_pts,
        trusted=is_trusted,
        checks_unavailable=unavailable,
    )
    if not unavailable:  # an incomplete check is retried next time rather than cached
        await redis_store.set_cached_url_scan(url_hash, result.model_dump())
    return result


async def scan_single_url(url: str, trusted_domains: dict) -> SingleUrlScanVerdict:
    """Public wrapper used by the stand-alone link scan (POST /api/v1/scan-url)."""
    return await _scan_single_url(url, trusted_domains)


WEAK_URL_MARKERS = ("credential/authentication path", "unencrypted http", "(weak signal)")


def _only_weak_reasons(v: SingleUrlScanVerdict) -> bool:
    return v.verdict == "SUSPICIOUS" and all(any(m in r.lower() for m in WEAK_URL_MARKERS) for r in v.reasons)


def _align_with_sender(v: SingleUrlScanVerdict, sender: Optional[SenderIntegrityResult]) -> SingleUrlScanVerdict:
    """A link on the sender's own domain is first-party: "reset your password at portal.westbrook.edu" from a
    DMARC-passing westbrook.edu email is not a credential lure. Only weak signals (login path, plain http) are
    waived; a lookalike or lure-word domain stays what it is. When the headers are absent (PDF, pasted text)
    the sender can't be authenticated, but a non-lookalike sender linking to its own domain is still first-party:
    forging the From line only helps an attacker if the link goes somewhere else."""
    if sender is None or not sender.sender_domain or sender.is_lookalike_domain:
        return v
    headers_absent = sender.dmarc_status == "unavailable"
    if not (sender.authenticated or headers_absent) or lure_domain_strength(sender.sender_domain)[0] == "strong":
        return v
    if not first_party(v.domain, sender.sender_domain):
        return v
    reg = registrable_domain(sender.sender_domain)
    if _only_weak_reasons(v):
        proof = "which passed authentication" if sender.authenticated else "(headers absent, so the sender itself is unverified)"
        return v.model_copy(update={
            "verdict": "CLEAN", "risk_Contribution": 0, "first_party": True,
            "reasons": [f"Link goes to the sender's own domain '{reg}' {proof}."],
        })
    return v.model_copy(update={"first_party": True})


def _recipient_check(v: SingleUrlScanVerdict, recipient: str) -> SingleUrlScanVerdict:
    """A link carrying the recipient's own university name on another domain (harrowgate-portal.net for a
    @harrowgate.ac.uk student) is a lookalike of that university."""
    if v.trusted or v.verdict == "MALICIOUS" or not recipient:
        return v
    imitated = recipient_lookalike(v.domain, recipient)
    if not imitated:
        return v
    reasons = [r for r in v.reasons if "No malicious indicators" not in r]
    reasons.insert(0, f"Domain '{v.domain}' is dressed up as the recipient's university ('{imitated}') but isn't it.")
    return v.model_copy(update={"verdict": "MALICIOUS", "risk_Contribution": max(v.risk_Contribution, 30), "reasons": reasons})


async def scan_email_urls_and_attachments(
    email_payload: SanitizedEmailPayload,
    links_verifiable: bool = True,
    sender: Optional[SenderIntegrityResult] = None,
) -> UrlScanToolResult:
    """
    Tool: Scan APIs (URLs) + Attachment Threat Check
    Scans all extracted URLs against Redis cache, Threat Intel APIs, and heuristics,
    plus evaluates anchor-text mismatches and high-risk attachment extensions.
    With `sender`, links on the authenticated sender's own domain are marked first-party.
    """
    trusted_domains = await redis_store.list_trusted_domains()
    verdicts: List[SingleUrlScanVerdict] = []

    for url in email_payload.extracted_urls:
        v = await _scan_single_url(url, trusted_domains)
        v = _recipient_check(v, email_payload.headers.to_address)
        verdicts.append(_align_with_sender(v, sender))

    malicious_count = sum(1 for v in verdicts if v.verdict == "MALICIOUS")
    suspicious_count = sum(1 for v in verdicts if v.verdict == "SUSPICIOUS")

    score = max((v.risk_Contribution for v in verdicts), default=0)
    findings: List[str] = []

    for v in verdicts:
        if v.verdict in ("MALICIOUS", "SUSPICIOUS"):
            findings.append(f"[{v.verdict}] {v.url} — {' '.join(v.reasons)}")
        else:
            findings.append(f"[CLEAN] {v.url} ({v.domain})")

    if email_payload.anchor_mismatches:
        score += 15
        for mm in email_payload.anchor_mismatches:
            findings.append(
                f"Deceptive Link Text: Anchor displays '{mm.visible_text_domain}' but redirects to '{mm.actual_href_domain}'."
            )

    high_risk_attachments: List[str] = []
    for att in email_payload.attachments:
        if att.is_high_risk_extension:
            high_risk_attachments.append(att.filename)
            score += 25
            findings.append(
                f"High-risk executable/script attachment detected: '{att.filename}' ({att.content_type})."
            )

    if not links_verifiable:
        findings.append(
            "Link destinations could not be recovered from this input, so the real targets of its links were not checked."
        )
    elif not verdicts and not high_risk_attachments:
        findings.append("No URLs or high-risk attachments present in email.")

    return UrlScanToolResult(
        total_urls_scanned=len(verdicts),
        malicious_count=malicious_count,
        suspicious_count=suspicious_count,
        url_verdicts=verdicts,
        high_risk_attachments=high_risk_attachments,
        component_score=min(30, score),
        findings=findings,
        limitations=list(dict.fromkeys(note for v in verdicts for note in v.checks_unavailable)),
    )
