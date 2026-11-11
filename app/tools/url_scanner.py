import hashlib
import os
import re
from typing import List
from urllib.parse import urlparse

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

from app.redis_store import redis_store
from app.schemas import SanitizedEmailPayload, SingleUrlScanVerdict, UrlScanToolResult
from app.tools.sender_integrity import HOMOGLYPH_TRANSLATION, PROTECTED_BRAND_KEYWORDS

SUSPICIOUS_TLDS = (".xyz", ".top", ".zip", ".mov", ".click", ".loan", ".work", ".gq", ".tk", ".ml", ".cf")
CREDENTIAL_PATH_KEYWORDS = (
    "/login", "/signin", "/verify", "/secure", "/account-update",
    "/password", "/auth", "/confirm", "/webscr", "/token", "/wallet"
)
IPV4_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


async def _query_google_safe_browsing(url: str, api_key: str) -> List[str]:
    """Optional live integration with Google Safe Browsing v4 ThreatMatches API."""
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
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.post(endpoint, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                return [f"Google Safe Browsing match: {m.get('threatType')}" for m in matches]
    except Exception:
        pass
    return []


async def _scan_single_url(url: str, trusted_domains: dict) -> SingleUrlScanVerdict:
    url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
    cached = await redis_store.get_cached_url_scan(url_hash)
    if cached:
        cached["source"] = "REDIS_CACHE"
        return SingleUrlScanVerdict(**cached)

    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    domain = host[4:] if host.startswith("www.") else host
    path_and_query = f"{parsed.path or ''}?{parsed.query or ''}".lower()

    reasons: List[str] = []
    verdict = "CLEAN"
    source = "HEURISTIC_THREAT_SCANNER"
    risk_pts = 0

    if domain in trusted_domains:
        reasons.append(f"Domain '{domain}' is verified in Trusted Domains Redis DB.")
    else:
        # 1. Optional Google Safe Browsing live check
        sb_key = os.getenv("SAFE_BROWSING_API_KEY", "").strip()
        if sb_key:
            sb_hits = await _query_google_safe_browsing(url, sb_key)
            if sb_hits:
                reasons.extend(sb_hits)
                verdict = "MALICIOUS"
                source = "GOOGLE_SAFE_BROWSING"
                risk_pts = 30

        # 2. Brand lookalike / homoglyph domain check
        skeleton = domain.translate(HOMOGLYPH_TRANSLATION)
        for kw, canonical in PROTECTED_BRAND_KEYWORDS.items():
            norm_kw = kw.translate(HOMOGLYPH_TRANSLATION)
            if (kw in domain or norm_kw in skeleton) and domain != canonical:
                reasons.append(f"Lookalike phishing domain '{domain}' spoofing '{canonical}'.")
                verdict = "MALICIOUS"
                risk_pts = max(risk_pts, 30)

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
    )
    await redis_store.set_cached_url_scan(url_hash, result.model_dump())
    return result


async def scan_email_urls_and_attachments(email_payload: SanitizedEmailPayload) -> UrlScanToolResult:
    """
    Tool: Scan APIs (URLs) + Attachment Threat Check
    Scans all extracted URLs against Redis cache, Threat Intel APIs, and heuristics,
    plus evaluates anchor-text mismatches and high-risk attachment extensions.
    """
    trusted_domains = await redis_store.list_trusted_domains()
    verdicts: List[SingleUrlScanVerdict] = []

    for url in email_payload.extracted_urls:
        v = await _scan_single_url(url, trusted_domains)
        verdicts.append(v)

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

    if not verdicts and not high_risk_attachments:
        findings.append("No URLs or high-risk attachments present in email.")

    return UrlScanToolResult(
        total_urls_scanned=len(verdicts),
        malicious_count=malicious_count,
        suspicious_count=suspicious_count,
        url_verdicts=verdicts,
        high_risk_attachments=high_risk_attachments,
        component_score=min(30, score),
        findings=findings,
    )
