import re
from typing import Dict, List, Optional, Tuple
from app.redis_store import redis_store
from app.schemas import SanitizedEmailPayload, SenderIntegrityResult

# High-value brands commonly targeted by lookalike/homograph domains
PROTECTED_BRAND_KEYWORDS: Dict[str, str] = {
    "paypal": "paypal.com",
    "paypai": "paypal.com",
    "paypa1": "paypal.com",
    "microsoft": "microsoft.com",
    "micros0ft": "microsoft.com",
    "rnicrosoft": "microsoft.com",
    "google": "google.com",
    "g00gle": "google.com",
    "github": "github.com",
    "stripe": "stripe.com",
    "acme-corp": "acme-corp.internal",
}

HOMOGLYPH_TRANSLATION = str.maketrans({
    "0": "o",
    "1": "l",
    "i": "l",  # Catch capital-I spoofing 'l' (e.g. paypaI -> paypal)
    "!": "i",
    "5": "s",
    "@": "a",
})


def _parse_auth_protocol(auth_header: str, received_spf: str, protocol: str) -> str:
    """Extracts pass/fail/softfail/neutral/none from Authentication-Results or Received-SPF."""
    combined = f"{auth_header} {received_spf}".lower()
    match = re.search(rf"\b{protocol}\s*=\s*(pass|fail|softfail|neutral|temperror|permerror|none)\b", combined)
    if match:
        return match.group(1)
    if protocol == "spf" and received_spf:
        first_word = received_spf.strip().split()[0].lower()
        if first_word in ("pass", "fail", "softfail", "neutral", "none"):
            return first_word
    return "none"


def _detect_lookalike_domain(domain: str, display_name: str, trusted_domains: Dict[str, str]) -> Tuple[bool, Optional[str], bool]:
    """
    Returns (is_lookalike_domain, impersonated_brand, display_name_spoofing).
    """
    clean_domain = domain.lower().strip()
    if clean_domain in trusted_domains:
        return False, None, False

    # Normalize homoglyphs (e.g., paypaI-support.com -> paypal-support.com)
    skeleton = clean_domain.translate(HOMOGLYPH_TRANSLATION)
    for keyword, canonical_domain in PROTECTED_BRAND_KEYWORDS.items():
        norm_kw = keyword.translate(HOMOGLYPH_TRANSLATION)
        if (keyword in clean_domain or norm_kw in skeleton) and clean_domain != canonical_domain:
            return True, canonical_domain, False

    # Also check if Display Name claims to be a protected brand or executive while using an untrusted domain
    disp_lower = display_name.lower()
    for keyword, canonical_domain in PROTECTED_BRAND_KEYWORDS.items():
        if keyword in disp_lower and clean_domain != canonical_domain:
            return False, canonical_domain, True

    if any(role in disp_lower for role in ("ceo", "cfo", "chief executive", "it support", "security team", "payroll")):
        if clean_domain not in trusted_domains:
            return False, "Executive / Internal Authority", True

    return False, None, False


async def check_sender_receiver_integrity(email_payload: SanitizedEmailPayload) -> SenderIntegrityResult:
    """
    Tool: Sender/Receiver Integrity check
    Parses sender/receiver info, verifies cryptographic protocols (SPF, DKIM, DMARC),
    checks sender alignment (Reply-To / Return-Path), and queries Trusted Domains Redis DB.
    """
    hdr = email_payload.headers
    sender_domain = hdr.from_domain
    trusted_category = await redis_store.lookup_domain(sender_domain)
    all_trusted = await redis_store.list_trusted_domains()
    in_trusted_redis = trusted_category is not None

    spf_status = _parse_auth_protocol(hdr.authentication_results, hdr.received_spf, "spf")
    dkim_status = _parse_auth_protocol(hdr.authentication_results, "", "dkim")
    if dkim_status == "none" and hdr.dkim_signature_present:
        dkim_status = "present_unverified"
    dmarc_status = _parse_auth_protocol(hdr.authentication_results, "", "dmarc")

    reply_to_mismatch = bool(hdr.reply_to_domain and hdr.reply_to_domain != sender_domain)
    return_path_mismatch = bool(hdr.return_path_domain and hdr.return_path_domain != sender_domain)

    is_lookalike, impersonated_brand, display_name_spoof = _detect_lookalike_domain(
        sender_domain, hdr.from_display_name, all_trusted
    )

    score = 0
    findings: List[str] = []

    if in_trusted_redis and spf_status == "pass" and dkim_status == "pass" and dmarc_status == "pass":
        findings.append(
            f"Sender domain '{sender_domain}' is verified in Trusted Domains Redis DB ({trusted_category}) and passed SPF, DKIM, and DMARC."
        )
        score = 0
    else:
        if not in_trusted_redis:
            findings.append(f"Sender domain '{sender_domain}' is NOT present in Trusted Domains Redis DB.")
        else:
            findings.append(
                f"CRITICAL: Sender domain '{sender_domain}' is in Trusted Domains Redis DB, but cryptographic authentication failed (spoofed header)."
            )
            score += 15

        if dmarc_status in ("fail", "none"):
            score += 15 if (impersonated_brand or in_trusted_redis or dmarc_status == "fail") else 8
            findings.append(f"DMARC verification status is '{dmarc_status}'.")

        if spf_status in ("fail", "softfail"):
            score += 8
            findings.append(f"SPF verification failed with status '{spf_status}'.")

        if dkim_status in ("fail", "none"):
            score += 7
            findings.append(f"DKIM signature check returned '{dkim_status}'.")

        if is_lookalike:
            score += 20
            findings.append(
                f"Lookalike / typosquatted domain detected: '{sender_domain}' impersonates '{impersonated_brand}'."
            )

        if display_name_spoof:
            score += 12
            findings.append(
                f"Display name spoofing: '{hdr.from_display_name}' claims authority/brand identity from untrusted domain '{sender_domain}'."
            )

        if reply_to_mismatch:
            score += 12
            findings.append(
                f"Reply-To domain mismatch: From '{sender_domain}' vs Reply-To '{hdr.reply_to_domain}'."
            )

        if return_path_mismatch and not in_trusted_redis:
            score += 5
            findings.append(
                f"Return-Path domain ('{hdr.return_path_domain}') differs from sender domain ('{sender_domain}')."
            )

    capped_score = min(35, score)

    return SenderIntegrityResult(
        sender_address=hdr.from_address,
        sender_domain=sender_domain,
        normalized_domain=sender_domain.translate(HOMOGLYPH_TRANSLATION),
        in_trusted_domains_redis=in_trusted_redis,
        trusted_domain_category=trusted_category,
        spf_status=spf_status,
        dkim_status=dkim_status,
        dmarc_status=dmarc_status,
        reply_to_mismatch=reply_to_mismatch,
        return_path_mismatch=return_path_mismatch,
        impersonated_brand=impersonated_brand,
        is_lookalike_domain=is_lookalike,
        display_name_spoofing=display_name_spoof,
        component_score=capped_score,
        findings=findings,
    )

