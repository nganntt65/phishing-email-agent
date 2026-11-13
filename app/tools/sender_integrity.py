"""Tool: who sent this, and can we prove it?

Three separate questions, kept separate in the result:
- authenticated: did the From domain really send it (DMARC pass, or SPF and DKIM both pass)?
- who is that domain: trusted list, a real university domain (.edu, .ac.xx), free webmail, or unknown?
- is it pretending: lookalike of a brand, a university or a trusted domain; an authority title on an
  address that can't back it up; replies routed elsewhere?

`verified` = authenticated AND (trusted or a real university). Only a verified sender gets the
benign-context cap and escapes the scam-script floors (see app/patterns.py).
"""

import re
from typing import Dict, List, Optional, Tuple

from app import config
from app.domains import (
    authority_title,
    brand_lookalike,
    find_trusted,
    is_academic_domain,
    is_brand_owned,
    is_free_webmail,
    lure_domain_strength,
    recipient_lookalike,
    trusted_lookalike,
    university_lookalike,
)
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


def _lookalike(domain: str, trusted_domains: Dict[str, str], recipient: str = "") -> Optional[str]:
    """The brand, university, trusted domain or recipient's university this sender domain imitates, or None."""
    if not domain or domain in trusted_domains or find_trusted(domain, trusted_domains):
        return None
    return (
        brand_lookalike(domain, PROTECTED_BRAND_KEYWORDS)
        or trusted_lookalike(domain, trusted_domains)
        or university_lookalike(domain)
        or recipient_lookalike(domain, recipient)
    )


def _display_name_claim(display_name: str, domain: str) -> Optional[str]:
    """A brand or an authority role claimed in the display name, if the domain can't back it up."""
    disp_lower = (display_name or "").lower()
    for keyword, canonical_domain in PROTECTED_BRAND_KEYWORDS.items():
        if keyword in disp_lower and domain != canonical_domain and not is_brand_owned(domain):
            return canonical_domain
    return None


async def check_sender_receiver_integrity(email_payload: SanitizedEmailPayload) -> SenderIntegrityResult:
    hdr = email_payload.headers
    sender_domain = hdr.from_domain
    trusted_category = await redis_store.lookup_domain(sender_domain)
    all_trusted = await redis_store.list_trusted_domains()
    if trusted_category is None and sender_domain:
        parent = find_trusted(sender_domain, all_trusted)  # subdomains of a trusted domain are trusted too
        trusted_category = parent[1] if parent else None
    in_trusted_redis = trusted_category is not None

    if hdr.auth_headers_present:
        spf_status = _parse_auth_protocol(hdr.authentication_results, hdr.received_spf, "spf")
        dkim_status = _parse_auth_protocol(hdr.authentication_results, "", "dkim")
        if dkim_status == "none" and hdr.dkim_signature_present:
            dkim_status = "present_unverified"
        dmarc_status = _parse_auth_protocol(hdr.authentication_results, "", "dmarc")
    else:
        # Pasted text or a PDF: the headers simply aren't there. Report it, don't punish it.
        spf_status = dkim_status = dmarc_status = "unavailable"

    authenticated = hdr.auth_headers_present and (dmarc_status == "pass" or (spf_status == "pass" and dkim_status == "pass"))
    free_webmail = is_free_webmail(sender_domain)
    academic = bool(sender_domain) and is_academic_domain(sender_domain)

    reply_to_mismatch = bool(hdr.reply_to_domain and hdr.reply_to_domain != sender_domain)
    return_path_mismatch = bool(hdr.return_path_domain and hdr.return_path_domain != sender_domain)

    impersonated = _lookalike(sender_domain, all_trusted, hdr.to_address)
    is_lookalike = impersonated is not None
    verified_institution = academic and authenticated and not is_lookalike
    verified = authenticated and (in_trusted_redis or verified_institution)

    # A brand name or an official-sounding role in the display name, from an address that can't back it up:
    # a free webmail address, or an unknown domain that isn't authenticated. Never for trusted or real
    # university senders ("Dr. Sutanto" from westbrook.edu is just a professor).
    display_name_spoof = False
    brand_claim = _display_name_claim(hdr.from_display_name, sender_domain) if sender_domain else None
    title = authority_title(hdr.from_display_name)
    if brand_claim and not in_trusted_redis:
        display_name_spoof = True
        impersonated = impersonated or brand_claim
    elif title and sender_domain and not in_trusted_redis and not (academic and not is_lookalike) and (free_webmail or not authenticated):
        display_name_spoof = True
        impersonated = impersonated or f"'{title}' (role claimed in the display name)"

    lure_strength, lure_words = lure_domain_strength(sender_domain) if sender_domain and not in_trusted_redis else ("", [])

    score = 0
    findings: List[str] = []

    if verified and (in_trusted_redis or verified_institution) and not reply_to_mismatch:
        who = f"verified in Trusted Domains Redis DB ({trusted_category})" if in_trusted_redis else "a real university domain"
        findings.append(f"Sender domain '{sender_domain}' is {who} and passed authentication (SPF/DKIM/DMARC).")
        score = 0
    else:
        if not sender_domain:
            findings.append("No sender address was available, so the sender could not be checked.")
        elif verified_institution:
            findings.append(f"Sender domain '{sender_domain}' is a real university domain and passed authentication.")
        elif not in_trusted_redis:
            findings.append(f"Sender domain '{sender_domain}' is NOT present in Trusted Domains Redis DB.")
        elif not hdr.auth_headers_present:
            findings.append(
                f"Sender domain '{sender_domain}' is in the Trusted Domains Redis DB, but no authentication "
                f"headers were available to prove the message really came from it."
            )
        else:
            findings.append(
                f"CRITICAL: Sender domain '{sender_domain}' is in Trusted Domains Redis DB, but cryptographic authentication failed (spoofed header)."
            )
            score += 15

        if dmarc_status in ("fail", "none"):
            score += 15 if (is_lookalike or in_trusted_redis or dmarc_status == "fail") else 8
            findings.append(f"DMARC verification status is '{dmarc_status}'.")

        if spf_status in ("fail", "softfail"):
            score += 8
            findings.append(f"SPF verification failed with status '{spf_status}'.")

        if dkim_status in ("fail", "none"):
            score += 7
            findings.append(f"DKIM signature check returned '{dkim_status}'.")

        if not hdr.auth_headers_present:
            findings.append("No authentication headers (SPF/DKIM/DMARC) were available, so they could not be checked.")

        if free_webmail and sender_domain:
            findings.append(f"'{sender_domain}' is a free webmail service: anyone can open an address there, so passing checks only prove it was sent via that service.")

        if is_lookalike:
            score += 20
            if impersonated in config.CAMPUS_DOMAINS:
                findings.append(
                    f"Lookalike domain detected: '{sender_domain}' looks similar to the official campus domain "
                    f"'{impersonated}' ({config.CAMPUS_NAME})."
                )
            elif is_academic_domain(impersonated):
                findings.append(
                    f"Lookalike domain detected: '{sender_domain}' is dressed up as a university address "
                    f"('{impersonated}') but isn't one."
                )
            else:
                findings.append(
                    f"Lookalike / typosquatted domain detected: '{sender_domain}' impersonates '{impersonated}'."
                )

        if lure_strength == "strong":
            score += 10
            findings.append(f"Sender domain '{sender_domain}' is built from words scam sites use ({', '.join(lure_words)}).")
        elif lure_strength == "weak":
            score += 5
            findings.append(f"Sender domain '{sender_domain}' contains a word scam sites often use ('{lure_words[0]}').")

        if display_name_spoof:
            pts = 12 if (free_webmail or hdr.auth_headers_present) else 8  # headers absent (PDF): the claim is weaker evidence
            score += pts
            where = "a free webmail address" if free_webmail else f"untrusted domain '{sender_domain}'"
            findings.append(
                f"Display name spoofing: '{hdr.from_display_name}' claims authority/brand identity from {where}."
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
        impersonated_brand=impersonated,
        is_lookalike_domain=is_lookalike,
        display_name_spoofing=display_name_spoof,
        authenticated=authenticated,
        is_free_webmail=free_webmail,
        verified_institution=verified_institution,
        verified=verified,
        domain_lure_words=lure_words,
        component_score=capped_score,
        findings=findings,
    )
