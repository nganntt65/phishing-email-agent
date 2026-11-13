"""Evidence extraction and grounding.

- `quote_for_term` returns the verbatim sentence that contains a matched rule term, so rule-engine
  evidence is always copied from the email (grounded by construction).
- `ground_evidence` checks LLM quotes against the email text. An LLM can invent a plausible quote;
  the UI shows ungrounded quotes struck through and the evaluation reports the grounded share.
- `primary_finding` names the specific thing the email asks the reader to do, in plain words.
"""

import re
from typing import Iterable, List, Optional

from app.schemas import EvidenceItem, SanitizedEmailPayload, SenderIntegrityResult, UrlScanToolResult

_SENTENCE_END = re.compile(r"[.!?\n]")

SIGNIN_RE = re.compile(
    r"\b(sign[\s-]?in|log[\s-]?in|log on|verify your (?:account|identity|credentials|email|student account)|"
    r"confirm your (?:password|account|identity|credentials|login)|re-?authenticate|"
    r"reset your (?:password|mfa)|re-?enter your password|update your password|validate your account)\b",
    re.IGNORECASE,
)
PURPOSE_RE = re.compile(
    r"\b(?:sign[\s-]?in|log[\s-]?in|log on|verify your (?:account|identity)|confirm your (?:account|identity))"
    r"(?:\s+[\w'-]+){0,4}?\s+(?:to|and)\s+"
    r"((?:view|access|see|check|claim|keep|avoid|restore|update|review|download|receive|release|unlock|secure|reactivate)"
    r"\b[^.!?\n,;:]{2,60})",
    re.IGNORECASE,
)
_PURPOSE_STOP = re.compile(r"\s+(?:before|by|within|or|otherwise|immediately|today|now|asap)\b.*$", re.IGNORECASE)
PAYMENT_RE = re.compile(
    r"\b(wire transfer|wire payment|gift cards?|bank (?:details|account details|information)|routing (?:number|details)|"
    r"ach (?:details|information|update)|payment details|processing fee|send (?:the )?payment|pay (?:a|the) fee|"
    r"direct deposit (?:details|information))\b",
    re.IGNORECASE,
)
LINK_MENTION_RE = re.compile(
    r"\b(click (?:here|the link|below|the button)|the link below|following link|use this link|button below|"
    r"sign in here|log in here|visit (?:the|this) (?:link|page))\b",
    re.IGNORECASE,
)
URGENCY_TERMS = (
    "within 24 hours", "within 12 hours", "within 48 hours", "immediately", "urgent", "immediate action",
    "expires today", "right away", "asap", "final notice", "last warning", "act now",
)


def quote_for_term(text: str, term: str, max_len: int = 220) -> Optional[str]:
    """Return the verbatim sentence in `text` containing `term` (case-insensitive)."""
    if not text or not term:
        return None
    match = re.search(re.escape(term), text, re.IGNORECASE)
    if not match:
        return None
    start = match.start()
    while start > 0 and not _SENTENCE_END.match(text[start - 1]):
        start -= 1
    end = match.end()
    while end < len(text) and not _SENTENCE_END.match(text[end]):
        end += 1
    if end < len(text) and text[end] in ".!?":
        end += 1
    quote = text[start:end].strip()
    if len(quote) > max_len:
        # Keep a verbatim window around the match instead of an edited sentence.
        lo = max(match.start() - max_len // 2, 0)
        quote = text[lo:lo + max_len].strip()
    return quote or None


def _normalize(text: str) -> str:
    text = (text or "").lower()
    text = text.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    text = text.replace("–", "-").replace("—", "-").replace(" ", " ")
    return re.sub(r"\s+", " ", text).strip()


def is_grounded(quote: str, text: str) -> bool:
    q = _normalize(quote).strip(" .\"'")
    return bool(q) and q in _normalize(text)


def ground_evidence(items: Iterable[EvidenceItem], text: str) -> List[EvidenceItem]:
    grounded: List[EvidenceItem] = []
    for item in items:
        if item.source in ("llm", "rules"):
            item = item.model_copy(update={"grounded": is_grounded(item.quote, text)})
        grounded.append(item)
    return grounded


def groundedness_share(items: Iterable[EvidenceItem]) -> Optional[float]:
    llm_items = [i for i in items if i.source == "llm"]
    if not llm_items:
        return None
    return round(sum(1 for i in llm_items if i.grounded) / len(llm_items), 3)


def email_text(payload: SanitizedEmailPayload) -> str:
    """Text the evidence must come from: subject plus sanitized body."""
    return f"{payload.headers.subject}\n{payload.body_text}"


def tool_evidence(sender: SenderIntegrityResult, urls: UrlScanToolResult, payload: SanitizedEmailPayload) -> List[EvidenceItem]:
    """Evidence from the deterministic tools: the header or URL that triggered a finding."""
    items: List[EvidenceItem] = []
    hdr = payload.headers
    if sender.is_lookalike_domain and hdr.from_raw:
        items.append(EvidenceItem(quote=hdr.from_raw, tactic="Lookalike sender domain", points=20, source="sender"))
    if sender.display_name_spoofing and hdr.from_raw:
        items.append(EvidenceItem(quote=hdr.from_raw, tactic="Display-name impersonation", points=12, source="sender"))
    if sender.reply_to_mismatch and hdr.reply_to_raw:
        items.append(EvidenceItem(quote=f"Reply-To: {hdr.reply_to_raw}", tactic="Replies go elsewhere", points=12, source="sender"))
    for verdict in urls.url_verdicts:
        if verdict.verdict in ("MALICIOUS", "SUSPICIOUS"):
            items.append(
                EvidenceItem(
                    quote=verdict.url,
                    tactic="Malicious link" if verdict.verdict == "MALICIOUS" else "Suspicious link",
                    points=verdict.risk_Contribution,
                    source="url",
                )
            )
    for mismatch in payload.anchor_mismatches:
        items.append(
            EvidenceItem(
                quote=f"Shows {mismatch.visible_text_domain}, opens {mismatch.actual_href_domain}",
                tactic="Disguised link",
                points=15,
                source="url",
            )
        )
    for name in urls.high_risk_attachments:
        items.append(EvidenceItem(quote=name, tactic="Dangerous attachment", points=25, source="url"))
    return items


def _clean_purpose(raw: str) -> str:
    purpose = _PURPOSE_STOP.sub("", raw.strip())
    purpose = re.sub(r"\s+", " ", purpose).strip(" .,")
    return purpose[:1].lower() + purpose[1:] if purpose else ""


def primary_finding(
    payload: SanitizedEmailPayload,
    sender: SenderIntegrityResult,
    urls: UrlScanToolResult,
    injection_detected: bool,
    low_risk: bool,
    signals: Optional[List[str]] = None,
    pattern_finding: Optional[str] = None,
) -> str:
    """One sentence naming what the email asks the reader to do (rule-based).

    `signals` are the wording tactics that scored points (e.g. "Urgency"), used so a low-risk
    result never claims "nothing matched" when something did.
    """
    text = email_text(payload)
    if low_risk and not urls.high_risk_attachments and not injection_detected:
        # Keyword rules can't tell "please sign in" from "you signed in" (a notification), so a
        # low-risk result must not claim the email is asking for something.
        if sender.verified and sender.sender_domain:
            return f"This looks like a routine notification from {sender.sender_domain}, with no strong warning signs."
        found = list(dict.fromkeys(s.lower() for s in (signals or []) if s))[:3]
        if found:
            return f"We found a few warning signs ({', '.join(found)}), but not enough to call this a scam."
        return "We found no warning signs in this email."
    if urls.high_risk_attachments:
        return (
            f"This email asks you to open '{urls.high_risk_attachments[0]}', a file that can run programs on your computer."
        )
    if injection_detected:
        return "This email hides instructions meant to trick automated scanners into marking it as safe."
    if SIGNIN_RE.search(text) and (pattern_finding is None or "sign in" in pattern_finding or "mailbox" in pattern_finding or "suspend" in pattern_finding):
        purpose = PURPOSE_RE.search(text)
        if purpose:
            cleaned = _clean_purpose(purpose.group(1))
            if cleaned:
                return f"This email asks you to sign in to {cleaned}."
    if pattern_finding:
        return pattern_finding
    if PAYMENT_RE.search(text):
        return "This email asks you to send money, buy gift cards, or change payment details."
    if SIGNIN_RE.search(text):
        purpose = PURPOSE_RE.search(text)
        if purpose:
            cleaned = _clean_purpose(purpose.group(1))
            if cleaned:
                return f"This email asks you to sign in to {cleaned}."
        return "This email asks you to sign in or confirm your account details."
    if payload.anchor_mismatches:
        mm = payload.anchor_mismatches[0]
        return f"A link in this email shows '{mm.visible_text_domain}' but actually opens '{mm.actual_href_domain}'."
    if sender.reply_to_mismatch:
        return f"Replies to this email would go to '{payload.headers.reply_to_domain}', not the sender's domain."
    malicious = [v for v in urls.url_verdicts if v.verdict == "MALICIOUS"]
    if malicious:
        return f"This email links to '{malicious[0].domain}', which looks unsafe."
    if low_risk:
        return "We didn't find requests for passwords, payments, or risky files."
    return "This email comes from a sender we couldn't verify."
