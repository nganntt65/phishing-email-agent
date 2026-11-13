"""Known scam scripts.

The component scores (sender 35, links 30, wording 35, memory 15) are additive, so a scam that relies on
wording alone can never reach the HIGH line (60). These patterns are the scripts that security teams treat
as near-certain scams on sight: buy gift cards, pay a fee to receive money, we changed our bank account,
wire this today and keep it quiet, "are you available?" openers, verify your account at this link,
mailbox is full, parcel could not be delivered. Each hit adds points to the wording component, and, when
the sender or the link cannot be verified, sets a floor of 60 on the final score.

A verified sender (trusted list or a real university domain, passing DMARC) with links to its own
domain never gets a floor: real IT desks do say "reset your password" (see `benign_context`).
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional

from app.domains import is_academic_domain, is_shortener, university_lookalike
from app.evidence import LINK_MENTION_RE, email_text, quote_for_term
from app.schemas import SanitizedEmailPayload, SenderIntegrityResult, SingleUrlScanVerdict, UrlScanToolResult

FLOOR = 60


@dataclass
class PatternHit:
    name: str
    title: str          # shown as the evidence tactic and in the score breakdown
    points: int         # added to the wording component (rule mode)
    floor: int          # minimum final score, 0 when the context doesn't justify one
    finding: str        # one plain sentence for the student: what the email asks
    why: str            # why it matters
    quote: Optional[str] = None
    details: List[str] = field(default_factory=list)


_I = re.IGNORECASE

GIFT_CARD_RE = re.compile(
    r"\b(?:buy|purchase|get|pick up|grab|obtain|send)\b[^.!?\n]{0,60}?\bgift\s?cards?\b|"
    r"\bgift\s?cards?\b[^.!?\n]{0,80}?\b(?:codes?|scratch|photo|pictures?|back of|pin)\b", _I)

FEE_RE = re.compile(
    r"\b(?:processing|activation|handling|clearance|release|administrative|admin|transfer|delivery|customs|"
    r"verification|unlocking|courier)\s+(?:fee|charge|payment)\b|"
    r"\b(?:fee|charge|payment|deposit)\b[^.!?\n]{0,50}?\bto (?:release|unlock|claim|receive|collect|process|activate|deliver)\b", _I)
AWARD_RE = re.compile(
    r"\b(?:selected|awarded?|won|winner|winnings|approved|qualif(?:y|ied)|grant|scholarship|prize|lottery|"
    r"refund|inheritance|compensation|funds|bursary|reward)\b", _I)

BANK_CHANGE_RE = re.compile(
    r"\b(?:changed?|updated?|new|switch(?:ed)?)\b[^.!?\n]{0,40}?\b(?:bank(?:ing)?|account|ach|wire|remittance|"
    r"payment|direct deposit|beneficiary)\b[^.!?\n]{0,30}?\b(?:details|information|info|instructions|number|account)\b|"
    r"\bnew (?:routing|account|iban|swift) (?:number|details)\b|\bremittance account\b|"
    r"\bupdate (?:your|our|the) (?:bank|banking|payment|remittance|direct deposit) (?:details|information|info)\b", _I)

WIRE_RE = re.compile(
    r"\b(?:wire|transfer|send|make|process|initiate|remit)\b[^.!?\n]{0,40}?"
    r"\b(?:payment|transfer|funds|money|\$\s?\d[\d,]*|usd|eur|gbp|nt\$|idr)\b", _I)
SECRECY_RE = re.compile(
    r"\bkeep (?:this|it) (?:between us|confidential|private|quiet)\b|\bconfidential\b|\bbetween us\b|"
    r"\bdo not (?:tell|discuss|mention|call|share)\b|\bdon'?t (?:call|tell|mention)\b", _I)
URGENT_RE = re.compile(
    r"\b(?:urgent|immediately|right away|asap|today|within \d+ hours|time[- ]sensitive|as soon as possible|"
    r"before (?:the )?end of (?:the )?day|by (?:noon|5|eod))\b", _I)

OPENER_RES = {
    "asks if you're available": re.compile(
        r"\bare you (?:available|at your desk|on campus|in (?:the )?office|around|there|free (?:right )?now|busy)\b|"
        r"\bgot a (?:minute|moment|sec)\b|\bdo you have a (?:minute|moment)\b", _I),
    "asks for a favour without saying what": re.compile(
        r"\b(?:need|want|require) (?:a|your|some) (?:quick |small |little |urgent )?(?:favou?r|help|assistance)\b|"
        r"\bhelp (?:me )?with something\b|\bsomething small\b|\bquick (?:task|request|favou?r)\b|\ba task for you\b", _I),
    "wants a fast reply": re.compile(
        r"\breply (?:when you see this|as soon as|asap|back|here|to this (?:email|message)|immediately|quickly)\b|"
        r"\blet me know as soon as\b|\bget back to me\b|\btext me\b|"
        r"\bsend me your (?:cell|mobile|phone|number|whatsapp)\b|\bwhat'?s your (?:cell|mobile|number)\b|"
        r"\b(?:add|contact|message|reach) (?:me|us|our \w+) (?:on|via|through) (?:line|whatsapp|telegram|wechat|signal)\b", _I),
    "says they can't be reached": re.compile(
        r"\b(?:in|stuck in|going into) (?:a |back-to-back )?meetings?\b|\bcan'?t (?:take|receive|make) (?:any )?calls?\b|"
        r"\bboard meeting\b|\bdo not call\b|\bdon'?t call\b|\bunable to (?:talk|call)\b", _I),
}

CREDENTIAL_ASK_RE = re.compile(
    r"\b(?:sign[\s-]?in|log[\s-]?in|log ?on)\b[^.!?\n]{0,60}?\b(?:to|and|now|here|immediately)\b|"
    r"\b(?:verify|confirm|validate|update|re-?enter|reset|unlock|re-?activate|restore|keep|secure|upgrade|renew|re-?confirm)\b"
    r"[^.!?\n]{0,30}?\b(?:your|the) (?:account|password|mailbox|email|e-mail|login|credentials|identity|storage|access|"
    r"student (?:account|email|id)|enrollment|details)\b", _I)
ACCOUNT_THREAT_RE = re.compile(
    r"\b(?:account|mailbox|email|access|messages?|service|password)\b[^.!?\n]{0,40}?\b(?:will be|has been|have been|is|are|being)\b"
    r"[^.!?\n]{0,15}?\b(?:suspended|locked|disabled|deactivated|closed|terminated|limited|restricted|on hold|held|deleted|blocked)\b|"
    r"\bfailure to (?:verify|confirm|act|respond)\b", _I)
QUOTA_RE = re.compile(
    r"\b(?:mailbox|email storage|storage|inbox|quota)\b[^.!?\n]{0,30}?\b(?:full|exceeded|limit|reached)\b|"
    r"\bupgrade (?:your )?(?:storage|mailbox|quota)\b|\bincoming (?:messages|mail|emails) (?:are |is )?(?:on hold|being held|held|blocked)\b|"
    r"\bstop receiving (?:messages|emails|mail)\b", _I)

DELIVERY_RE = re.compile(
    r"\b(?:package|parcel|shipment|delivery|order)\b[^.!?\n]{0,80}?\b(?:could not be delivered|couldn'?t be delivered|"
    r"unable to deliver|failed|unsuccessful|missed|nobody was (?:available|home)|reschedule|redeliver|re-deliver|"
    r"held|on hold|awaiting|customs|unpaid|outstanding|fee)\b|\breschedule (?:your )?delivery\b|\bdelivery attempt failed\b", _I)

PII_REQUEST_RE = re.compile(
    r"\b(?:complete|fill|submit|provide|send|enter|upload|reply with|include|attach)\b[^.!?\n]{0,80}?"
    r"\b(?:student id|passport|social security|ssn|national id|id card|ktp|id number|date of birth|direct deposit|bank account|"
    r"bank ?book|bank statement|routing number|debit card|credit card|card number|cvv|pin code|mother'?s maiden)\b", _I)
BANKING_PII_RE = re.compile(
    r"\b(?:direct deposit|bank account|bank ?book|bank statement|routing number|debit card|credit card|card number|cvv|"
    r"social security|ssn|passport|id card|ktp)\b", _I)


def _quote(text: str, match: Optional[re.Match]) -> Optional[str]:
    return quote_for_term(text, match.group(0)) if match else None


WEAK_URL_MARKERS = ("credential/authentication path", "unencrypted http", "(weak signal)")


def link_is_safe(v: SingleUrlScanVerdict, sender: SenderIntegrityResult) -> bool:
    """A link we would not call a phishing landing page: trusted, the sender's own domain, or a real
    university domain that isn't a lookalike. Pasted text has no sender to align with, so there a link
    only counts against the email when it carries a real signal of its own (lookalike, shortener, IP...)."""
    if v.trusted or v.first_party:
        return True
    if v.domain and is_academic_domain(v.domain) and not university_lookalike(v.domain):
        return True
    if not sender.sender_domain:
        return v.verdict == "CLEAN" or all(any(m in r.lower() for m in WEAK_URL_MARKERS) for r in v.reasons)
    return False


def detect_patterns(
    payload: SanitizedEmailPayload,
    sender: SenderIntegrityResult,
    urls: UrlScanToolResult,
    benign_context: bool = False,
    link_unrecovered: bool = False,
) -> List[PatternHit]:
    """Return the scam scripts this email matches, most serious first."""
    text = email_text(payload)
    hits: List[PatternHit] = []
    unverified = not sender.verified
    unsafe_links = [v for v in urls.url_verdicts if not link_is_safe(v, sender)]
    hidden_links = [v for v in unsafe_links if is_shortener(v.domain) or v.verdict != "CLEAN"]
    # "Click here" with no recoverable link (PDF kept only the printed text) from a sender that is neither a
    # university nor on the trusted list: the lure is there, the landing page just couldn't be read.
    academic_sender = bool(sender.sender_domain) and is_academic_domain(sender.sender_domain) and not sender.is_lookalike_domain
    unseen_link = (not urls.url_verdicts and (link_unrecovered or bool(LINK_MENTION_RE.search(text)))
                   and bool(sender.sender_domain) and not academic_sender and not sender.in_trusted_domains_redis)

    def add(name, title, points, floor_when, finding, why, match, details=None):
        hits.append(PatternHit(name=name, title=title, points=points, floor=FLOOR if (floor_when and not benign_context) else 0,
                               finding=finding, why=why, quote=_quote(text, match), details=details or []))

    m = GIFT_CARD_RE.search(text)
    if m:
        add("gift_card", "Gift-card request", 12, unverified,
            "This email asks you to buy gift cards and send the codes or photos.",
            "No university office or professor asks for gift cards by email. The codes are as good as cash and can't be recovered.", m)

    m = FEE_RE.search(text)
    if m and AWARD_RE.search(text):
        add("advance_fee", "Fee to release money", 12, unverified,
            "This email says you've been awarded money but must pay a fee first.",
            "Real scholarships and refunds never charge a fee to release the money. The fee is the scam.", m)

    m = BANK_CHANGE_RE.search(text)
    if m:
        add("bank_change", "Change of bank details", 10, unverified or sender.reply_to_mismatch,
            "This email asks you to send payments to a new bank account.",
            "'We changed our bank details' is the standard invoice-fraud script. Confirm by phone on a number you already have.", m)

    m = WIRE_RE.search(text)
    if m and (SECRECY_RE.search(text) or URGENT_RE.search(text)):
        add("wire_request", "Urgent or secret money transfer", 12, unverified or sender.display_name_spoofing or sender.reply_to_mismatch,
            "This email asks you to send money quickly, or to keep the request quiet.",
            "Pressure plus secrecy is how payment fraud works: it stops you checking with anyone.", m)

    m = PII_REQUEST_RE.search(text)
    if m:
        banking = bool(BANKING_PII_RE.search(quote_for_term(text, m.group(0)) or m.group(0)))
        add("pii_request", "Asks for ID or banking details", 10 if banking else 6, unverified and banking,
            "This email asks you to hand over personal or banking details through a form or reply.",
            "Scammers collect ID and bank details to open accounts or redirect pay in your name.", m)

    opener = [(label, rx.search(text)) for label, rx in OPENER_RES.items()]
    opener = [(label, mm) for label, mm in opener if mm]
    if opener:
        strong = len(opener) >= 2 and not payload.extracted_urls and unverified
        add("bec_opener", "'Are you available?' opener", 10 if len(opener) >= 2 else 4, strong,
            "This email asks whether you're available and wants a quick reply, without saying what for.",
            "That is how gift-card and payment scams start: a short message to get you talking, then the request. "
            "Check with the person by phone before replying.", opener[0][1], [label for label, _ in opener])

    ask, threat, quota = CREDENTIAL_ASK_RE.search(text), ACCOUNT_THREAT_RE.search(text), QUOTA_RE.search(text)
    if ask or threat or quota:
        points = (10 if ask else 0) + (8 if threat else 0) + (8 if quota else 0)
        lure = bool(unsafe_links) or sender.is_lookalike_domain or unseen_link
        if quota:
            finding = "This email says your mailbox is full and asks you to click a link to fix it."
            why = "Universities never fix mailbox storage through a link in an email. The link leads to a fake login page."
        elif threat:
            finding = "This email threatens to suspend or close your account unless you act through its link."
            why = "The threat is there to make you click before you check. Fake login pages steal the password you type."
        else:
            finding = "This email asks you to sign in or confirm your account through its link."
            why = "The link doesn't go to the university or to the sender's own domain. That is where passwords get stolen."
        add("credential_lure", "Asks you to sign in or verify through a link", points, lure, finding, why, ask or threat or quota)

    m = DELIVERY_RE.search(text)
    if m:
        add("delivery_lure", "Missed-delivery notice", 8, bool(hidden_links) and unverified,
            "This email says a delivery failed and asks you to reschedule through a link that hides where it goes.",
            "Parcel notices from unknown senders with shortened or odd links lead to card-detail and login forms.", m)

    order = {"gift_card": 0, "wire_request": 1, "bank_change": 2, "advance_fee": 3, "pii_request": 4,
             "credential_lure": 5, "delivery_lure": 6, "bec_opener": 7}
    hits.sort(key=lambda h: (-(h.floor > 0), order.get(h.name, 9)))
    return hits


def pattern_floor(hits: List[PatternHit]) -> int:
    return max((h.floor for h in hits), default=0)
