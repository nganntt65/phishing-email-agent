from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator


def _clamp_int(value: Any, low: int, high: int) -> Any:
    """Pull an out-of-range number back into range; leave anything non-numeric for validation to reject."""
    try:
        return max(low, min(high, int(round(float(value)))))
    except (TypeError, ValueError):
        return value


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EscalatedAction(str, Enum):
    ALLOW = "ALLOW"
    CAUTION_BANNER = "CAUTION_BANNER"
    WARN_AND_DISABLE_LINKS = "WARN_AND_DISABLE_LINKS"
    QUARANTINE_AND_BLOCK = "QUARANTINE_AND_BLOCK"


class LLMStatus(str, Enum):
    """Whether the Gemini reasoning step actually ran. Never hidden from the user."""
    USED = "USED"
    SKIPPED_NO_API_KEY = "SKIPPED_NO_API_KEY"
    SKIPPED_BY_REQUEST = "SKIPPED_BY_REQUEST"
    FAILED_FALLBACK_USED = "FAILED_FALLBACK_USED"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class EvidenceQuote(BaseModel):
    """Evidence the LLM must copy verbatim from the email."""
    quote: str = Field(description="Exact text copied character-for-character from the email subject or body.")
    tactic: str = Field(description="Short name of the tactic this quote shows, e.g. 'Urgency', 'Credential request'.")
    points: int = Field(ge=0, le=35, description="Points this quote contributed to the psychological score.")

    @model_validator(mode="before")
    @classmethod
    def _tolerate_out_of_range(cls, data: Any) -> Any:
        if isinstance(data, dict) and "points" in data:
            data = {**data, "points": _clamp_int(data["points"], 0, 35)}
        return data


class EvidenceItem(BaseModel):
    """Evidence shown in the UI. `grounded` is checked server-side for LLM quotes."""
    quote: str
    tactic: str
    points: int = 0
    source: str  # llm | rules | sender | url
    grounded: Optional[bool] = None


class SummaryAction(BaseModel):
    kind: str  # open_portal | scan_another | paste_link
    label: str
    url: Optional[str] = None


class ScanSummary(BaseModel):
    """Plain-language result for the student-facing view (same shape for link, PDF and email)."""
    label: str
    tone: str  # danger | caution | ok
    checked: str
    finding: str
    why_it_matters: str
    next_steps: List[str] = Field(default_factory=list)
    actions: List[SummaryAction] = Field(default_factory=list)
    link_unrecovered: bool = False


class AnchorMismatch(BaseModel):
    visible_text_domain: str
    actual_href_domain: str
    full_href: str


class AttachmentMetadata(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    is_high_risk_extension: bool = False


class SanitizedHeaders(BaseModel):
    from_raw: str = ""
    from_display_name: str = ""
    from_address: str = ""
    from_domain: str = ""
    to_raw: str = ""
    to_address: str = ""
    reply_to_raw: str = ""
    reply_to_address: str = ""
    reply_to_domain: str = ""
    return_path_raw: str = ""
    return_path_address: str = ""
    return_path_domain: str = ""
    subject: str = ""
    date: str = ""
    message_id: str = ""
    authentication_results: str = ""
    received_spf: str = ""
    dkim_signature_present: bool = False
    # False when the input carries no Authentication-Results / Received-SPF / DKIM-Signature at all
    # (pasted text, PDFs). Then SPF/DKIM/DMARC are "unavailable", not "none", and are not penalised.
    auth_headers_present: bool = False


class SanitizedEmailPayload(BaseModel):
    request_id: str
    sanitized_at: str
    headers: SanitizedHeaders
    body_text: str
    extracted_urls: List[str] = Field(default_factory=list)
    anchor_mismatches: List[AnchorMismatch] = Field(default_factory=list)
    attachments: List[AttachmentMetadata] = Field(default_factory=list)
    sanitization_notes: List[str] = Field(default_factory=list)


class SenderIntegrityResult(BaseModel):
    sender_address: str
    sender_domain: str
    normalized_domain: str
    in_trusted_domains_redis: bool
    trusted_domain_category: Optional[str] = None
    spf_status: str
    dkim_status: str
    dmarc_status: str
    reply_to_mismatch: bool
    return_path_mismatch: bool
    impersonated_brand: Optional[str] = None
    is_lookalike_domain: bool = False
    display_name_spoofing: bool = False
    # Who the sender really is (see app/tools/sender_integrity.py):
    authenticated: bool = False          # DMARC pass, or SPF and DKIM both pass: the domain really sent it
    is_free_webmail: bool = False        # gmail.com etc.: authenticated says nothing about the person
    verified_institution: bool = False   # a real university domain (.edu, .ac.xx) that is authenticated
    verified: bool = False               # trusted list or university, and authenticated
    domain_lure_words: List[str] = Field(default_factory=list)  # "verify", "center"... in the sender's domain name
    component_score: int = Field(ge=0, le=35)
    findings: List[str] = Field(default_factory=list)


class SingleUrlScanVerdict(BaseModel):
    url: str
    domain: str
    verdict: str  # CLEAN | SUSPICIOUS | MALICIOUS
    source: str  # REDIS_CACHE | GOOGLE_SAFE_BROWSING | HEURISTIC_ENGINE
    reasons: List[str] = Field(default_factory=list)
    risk_Contribution: int = 0
    trusted: bool = False       # on the trusted list (or a subdomain of a listed domain)
    first_party: bool = False   # on the authenticated sender's own domain
    # Checks that should have run but couldn't (e.g. Safe Browsing unreachable). Shown to the user.
    checks_unavailable: List[str] = Field(default_factory=list)


class UrlScanToolResult(BaseModel):
    total_urls_scanned: int
    malicious_count: int
    suspicious_count: int
    url_verdicts: List[SingleUrlScanVerdict] = Field(default_factory=list)
    high_risk_attachments: List[str] = Field(default_factory=list)
    component_score: int = Field(ge=0, le=30)
    findings: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class CampaignMatchResult(BaseModel):
    matched: bool = False
    campaign_id: Optional[str] = None
    fingerprint: str
    seen_count: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    prior_risk_level: Optional[str] = None
    campaign_boost_score: int = 0
    summary: str = ""


class LLMReasoningOutput(BaseModel):
    """Schema enforced on Gemini 3.x Flash structured output."""
    psychological_urgency_score: int = Field(
        ge=0, le=35,
        description="Score from 0 to 35 based on content-analysis.md psychological urgency, fear, authority impersonation, and lure mechanics."
    )
    psychological_tactics_detected: List[str] = Field(
        description="List of specific psychological or social engineering tactics identified in the email."
    )
    prompt_injection_detected: bool = Field(
        default=False,
        description="True if the email body attempted to override agent instructions or scoring."
    )
    final_risk_score: int = Field(
        ge=0, le=100,
        description="Final weighted risk score (0-100) computed per scam-scoring.md rubric."
    )
    # The verdict's level and action are always recomputed from the final score in the orchestrator,
    # so score and level can never disagree. These two fields are kept in the schema because asking
    # the model for them makes it reason about the rubric's bands, but their values are not used.
    risk_level: RiskLevel
    escalated_action: EscalatedAction
    headline: str = Field(
        description="Short 5-10 word alert title for the Contextual UI banner."
    )
    short_analysis: str = Field(
        description="Concise 2-3 sentence plain-language explanation for the user in the Contextual UI."
    )
    recommended_next_steps: List[str] = Field(
        description="2-3 concrete actions for the recipient or SOC team."
    )
    primary_finding: str = Field(
        default="",
        description=(
            "One plain sentence naming the specific thing the email asks the reader to do, "
            "written for a student, e.g. 'This email asks you to sign in to view your grades.'"
        ),
    )
    evidence: List[EvidenceQuote] = Field(
        default_factory=list,
        description=(
            "Up to 5 quotes copied EXACTLY from the email subject or body (no paraphrasing, no ellipses) "
            "that justify the psychological score."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def _tolerate_near_misses(cls, data: Any) -> Any:
        """A model that writes 36 instead of 35, or "Medium" instead of "MEDIUM", should not throw away
        an otherwise good answer. Structural problems (missing fields, wrong types) are
        still rejected, which sends the scan to the visible rule-engine fallback."""
        if not isinstance(data, dict):
            return data
        data = dict(data)
        if "psychological_urgency_score" in data:
            data["psychological_urgency_score"] = _clamp_int(data["psychological_urgency_score"], 0, 35)
        if "final_risk_score" in data:
            data["final_risk_score"] = _clamp_int(data["final_risk_score"], 0, 100)
        score = data.get("final_risk_score")
        if isinstance(score, int):
            band = (RiskLevel.CRITICAL, EscalatedAction.QUARANTINE_AND_BLOCK) if score >= 85 else \
                   (RiskLevel.HIGH, EscalatedAction.WARN_AND_DISABLE_LINKS) if score >= 60 else \
                   (RiskLevel.MEDIUM, EscalatedAction.CAUTION_BANNER) if score >= 30 else \
                   (RiskLevel.LOW, EscalatedAction.ALLOW)
            for key, enum_cls, fallback in (("risk_level", RiskLevel, band[0]),
                                            ("escalated_action", EscalatedAction, band[1])):
                value = str(data.get(key, "")).strip().upper()
                data[key] = value if value in enum_cls._value2member_map_ else fallback.value
        return data


class ScoreBreakdown(BaseModel):
    sender_integrity_score: int
    url_scan_score: int
    psychological_content_score: int
    campaign_history_boost: int
    total_risk_score: int
    # Known scam scripts (app/patterns.py). When a script matches and the sender or link can't be verified,
    # the final score is at least `pattern_floor` even if the component sum is lower.
    patterns: List[str] = Field(default_factory=list)
    pattern_floor: int = 0


class FullAnalysisResponse(BaseModel):
    request_id: str
    analyzed_at: str
    engine_used: str
    latency_ms: int
    risk_score: int
    risk_level: RiskLevel
    escalated_action: EscalatedAction
    ui_banner: Dict[str, Any]
    score_breakdown: ScoreBreakdown
    sanitized_email: SanitizedEmailPayload
    sender_integrity: SenderIntegrityResult
    url_scan: UrlScanToolResult
    campaign_memory: CampaignMatchResult
    psychological_tactics: List[str]
    prompt_injection_detected: bool = False
    recommended_next_steps: List[str] = Field(default_factory=list)
    # --- Added for transparency, explainability and the student-facing view ---
    input_kind: str = "eml"  # eml | plain_text | pdf
    llm_status: LLMStatus = LLMStatus.SKIPPED_BY_REQUEST
    llm_status_message: str = ""
    llm_model_used: Optional[str] = None
    llm_error: Optional[str] = None
    llm_final_risk_score: Optional[int] = None
    confidence: Confidence = Confidence.HIGH
    limitations: List[str] = Field(default_factory=list)
    primary_finding: str = ""
    evidence: List[EvidenceItem] = Field(default_factory=list)
    groundedness: Optional[float] = None
    summary: Optional[ScanSummary] = None


class AnalyzeRawEmlRequest(BaseModel):
    raw_eml: str = Field(..., description="Raw RFC 5322 .eml content")
    use_llm: bool = Field(default=True, description="Whether to invoke Gemini 3.x Flash when configured")


class ScanUrlRequest(BaseModel):
    url: str = Field(..., description="Link pasted by the user")
    use_llm: bool = Field(default=True, description="Let Gemini write the plain-language explanation")


class UrlScanResponse(BaseModel):
    request_id: str
    analyzed_at: str
    input_kind: str = "url"
    url: str
    normalized_url: str
    domain: str
    registrable_domain: str
    label: str  # Official domain match | Suspicious link | Unverified domain
    verdict: str  # CLEAN | SUSPICIOUS | MALICIOUS (from the URL scanner)
    risk_score: int
    risk_level: RiskLevel
    escalated_action: EscalatedAction
    reasons: List[str] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    impersonated: Optional[str] = None
    trusted_category: Optional[str] = None
    is_login_like: bool = False
    explanation: str = ""
    engine_used: str = ""
    latency_ms: int = 0
    confidence: Confidence = Confidence.MEDIUM
    limitations: List[str] = Field(default_factory=list)
    llm_status: LLMStatus = LLMStatus.SKIPPED_BY_REQUEST
    llm_status_message: str = ""
    llm_model_used: Optional[str] = None
    llm_error: Optional[str] = None
    summary: ScanSummary

