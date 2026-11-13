import asyncio
from datetime import datetime, timezone
import json
import re
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional

from app import llm
from app.evidence import (
    LINK_MENTION_RE,
    PAYMENT_RE,
    SIGNIN_RE,
    email_text,
    ground_evidence,
    groundedness_share,
    primary_finding,
    quote_for_term,
    tool_evidence,
)
from app.framework_loader import framework_loader
from app.memory import campaign_memory
from app.patterns import PatternHit, detect_patterns, pattern_floor
from app.pdf_parser import parse_pdf, to_payload
from app.sanitizer import preprocess_and_sanitize_eml
from app.schemas import (
    CampaignMatchResult,
    Confidence,
    EscalatedAction,
    EvidenceItem,
    EvidenceQuote,
    FullAnalysisResponse,
    LLMReasoningOutput,
    LLMStatus,
    RiskLevel,
    SanitizedEmailPayload,
    ScoreBreakdown,
    SenderIntegrityResult,
    UrlScanToolResult,
)
from app.summary import build_email_summary
from app.tools.sender_integrity import check_sender_receiver_integrity
from app.tools.url_scanner import scan_email_urls_and_attachments

StepCallback = Optional[Callable[[Dict[str, Any]], Awaitable[None]]]
LLMUnavailableError = llm.LLMUnavailableError

PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"system\s+override",
    r"mark\s+this\s+email\s+as\s+(safe|benign|allow)",
    r"risk_score\s*[:=]\s*0",
    r"disregard\s+the\s+scoring\s+rubric",
]

URGENCY_FALLBACK_TERMS = [
    "within 24 hours", "within 12 hours", "within 48 hours", "immediately", "urgent", "immediate action",
    "expires today", "right away", "asap", "board meeting", "do not call", "final notice", "last warning",
    "act now", "time sensitive", "time-sensitive",
]
FEAR_TERMS = [
    "suspended", "permanently closed", "terminated", "unauthorized", "locked", "legal action", "penalty",
    "wire transfer", "overdue invoice", "deactivated", "disabled", "on hold", "being held", "will be closed",
    "lose access", "stop receiving", "restricted",
]
BEC_TERMS = ("ceo", "chief executive", "wire payment", "gift card", "payroll")

PLAIN_TEXT_LIMITATION = "This was pasted as plain text without email headers, so we couldn't check who sent it."
NO_AUTH_LIMITATION = "No authentication headers (SPF/DKIM/DMARC) were included, so we couldn't confirm who really sent it."
NO_SENDER_LIMITATION = "No sender address was found."
LINK_UNRECOVERED_TEXT = "The text mentions a link, but the link itself wasn't included, so we couldn't check where it goes."
NO_LLM_LIMITATION = "AI reasoning wasn't used, so the wording of the message was checked with keyword rules only."


def _map_score_to_level_and_action(score: int) -> tuple[RiskLevel, EscalatedAction, str]:
    if score >= 85:
        return RiskLevel.CRITICAL, EscalatedAction.QUARANTINE_AND_BLOCK, "red"
    if score >= 60:
        return RiskLevel.HIGH, EscalatedAction.WARN_AND_DISABLE_LINKS, "orange"
    if score >= 30:
        return RiskLevel.MEDIUM, EscalatedAction.CAUTION_BANNER, "amber"
    return RiskLevel.LOW, EscalatedAction.ALLOW, "green"


def _apply_overrides(score: int, injection_detected: bool, url_res: UrlScanToolResult, floor: int = 0) -> int:
    """scam-scoring.md sections E and F: minimum scores applied after the component sum."""
    score = max(score, floor)  # known scam script with an unverified sender or link
    if injection_detected:
        score = max(score, 88)
    if url_res.high_risk_attachments:
        score = max(score, 85)
    return min(score, 100)


def _benign_context(sender_res: SenderIntegrityResult, url_res: UrlScanToolResult) -> bool:
    """content-analysis.md: a verified sender (trusted list or a real university, authenticated) whose links are
    all trusted or first-party. Routine mail from such a sender may say 'urgent' or 'reset your password'."""
    return (
        sender_res.verified
        and not sender_res.reply_to_mismatch
        and url_res.malicious_count == 0
        and url_res.suspicious_count == 0
        and all(v.trusted or v.first_party for v in url_res.url_verdicts)
        and not url_res.high_risk_attachments
    )


def _confidence(limitations: List[str]) -> Confidence:
    if not limitations:
        return Confidence.HIGH
    return Confidence.MEDIUM if len(limitations) == 1 else Confidence.LOW


def _evaluate_content_playbook_fallback(
    email_payload: SanitizedEmailPayload,
    sender_res: SenderIntegrityResult,
    url_res: UrlScanToolResult,
    campaign_res: CampaignMatchResult,
    hits: Optional[List[PatternHit]] = None,
) -> tuple[LLMReasoningOutput, str]:
    """
    Deterministic execution of `content-analysis.md` and `scam-scoring.md`
    used when GEMINI_API_KEY is not configured or when offline fallback is requested.
    Every point awarded comes with a verbatim quote from the email (evidence).
    """
    original_text = email_text(email_payload)
    subject_and_body = original_text.lower()
    tactics: List[str] = []
    evidence: List[EvidenceQuote] = []
    psych_score = 0

    def _add_quote(term: str, tactic: str, pts: int) -> None:
        quote = quote_for_term(original_text, term)
        if quote and all(q.quote != quote for q in evidence):
            evidence.append(EvidenceQuote(quote=quote, tactic=tactic, points=pts))

    # 1. Urgency & Artificial Time Pressure (0-12 pts)
    matched_urgency = [t for t in URGENCY_FALLBACK_TERMS if t in subject_and_body]
    if matched_urgency:
        pts = 11 if len(matched_urgency) >= 2 else 7
        psych_score += pts
        tactics.append(
            f"Psychological Urgency (+{pts} pts): Uses artificial time pressure ({', '.join(matched_urgency[:3])})."
        )
        for term in matched_urgency[:2]:
            _add_quote(term, "Urgency", pts)

    # 2. Fear, Coercion & Negative Consequences (0-10 pts)
    matched_fear = [t for t in FEAR_TERMS if t in subject_and_body]
    if matched_fear:
        pts = 9 if len(matched_fear) >= 2 else 6
        psych_score += pts
        tactics.append(
            f"Fear & Coercion (+{pts} pts): Threatens negative consequences ({', '.join(matched_fear[:3])})."
        )
        for term in matched_fear[:2]:
            _add_quote(term, "Fear / threat", pts)

    # 3. Authority & Brand Impersonation / BEC Cues (0-8 pts)
    if sender_res.impersonated_brand or sender_res.display_name_spoofing:
        psych_score += 8
        tactics.append(
            f"Authority / Brand Impersonation (+8 pts): Impersonates '{sender_res.impersonated_brand}'."
        )
    elif any(k in subject_and_body for k in BEC_TERMS):
        psych_score += 6
        tactics.append("Authority / BEC Lure (+6 pts): Requests sensitive financial/executive action.")
        for term in BEC_TERMS:
            if term in subject_and_body:
                _add_quote(term, "Authority / payment request", 6)
                break

    # 4. Lure Mechanics & Prompt Injection Evasion (0-5 pts)
    injection_match = None
    for pat in PROMPT_INJECTION_PATTERNS:
        injection_match = re.search(pat, original_text, re.IGNORECASE)
        if injection_match:
            break
    injection_detected = injection_match is not None
    if injection_detected:
        psych_score += 5
        tactics.append(
            "Adversarial Evasion (+5 pts): Detected indirect prompt injection attempting to manipulate the AI verdict."
        )
        _add_quote(injection_match.group(0), "Prompt injection", 5)
    elif email_payload.anchor_mismatches or "dear customer" in subject_and_body or "valued user" in subject_and_body:
        psych_score += 4
        tactics.append("Deceptive Lure Mechanics (+4 pts): Uses generic greeting and/or mismatched link anchor text.")
        for term in ("dear customer", "valued user", "dear valued customer"):
            if term in subject_and_body:
                _add_quote(term, "Generic greeting", 4)
                break

    # 5. Sensitive requests (content-analysis.md section 5)
    payment_match = PAYMENT_RE.search(original_text)
    signin_match = SIGNIN_RE.search(original_text)
    if payment_match:
        psych_score += 8
        tactics.append("Money Request (+8 pts): Asks the reader to move money, buy gift cards, or change payment details.")
        _add_quote(payment_match.group(0), "Money request", 8)
    elif signin_match:
        psych_score += 4
        tactics.append("Credential Request (+4 pts): Asks the reader to sign in or verify account details.")
        _add_quote(signin_match.group(0), "Credential request", 4)

    # 6. Known scam scripts (patterns.py): gift cards, fee to release money, new bank details, ...
    hits = hits or []
    for hit in hits:
        psych_score += hit.points
        detail = f" ({'; '.join(hit.details)})" if hit.details else ""
        tactics.append(f"{hit.title} (+{hit.points} pts){detail}: {hit.finding}")
        if hit.quote and all(q.quote != hit.quote for q in evidence):
            evidence.append(EvidenceQuote(quote=hit.quote, tactic=hit.title, points=hit.points))

    # Benign Context Adjustment per content-analysis.md
    if _benign_context(sender_res, url_res) and not injection_detected:
        psych_score = min(psych_score, 4)
        tactics = [
            "Benign Context Cap Applied (content-analysis.md): verified sender (trusted list or real university, authenticated) and first-party links."
        ]
        evidence = [
            EvidenceQuote(quote=e.quote, tactic=f"{e.tactic} (not counted: verified sender)", points=0) for e in evidence
        ]

    psych_score = min(35, psych_score)

    total_score = min(
        100,
        sender_res.component_score
        + url_res.component_score
        + psych_score
        + campaign_res.campaign_boost_score,
    )
    total_score = _apply_overrides(total_score, injection_detected, url_res, pattern_floor(hits))

    risk_level, escalated_action, _ = _map_score_to_level_and_action(total_score)

    # Craft human-readable headline & short analysis
    if risk_level == RiskLevel.CRITICAL:
        headline = "Critical Phishing Threat — Quarantined & Links Blocked"
        reasons_summary = []
        if sender_res.is_lookalike_domain:
            reasons_summary.append(
                f"spoofs {sender_res.impersonated_brand} using lookalike domain '{sender_res.sender_domain}'"
            )
        elif sender_res.dmarc_status not in ("pass", "unavailable"):
            reasons_summary.append(f"fails cryptographic authentication (DMARC={sender_res.dmarc_status})")
        if url_res.malicious_count > 0 or url_res.high_risk_attachments:
            reasons_summary.append("contains malicious credential-harvesting links or executable attachments")
        if injection_detected:
            reasons_summary.append("embeds adversarial prompt-injection instructions")
        joined = ", ".join(reasons_summary) or "exhibits severe social-engineering indicators"
        short_analysis = (
            f"This email {joined}. It combines technical spoofing with high psychological urgency to pressure "
            f"immediate action. Do not click any links, open attachments, or reply."
        )
        next_steps = [
            "Quarantine email immediately and block sender domain at the gateway.",
            "Do not click any links or enter credentials.",
            "Alert SOC if any user interacted with the embedded URLs.",
        ]
    elif risk_level == RiskLevel.HIGH:
        headline = "High Risk Social Engineering / BEC Detected — Links Disabled"
        short_analysis = (
            f"This message comes from an unverified sender ('{sender_res.sender_domain or 'unknown'}') with suspicious reply routing "
            f"or urgency cues typical of Business Email Compromise (BEC). All links have been disabled; verify any "
            f"requests out-of-band via a known phone number."
        )
        next_steps = [
            "Verify the request with the purported sender via an independent voice/Slack channel.",
            "Do not reply to the Reply-To address or authorize any financial transfer.",
        ]
    elif risk_level == RiskLevel.MEDIUM:
        headline = "Caution: Unverified External Sender with Urgent Language"
        short_analysis = (
            f"Sender '{sender_res.sender_domain or 'unknown'}' is not in the Trusted Domains Redis DB and uses urgency cues. "
            f"Proceed with caution and verify before sharing sensitive data."
        )
        next_steps = [
            "Confirm sender identity before clicking links or replying.",
        ]
    else:
        if sender_res.in_trusted_domains_redis and sender_res.dmarc_status == "pass":
            headline = "Verified Sender & Authentic Cryptographic Signatures"
            short_analysis = (
                f"This email originates from a verified domain ('{sender_res.sender_domain}') in the Trusted Domains "
                f"Redis DB, passes SPF, DKIM, and DMARC checks, and links exclusively to clean canonical URLs."
            )
        else:
            headline = "No Significant Phishing Indicators Found"
            short_analysis = (
                "The rule engine found no strong phishing signals in this message. "
                "Some checks could not run on this input; see the limitations listed with the result."
            )
        next_steps = [
            "No action required — email passed sender integrity and URL threat scans.",
        ]

    finding = primary_finding(email_payload, sender_res, url_res, injection_detected, risk_level == RiskLevel.LOW,
                              signals=[e.tactic for e in evidence if e.points > 0],
                              pattern_finding=hits[0].finding if hits and risk_level != RiskLevel.LOW else None)
    return (
        LLMReasoningOutput(
            psychological_urgency_score=psych_score,
            psychological_tactics_detected=tactics or ["No manipulative psychological tactics detected."],
            prompt_injection_detected=injection_detected,
            final_risk_score=total_score,
            risk_level=risk_level,
            escalated_action=escalated_action,
            headline=headline,
            short_analysis=short_analysis,
            recommended_next_steps=next_steps,
            primary_finding=finding,
            evidence=evidence[:5],
        ),
        "Rubric Engine (Skill .md Deterministic Mode — Set GEMINI_API_KEY for live Gemini 3.x Flash)",
    )


class PhishingAgentOrchestrator:
    """
    AGENT ORCHESTRATOR:
    Manages the agent loop, assembles the Base System Prompt + Skill Playbooks (.md),
    routes execution to Tools (Sender Integrity + Redis, URL Scan APIs) and Campaign Memory,
    invokes Gemini 3.x Flash for structured reasoning, and streams status updates.
    Whether Gemini actually ran is always reported (llm_status); fallbacks are never silent.
    """

    @property
    def model_name(self) -> str:
        return llm.primary_model()

    async def _emit(self, callback: StepCallback, stage: str, message: str, data: Optional[dict] = None) -> None:
        if callback is not None:
            await callback(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "stage": stage,
                    "message": message,
                    "data": data or {},
                }
            )

    def _build_user_prompt(
        self,
        email_payload: SanitizedEmailPayload,
        sender_res: SenderIntegrityResult,
        url_res: UrlScanToolResult,
        campaign_res: CampaignMatchResult,
        input_kind: str = "eml",
        limitations: Optional[List[str]] = None,
        hits: Optional[List[PatternHit]] = None,
    ) -> str:
        return (
            "Evaluate the following sanitized email and deterministic tool outputs according to "
            "`content-analysis.md` and `scam-scoring.md`.\n\n"
            "=== INPUT CONTEXT ===\n"
            f"Input type: {input_kind}\n"
            f"Known limitations: {json.dumps(limitations or [])}\n"
            "SPF/DKIM/DMARC status 'unavailable' means the headers were not present in this input "
            "(e.g. a PDF or pasted text); do not treat that alone as evidence of phishing.\n\n"
            "=== TOOL OUTPUT 1: SENDER / RECEIVER INTEGRITY CHECK (+ TRUSTED DOMAINS REDIS DB) ===\n"
            f"{json.dumps(sender_res.model_dump(), indent=2)}\n\n"
            "=== TOOL OUTPUT 2: URL SCAN APIs & ATTACHMENT CHECK ===\n"
            f"{json.dumps(url_res.model_dump(), indent=2)}\n\n"
            "=== TOOL OUTPUT 3: CAMPAIGN MEMORY / HISTORICAL OUTPUTS ===\n"
            f"{json.dumps(campaign_res.model_dump(), indent=2)}\n\n"
            "=== TOOL OUTPUT 4: KNOWN SCAM SCRIPTS MATCHED BY THE RULE ENGINE (scam-scoring.md section F) ===\n"
            f"{json.dumps([{'script': h.title, 'points': h.points, 'minimum_final_score': h.floor, 'quote': h.quote} for h in (hits or [])], indent=2)}\n\n"
            "=== PREPROCESSED & SANITIZED EMAIL (UNTRUSTED DATA) ===\n"
            "<untrusted_email_data>\n"
            f"From: {email_payload.headers.from_raw}\n"
            f"Reply-To: {email_payload.headers.reply_to_raw}\n"
            f"Return-Path: {email_payload.headers.return_path_raw}\n"
            f"Subject: {email_payload.headers.subject}\n"
            f"Sanitization Notes: {json.dumps(email_payload.sanitization_notes)}\n"
            f"Body:\n{email_payload.body_text}\n"
            "</untrusted_email_data>\n\n"
            "Output requirements: `evidence` quotes must be copied character-for-character from the Subject or "
            "Body above (they are verified automatically; invented quotes are flagged). `primary_finding` is one "
            "plain sentence for a student naming what the email asks them to do."
        )

    async def analyze_raw_eml(
        self,
        raw_eml: str,
        use_llm: bool = True,
        step_callback: StepCallback = None,
        strict_llm: bool = False,
        record_memory: bool = True,
    ) -> FullAnalysisResponse:
        start_time = time.perf_counter()

        # Step 1: Preprocess & Sanitize .eml
        await self._emit(
            step_callback,
            "INPUT_SANITIZATION",
            "Preprocessing & sanitizing raw .eml headers, HTML body, URLs, and attachments...",
        )
        sanitized = preprocess_and_sanitize_eml(raw_eml)
        await self._emit(
            step_callback,
            "INPUT_SANITIZED",
            f"Sanitized email '{sanitized.headers.subject}' from '{sanitized.headers.from_address}' ({len(sanitized.extracted_urls)} URLs extracted).",
            {
                "request_id": sanitized.request_id,
                "from": sanitized.headers.from_address,
                "subject": sanitized.headers.subject,
                "urls_count": len(sanitized.extracted_urls),
            },
        )

        hdr = sanitized.headers
        input_kind = "eml" if (hdr.from_address or hdr.auth_headers_present) else "plain_text"
        limitations: List[str] = []
        link_unrecovered = False
        if input_kind == "plain_text":
            limitations.append(PLAIN_TEXT_LIMITATION)
            if not sanitized.extracted_urls and LINK_MENTION_RE.search(sanitized.body_text):
                limitations.append(LINK_UNRECOVERED_TEXT)
                link_unrecovered = True

        return await self._analyze_sanitized(
            sanitized,
            input_kind=input_kind,
            limitations=limitations,
            link_unrecovered=link_unrecovered,
            use_llm=use_llm,
            step_callback=step_callback,
            strict_llm=strict_llm,
            record_memory=record_memory,
            start_time=start_time,
        )

    async def analyze_pdf_bytes(
        self,
        data: bytes,
        use_llm: bool = True,
        step_callback: StepCallback = None,
        strict_llm: bool = False,
        record_memory: bool = True,
    ) -> FullAnalysisResponse:
        """Analyse an email saved with Print -> Save as PDF. Raises UnreadablePdfError."""
        start_time = time.perf_counter()
        await self._emit(step_callback, "INPUT_SANITIZATION", "Reading the PDF: text, printed headers, and link targets...")
        parsed = await asyncio.to_thread(parse_pdf, data)
        sanitized = to_payload(parsed)
        await self._emit(
            step_callback,
            "INPUT_SANITIZED",
            f"Read {parsed.page_count} page(s); recovered {len(parsed.links)} clickable link(s).",
            {"request_id": sanitized.request_id, "from": sanitized.headers.from_address, "subject": sanitized.headers.subject},
        )
        return await self._analyze_sanitized(
            sanitized,
            input_kind="pdf",
            limitations=list(parsed.limitations),
            link_unrecovered=parsed.link_unrecovered,
            use_llm=use_llm,
            step_callback=step_callback,
            strict_llm=strict_llm,
            record_memory=record_memory,
            start_time=start_time,
        )

    async def _analyze_sanitized(
        self,
        sanitized: SanitizedEmailPayload,
        *,
        input_kind: str,
        limitations: List[str],
        link_unrecovered: bool,
        use_llm: bool,
        step_callback: StepCallback,
        strict_llm: bool,
        record_memory: bool,
        start_time: float,
    ) -> FullAnalysisResponse:
        hdr = sanitized.headers
        if not hdr.auth_headers_present and input_kind == "eml":
            limitations.append(NO_AUTH_LIMITATION)
        if not hdr.from_address and input_kind != "plain_text":
            limitations.append(NO_SENDER_LIMITATION)

        # Step 2: Load Agent Framework (Base System Prompt + Skill Playbooks .md)
        await self._emit(
            step_callback,
            "AGENT_FRAMEWORK",
            "Loading Base System Prompt, content-analysis.md, and scam-scoring.md...",
        )
        system_instruction = framework_loader.assemble_system_instruction()

        # Step 3: Route Tools in Parallel (Sender Integrity + Redis DB, URL Scan APIs, Campaign Memory)
        await self._emit(
            step_callback,
            "TOOLS_EXECUTION",
            "Executing Sender/Receiver Integrity check (SPF/DKIM/DMARC + Trusted Domains Redis) & URL Scan APIs...",
        )
        # The sender check runs first so the URL scan can tell first-party links (the authenticated sender's own domain).
        sender_res = await check_sender_receiver_integrity(sanitized)
        url_res = await scan_email_urls_and_attachments(sanitized, links_verifiable=not link_unrecovered, sender=sender_res)
        limitations.extend(url_res.limitations)
        await self._emit(
            step_callback,
            "TOOLS_COMPLETED",
            f"Sender Integrity Score: {sender_res.component_score}/35 | URL Scan Score: {url_res.component_score}/30",
            {
                "sender_integrity_score": sender_res.component_score,
                "url_scan_score": url_res.component_score,
                "in_trusted_redis": sender_res.in_trusted_domains_redis,
            },
        )

        # Step 4: Query Campaign History / Memory
        await self._emit(
            step_callback,
            "MEMORY_LOOKUP",
            "Querying Campaign History DB for matching phishing fingerprints...",
        )
        campaign_res = campaign_memory.lookup_campaign(sanitized)
        await self._emit(
            step_callback,
            "MEMORY_COMPLETED",
            campaign_res.summary,
            {"matched": campaign_res.matched, "campaign_id": campaign_res.campaign_id},
        )

        # Step 4b: Known scam scripts (rule engine, runs in both modes; Gemini can raise the score, never lower it)
        hits = detect_patterns(sanitized, sender_res, url_res, benign_context=_benign_context(sender_res, url_res),
                               link_unrecovered=link_unrecovered)
        floor = pattern_floor(hits)
        if hits:
            await self._emit(
                step_callback,
                "PATTERNS_MATCHED",
                f"Known scam script(s): {', '.join(h.title for h in hits)}"
                + (f". Final score will be at least {floor}." if floor else " (sender or link verified: no minimum score)."),
                {"patterns": [h.name for h in hits], "floor": floor},
            )

        # Step 5: Assemble Prompt & Invoke LLM / Reasoning Engine (Gemini 3.x Flash)
        await self._emit(
            step_callback,
            "LLM_REASONING",
            "Assembling Prompt + Skill .md + Tool outputs and invoking Reasoning Engine...",
        )
        user_prompt = self._build_user_prompt(
            sanitized, sender_res, url_res, campaign_res, input_kind=input_kind, limitations=limitations, hits=hits
        )
        llm_result = await asyncio.to_thread(
            llm.generate,
            system_instruction=system_instruction,
            prompt=user_prompt,
            response_schema=LLMReasoningOutput,
            use_llm=use_llm,
        )
        status_message = llm.status_message(llm_result.status, llm_result.error)

        if llm_result.used:
            llm_output: LLMReasoningOutput = llm_result.data
            engine_used = f"Gemini Reasoning Engine ({llm_result.model})"
            evidence_source = "llm"
            if not llm_output.primary_finding.strip():
                llm_output.primary_finding = primary_finding(
                    sanitized, sender_res, url_res, llm_output.prompt_injection_detected,
                    llm_output.risk_level == RiskLevel.LOW,
                    signals=[e.tactic for e in llm_output.evidence if e.points > 0]
                    or [re.split(r"[:(\-–—]", t, maxsplit=1)[0].strip() for t in llm_output.psychological_tactics_detected
                        if llm_output.psychological_urgency_score > 0],
                )
        else:
            if strict_llm:
                raise LLMUnavailableError(llm_result.status, status_message)
            llm_output, engine_used = _evaluate_content_playbook_fallback(sanitized, sender_res, url_res, campaign_res, hits)
            evidence_source = "rules"
            limitations.append(NO_LLM_LIMITATION)
            await self._emit(
                step_callback,
                "LLM_FALLBACK",
                f"{status_message} The verdict was produced by the rule engine.",
                {"llm_status": llm_result.status.value, "llm_error": llm_result.error},
            )

        # Ensure final score and action remain aligned with scam-scoring.md rubric
        computed_total = min(
            100,
            sender_res.component_score
            + url_res.component_score
            + llm_output.psychological_urgency_score
            + campaign_res.campaign_boost_score,
        )
        computed_total = _apply_overrides(computed_total, llm_output.prompt_injection_detected, url_res, floor)

        # The LLM can raise the score but never lower it below the computed rubric total.
        final_score = max(computed_total, llm_output.final_risk_score)
        risk_level, escalated_action, banner_color = _map_score_to_level_and_action(final_score)

        evidence_items = [
            EvidenceItem(quote=e.quote, tactic=e.tactic, points=e.points, source=evidence_source)
            for e in llm_output.evidence
        ] + tool_evidence(sender_res, url_res, sanitized)
        evidence_items = ground_evidence(evidence_items, email_text(sanitized))

        summary = build_email_summary(
            level=risk_level,
            finding=llm_output.primary_finding,
            payload=sanitized,
            sender=sender_res,
            urls=url_res,
            injection=llm_output.prompt_injection_detected,
            link_unrecovered=link_unrecovered,
            pattern_why=hits[0].why if hits else None,
            # The LLM may score tactics without quoting them, so the score counts too.
            has_signals=llm_output.psychological_urgency_score > 0 or any(e.points > 0 for e in llm_output.evidence),
        )

        latency_ms = int((time.perf_counter() - start_time) * 1000)

        breakdown = ScoreBreakdown(
            sender_integrity_score=sender_res.component_score,
            url_scan_score=url_res.component_score,
            psychological_content_score=llm_output.psychological_urgency_score,
            campaign_history_boost=campaign_res.campaign_boost_score,
            total_risk_score=final_score,
            patterns=[h.title for h in hits],
            pattern_floor=floor,
        )

        limitations = list(dict.fromkeys(limitations))
        response_obj = FullAnalysisResponse(
            request_id=sanitized.request_id,
            analyzed_at=datetime.now(timezone.utc).isoformat(),
            engine_used=engine_used,
            latency_ms=latency_ms,
            risk_score=final_score,
            risk_level=risk_level,
            escalated_action=escalated_action,
            ui_banner={
                "color": banner_color,
                "headline": llm_output.headline,
                "short_analysis": llm_output.short_analysis,
                "escalated_action": escalated_action.value,
                "risk_level": risk_level.value,
                "risk_score": final_score,
            },
            score_breakdown=breakdown,
            sanitized_email=sanitized,
            sender_integrity=sender_res,
            url_scan=url_res,
            campaign_memory=campaign_res,
            psychological_tactics=llm_output.psychological_tactics_detected,
            prompt_injection_detected=llm_output.prompt_injection_detected,
            recommended_next_steps=llm_output.recommended_next_steps,
            input_kind=input_kind,
            llm_status=llm_result.status,
            llm_status_message=status_message,
            llm_model_used=llm_result.model,
            llm_error=llm_result.error,
            llm_final_risk_score=llm_output.final_risk_score if llm_result.used else None,
            confidence=_confidence(limitations),
            limitations=limitations,
            primary_finding=llm_output.primary_finding,
            evidence=evidence_items,
            groundedness=groundedness_share(evidence_items),
            summary=summary,
        )

        # Step 6: Persist to Campaign History / Historical Outputs DB
        if record_memory:
            campaign_id = campaign_memory.record_analysis_output(
                payload=sanitized,
                fingerprint=campaign_res.fingerprint,
                risk_score=final_score,
                risk_level=risk_level.value,
                escalated_action=escalated_action.value,
                metadata={
                    "input_kind": input_kind,
                    "engine_used": engine_used,
                    "llm_status": llm_result.status.value,
                    "score_breakdown": breakdown.model_dump(),
                },
            )
            if campaign_id:
                response_obj.campaign_memory.campaign_id = campaign_id

        await self._emit(
            step_callback,
            "COMPLETED",
            f"Verdict: {escalated_action.value} (Score: {final_score}/100 in {latency_ms}ms)",
            response_obj.model_dump(mode="json"),
        )

        return response_obj


orchestrator = PhishingAgentOrchestrator()
