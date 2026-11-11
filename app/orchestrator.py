import asyncio
from datetime import datetime, timezone
import json
import os
import re
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional

try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None  # type: ignore
    types = None  # type: ignore

from app.framework_loader import framework_loader
from app.memory import campaign_memory
from app.sanitizer import preprocess_and_sanitize_eml
from app.schemas import (
    CampaignMatchResult,
    EscalatedAction,
    FullAnalysisResponse,
    LLMReasoningOutput,
    RiskLevel,
    SanitizedEmailPayload,
    ScoreBreakdown,
    SenderIntegrityResult,
    UrlScanToolResult,
)
from app.tools.sender_integrity import check_sender_receiver_integrity
from app.tools.url_scanner import scan_email_urls_and_attachments

StepCallback = Optional[Callable[[Dict[str, Any]], Awaitable[None]]]

PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"system\s+override",
    r"mark\s+this\s+email\s+as\s+(safe|benign|allow)",
    r"risk_score\s*[:=]\s*0",
    r"disregard\s+the\s+scoring\s+rubric",
]


def _map_score_to_level_and_action(score: int) -> tuple[RiskLevel, EscalatedAction, str]:
    if score >= 85:
        return RiskLevel.CRITICAL, EscalatedAction.QUARANTINE_AND_BLOCK, "red"
    if score >= 60:
        return RiskLevel.HIGH, EscalatedAction.WARN_AND_DISABLE_LINKS, "orange"
    if score >= 30:
        return RiskLevel.MEDIUM, EscalatedAction.CAUTION_BANNER, "amber"
    return RiskLevel.LOW, EscalatedAction.ALLOW, "green"


def _evaluate_content_playbook_fallback(
    email_payload: SanitizedEmailPayload,
    sender_res: SenderIntegrityResult,
    url_res: UrlScanToolResult,
    campaign_res: CampaignMatchResult,
) -> tuple[LLMReasoningOutput, str]:
    """
    Deterministic execution of `content-analysis.md` and `scam-scoring.md`
    used when GEMINI_API_KEY is not configured or when offline fallback is requested.
    """
    subject_and_body = f"{email_payload.headers.subject}\n{email_payload.body_text}".lower()
    tactics: List[str] = []
    psych_score = 0

    # 1. Urgency & Artificial Time Pressure (0-12 pts)
    urgency_terms = [
        "within 24 hours", "within 12 hours", "immediately", "urgent",
        "immediate action", "expires today", "right away", "asap", "board meeting", "do not call"
    ]
    matched_urgency = [t for t in urgency_terms if t in subject_and_body]
    if matched_urgency:
        pts = 11 if len(matched_urgency) >= 2 else 7
        psych_score += pts
        tactics.append(
            f"Psychological Urgency (+{pts} pts): Uses artificial time pressure ({', '.join(matched_urgency[:3])})."
        )

    # 2. Fear, Coercion & Negative Consequences (0-10 pts)
    fear_terms = [
        "suspended", "permanently closed", "terminated", "unauthorized",
        "locked", "legal action", "penalty", "wire transfer", "overdue invoice"
    ]
    matched_fear = [t for t in fear_terms if t in subject_and_body]
    if matched_fear:
        pts = 9 if len(matched_fear) >= 2 else 6
        psych_score += pts
        tactics.append(
            f"Fear & Coercion (+{pts} pts): Threatens negative consequences ({', '.join(matched_fear[:3])})."
        )

    # 3. Authority & Brand Impersonation / BEC Cues (0-8 pts)
    if sender_res.impersonated_brand or sender_res.display_name_spoofing:
        psych_score += 8
        tactics.append(
            f"Authority / Brand Impersonation (+8 pts): Impersonates '{sender_res.impersonated_brand}'."
        )
    elif any(k in subject_and_body for k in ("ceo", "chief executive", "wire payment", "gift card", "payroll")):
        psych_score += 6
        tactics.append("Authority / BEC Lure (+6 pts): Requests sensitive financial/executive action.")

    # 4. Lure Mechanics & Prompt Injection Evasion (0-5 pts)
    injection_detected = any(re.search(pat, subject_and_body) for pat in PROMPT_INJECTION_PATTERNS)
    if injection_detected:
        psych_score += 5
        tactics.append(
            "Adversarial Evasion (+5 pts): Detected indirect prompt injection attempting to manipulate the AI verdict."
        )
    elif email_payload.anchor_mismatches or "dear customer" in subject_and_body or "valued user" in subject_and_body:
        psych_score += 4
        tactics.append("Deceptive Lure Mechanics (+4 pts): Uses generic greeting and/or mismatched link anchor text.")

    # Benign Context Adjustment per content-analysis.md
    if (
        sender_res.in_trusted_domains_redis
        and sender_res.spf_status == "pass"
        and sender_res.dkim_status == "pass"
        and sender_res.dmarc_status == "pass"
        and url_res.malicious_count == 0
        and url_res.suspicious_count == 0
        and not injection_detected
    ):
        psych_score = min(psych_score, 4)
        tactics = [
            "Benign Context Cap Applied (content-analysis.md): Verified Trusted Domain with full SPF/DKIM/DMARC pass and canonical URLs."
        ]

    psych_score = min(35, psych_score)

    total_score = min(
        100,
        sender_res.component_score
        + url_res.component_score
        + psych_score
        + campaign_res.campaign_boost_score,
    )
    if injection_detected:
        total_score = max(total_score, 88)

    risk_level, escalated_action, _ = _map_score_to_level_and_action(total_score)

    # Craft human-readable headline & short analysis
    if risk_level == RiskLevel.CRITICAL:
        headline = "Critical Phishing Threat — Quarantined & Links Blocked"
        reasons_summary = []
        if sender_res.is_lookalike_domain:
            reasons_summary.append(
                f"spoofs {sender_res.impersonated_brand} using lookalike domain '{sender_res.sender_domain}'"
            )
        elif sender_res.dmarc_status != "pass":
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
            f"This message comes from an unverified sender ('{sender_res.sender_domain}') with suspicious reply routing "
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
            f"Sender '{sender_res.sender_domain}' is not in the Trusted Domains Redis DB and uses urgency cues. "
            f"Proceed with caution and verify before sharing sensitive data."
        )
        next_steps = [
            "Confirm sender identity before clicking links or replying.",
        ]
    else:
        headline = "Verified Sender & Authentic Cryptographic Signatures"
        short_analysis = (
            f"This email originates from a verified domain ('{sender_res.sender_domain}') in the Trusted Domains "
            f"Redis DB, passes SPF, DKIM, and DMARC checks, and links exclusively to clean canonical URLs."
        )
        next_steps = [
            "No action required — email passed sender integrity and URL threat scans.",
        ]

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
        ),
        "Rubric Engine (Skill .md Deterministic Mode — Set GEMINI_API_KEY for live Gemini 3.x Flash)",
    )


class PhishingAgentOrchestrator:
    """
    AGENT ORCHESTRATOR:
    Manages the agent loop, assembles the Base System Prompt + Skill Playbooks (.md),
    routes execution to Tools (Sender Integrity + Redis, URL Scan APIs) and Campaign Memory,
    invokes Gemini 3.x Flash for structured reasoning, and streams status updates.
    """

    def __init__(self) -> None:
        self.model_name = os.getenv("GEMINI_MODEL", "gemini-3-flash-preview")

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
    ) -> str:
        return (
            "Evaluate the following sanitized email and deterministic tool outputs according to "
            "`content-analysis.md` and `scam-scoring.md`.\n\n"
            "=== TOOL OUTPUT 1: SENDER / RECEIVER INTEGRITY CHECK (+ TRUSTED DOMAINS REDIS DB) ===\n"
            f"{json.dumps(sender_res.model_dump(), indent=2)}\n\n"
            "=== TOOL OUTPUT 2: URL SCAN APIs & ATTACHMENT CHECK ===\n"
            f"{json.dumps(url_res.model_dump(), indent=2)}\n\n"
            "=== TOOL OUTPUT 3: CAMPAIGN MEMORY / HISTORICAL OUTPUTS ===\n"
            f"{json.dumps(campaign_res.model_dump(), indent=2)}\n\n"
            "=== PREPROCESSED & SANITIZED EMAIL (UNTRUSTED DATA) ===\n"
            "<untrusted_email_data>\n"
            f"From: {email_payload.headers.from_raw}\n"
            f"Reply-To: {email_payload.headers.reply_to_raw}\n"
            f"Return-Path: {email_payload.headers.return_path_raw}\n"
            f"Subject: {email_payload.headers.subject}\n"
            f"Sanitization Notes: {json.dumps(email_payload.sanitization_notes)}\n"
            f"Body:\n{email_payload.body_text}\n"
            "</untrusted_email_data>\n"
        )

    async def _call_gemini_reasoning(
        self,
        system_instruction: str,
        user_prompt: str,
        email_payload: SanitizedEmailPayload,
        sender_res: SenderIntegrityResult,
        url_res: UrlScanToolResult,
        campaign_res: CampaignMatchResult,
        use_llm: bool = True,
    ) -> tuple[LLMReasoningOutput, str]:
        api_key = os.getenv("GEMINI_API_KEY", "").strip()
        if not use_llm or not api_key or genai is None or types is None:
            return _evaluate_content_playbook_fallback(email_payload, sender_res, url_res, campaign_res)

        def _sync_generate() -> tuple[LLMReasoningOutput, str]:
            client = genai.Client(api_key=api_key)
            models_to_try = [self.model_name, "gemini-2.5-flash"]
            last_err = None
            for model_id in dict.fromkeys(models_to_try):
                try:
                    response = client.models.generate_content(
                        model=model_id,
                        contents=user_prompt,
                        config=types.GenerateContentConfig(
                            system_instruction=system_instruction,
                            temperature=0.1,
                            response_mime_type="application/json",
                            response_schema=LLMReasoningOutput,
                        ),
                    )
                    parsed = LLMReasoningOutput.model_validate_json(response.text)
                    return parsed, f"Gemini Reasoning Engine ({model_id})"
                except Exception as exc:
                    last_err = exc
            raise RuntimeError(f"Gemini API call failed: {last_err}")

        try:
            return await asyncio.to_thread(_sync_generate)
        except Exception:
            # Graceful fallback if API key is invalid or network is restricted
            return _evaluate_content_playbook_fallback(email_payload, sender_res, url_res, campaign_res)

    async def analyze_raw_eml(
        self,
        raw_eml: str,
        use_llm: bool = True,
        step_callback: StepCallback = None,
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
        sender_res, url_res = await asyncio.gather(
            check_sender_receiver_integrity(sanitized),
            scan_email_urls_and_attachments(sanitized),
        )
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

        # Step 5: Assemble Prompt & Invoke LLM / Reasoning Engine (Gemini 3.x Flash)
        await self._emit(
            step_callback,
            "LLM_REASONING",
            "Assembling Prompt + Skill .md + Tool outputs and invoking Reasoning Engine...",
        )
        user_prompt = self._build_user_prompt(sanitized, sender_res, url_res, campaign_res)
        llm_output, engine_used = await self._call_gemini_reasoning(
            system_instruction=system_instruction,
            user_prompt=user_prompt,
            email_payload=sanitized,
            sender_res=sender_res,
            url_res=url_res,
            campaign_res=campaign_res,
            use_llm=use_llm,
        )

        # Ensure final score and action remain aligned with scam-scoring.md rubric
        computed_total = min(
            100,
            sender_res.component_score
            + url_res.component_score
            + llm_output.psychological_urgency_score
            + campaign_res.campaign_boost_score,
        )
        if llm_output.prompt_injection_detected:
            computed_total = max(computed_total, 88)

        final_score = max(computed_total, llm_output.final_risk_score)
        risk_level, escalated_action, banner_color = _map_score_to_level_and_action(final_score)

        latency_ms = int((time.perf_counter() - start_time) * 1000)

        breakdown = ScoreBreakdown(
            sender_integrity_score=sender_res.component_score,
            url_scan_score=url_res.component_score,
            psychological_content_score=llm_output.psychological_urgency_score,
            campaign_history_boost=campaign_res.campaign_boost_score,
            total_risk_score=final_score,
        )

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
        )

        # Step 6: Persist to Campaign History / Historical Outputs DB
        campaign_id = campaign_memory.record_analysis_output(
            payload=sanitized,
            fingerprint=campaign_res.fingerprint,
            risk_score=final_score,
            risk_level=risk_level.value,
            escalated_action=escalated_action.value,
            short_analysis=llm_output.short_analysis,
            full_response_dict=response_obj.model_dump(),
        )
        response_obj.campaign_memory.campaign_id = campaign_id

        await self._emit(
            step_callback,
            "COMPLETED",
            f"Verdict: {escalated_action.value} (Score: {final_score}/100 in {latency_ms}ms)",
            response_obj.model_dump(),
        )

        return response_obj


orchestrator = PhishingAgentOrchestrator()
