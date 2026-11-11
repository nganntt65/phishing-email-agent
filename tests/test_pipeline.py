import asyncio
from fastapi.testclient import TestClient

from app.main import app
from app.orchestrator import orchestrator
from app.redis_store import redis_store
from app.sample_emails import SAMPLE_EMLS
from app.schemas import EscalatedAction, RiskLevel


def test_end_to_end_pipeline():
    async def _run():
        await redis_store.initialize()

        # 1. PayPal Phish -> CRITICAL / QUARANTINE_AND_BLOCK
        res_phish = await orchestrator.analyze_raw_eml(
            SAMPLE_EMLS["paypal_phish"]["raw_eml"], use_llm=False
        )
        assert res_phish.risk_level == RiskLevel.CRITICAL
        assert res_phish.escalated_action == EscalatedAction.QUARANTINE_AND_BLOCK
        assert res_phish.sender_integrity.is_lookalike_domain is True
        assert res_phish.url_scan.malicious_count >= 1
        assert len(res_phish.sanitized_email.anchor_mismatches) == 1

        # 2. Executive BEC Wire Transfer -> HIGH or CRITICAL
        res_bec = await orchestrator.analyze_raw_eml(
            SAMPLE_EMLS["ceo_bec_wire"]["raw_eml"], use_llm=False
        )
        assert res_bec.risk_score >= 60
        assert res_bec.sender_integrity.reply_to_mismatch is True

        # 3. Prompt Injection Evasion + .pdf.exe -> Blocked & Flagged
        res_inj = await orchestrator.analyze_raw_eml(
            SAMPLE_EMLS["prompt_injection_attack"]["raw_eml"], use_llm=False
        )
        assert res_inj.prompt_injection_detected is True
        assert res_inj.risk_level == RiskLevel.CRITICAL
        assert res_inj.escalated_action == EscalatedAction.QUARANTINE_AND_BLOCK
        assert "W2_Tax_Compliance_Form_2026.pdf.exe" in res_inj.url_scan.high_risk_attachments

        # 4. Legitimate GitHub Security Alert -> LOW / ALLOW
        res_legit = await orchestrator.analyze_raw_eml(
            SAMPLE_EMLS["legit_github_alert"]["raw_eml"], use_llm=False
        )
        assert res_legit.sender_integrity.in_trusted_domains_redis is True
        assert res_legit.risk_level == RiskLevel.LOW
        assert res_legit.escalated_action == EscalatedAction.ALLOW

        # 5. University IT Helpdesk MFA Reset Lure -> HIGH / WARN_AND_DISABLE_LINKS
        res_high_uni = await orchestrator.analyze_raw_eml(
            SAMPLE_EMLS["university_grant_high_risk"]["raw_eml"], use_llm=False
        )
        assert res_high_uni.risk_level == RiskLevel.HIGH
        assert res_high_uni.escalated_action == EscalatedAction.WARN_AND_DISABLE_LINKS
        assert 60 <= res_high_uni.risk_score < 85

        # 6. Vendor ACH Banking Update & Overdue Invoice -> HIGH / WARN_AND_DISABLE_LINKS
        res_high_vendor = await orchestrator.analyze_raw_eml(
            SAMPLE_EMLS["vendor_bank_update_high_risk"]["raw_eml"], use_llm=False
        )
        assert res_high_vendor.risk_level == RiskLevel.HIGH
        assert res_high_vendor.escalated_action == EscalatedAction.WARN_AND_DISABLE_LINKS
        assert 60 <= res_high_vendor.risk_score < 85

        # 7. Academic Symposium Registration Reminder -> MEDIUM / CAUTION_BANNER
        res_med_conf = await orchestrator.analyze_raw_eml(
            SAMPLE_EMLS["academic_conference_medium_risk"]["raw_eml"], use_llm=False
        )
        assert res_med_conf.risk_level == RiskLevel.MEDIUM
        assert res_med_conf.escalated_action == EscalatedAction.CAUTION_BANNER
        assert 30 <= res_med_conf.risk_score < 60

        # 8. Third-Party Benefits Open Enrollment Notice -> MEDIUM / CAUTION_BANNER
        res_med_hr = await orchestrator.analyze_raw_eml(
            SAMPLE_EMLS["hr_survey_medium_risk"]["raw_eml"], use_llm=False
        )
        assert res_med_hr.risk_level == RiskLevel.MEDIUM
        assert res_med_hr.escalated_action == EscalatedAction.CAUTION_BANNER
        assert 30 <= res_med_hr.risk_score < 60

    asyncio.run(_run())


def test_fastapi_rest_and_websocket_endpoints():
    with TestClient(app) as client:
        # Health & Skills
        resp_health = client.get("/api/v1/health")
        assert resp_health.status_code == 200
        assert resp_health.json()["status"] == "ok"

        resp_skills = client.get("/api/v1/skills")
        assert resp_skills.status_code == 200
        assert "content-analysis.md" in resp_skills.json()["content_analysis_skill"]

        # Trusted Domains Redis DB CRUD
        resp_domains = client.post(
            "/api/v1/trusted-domains",
            json={"domain": "verified-partner.org", "category": "B2B Partner"},
        )
        assert resp_domains.status_code == 200
        assert "verified-partner.org" in resp_domains.json()["domains"]

        # HTTPS POST /api/v1/analyze
        resp_analyze = client.post(
            "/api/v1/analyze",
            json={"raw_eml": SAMPLE_EMLS["paypal_phish"]["raw_eml"], "use_llm": False},
        )
        assert resp_analyze.status_code == 200
        body = resp_analyze.json()
        assert body["escalated_action"] == "QUARANTINE_AND_BLOCK"
        assert body["risk_score"] >= 85

        # WebSocket /ws/analyze streaming
        stages_received = []
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json(
                {"raw_eml": SAMPLE_EMLS["legit_github_alert"]["raw_eml"], "use_llm": False}
            )
            while True:
                event = ws.receive_json()
                stages_received.append(event["stage"])
                if event["stage"] == "COMPLETED":
                    assert event["data"]["escalated_action"] == "ALLOW"
                    break

        assert "INPUT_SANITIZATION" in stages_received
        assert "AGENT_FRAMEWORK" in stages_received
        assert "TOOLS_EXECUTION" in stages_received
        assert "MEMORY_LOOKUP" in stages_received
        assert "LLM_REASONING" in stages_received
        assert "COMPLETED" in stages_received
