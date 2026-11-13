"""Regression tests: URL crash, stale cache, privacy, size limit,
and the Safe Browsing silent-failure found while fixing B2."""

import asyncio
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

import app.main as main_module
import app.orchestrator as orchestrator_module
from app.link_scan import InvalidUrlError, analyze_url, normalize_url
from app.main import MAX_EML_CHARS, app
from app.memory import CampaignHistoryMemory
from app.orchestrator import orchestrator
from app.redis_store import redis_store
from app.sample_emails import SAMPLE_EMLS
from app.tools import url_scanner

PRIVATE_MARKER = "My student ID is 2026001234 and my bank account is 889-001-77."


def run(coro):
    async def _wrap():
        await redis_store.initialize()
        return await coro
    return asyncio.run(_wrap())


@pytest.fixture
def fresh_memory(tmp_path, monkeypatch):
    memory = CampaignHistoryMemory(db_path=str(tmp_path / "memory.db"))
    monkeypatch.setattr(orchestrator_module, "campaign_memory", memory)
    monkeypatch.setattr(main_module, "campaign_memory", memory)
    return memory


def _db_text(memory: CampaignHistoryMemory) -> str:
    con = sqlite3.connect(memory.db_path)
    try:
        rows = con.execute("SELECT * FROM historical_outputs").fetchall()
        rows += con.execute("SELECT * FROM campaign_clusters").fetchall()
        return "\n".join(str(r) for r in rows)
    finally:
        con.close()


# ---------------------------------------------------------------- B1: malformed port

@pytest.mark.parametrize("raw", ["https://example.com:99999/login", "https://example.com:abc/x"])
def test_malformed_port_is_a_field_error_not_a_crash(raw):
    with pytest.raises(InvalidUrlError) as err:
        normalize_url(raw)
    assert "port" in str(err.value)


def test_malformed_port_returns_422_from_the_endpoint():
    with TestClient(app) as client:
        r = client.post("/api/v1/scan-url", json={"url": "https://example.com:99999/x", "use_llm": False})
    assert r.status_code == 422
    assert r.json()["detail"]["field"] == "url"


def test_valid_port_is_kept():
    assert normalize_url("https://example.com:8443/x")[0] == "https://example.com:8443/x"


# ---------------------------------------------------------------- B2: cache vs trusted list

def test_trusting_a_domain_takes_effect_immediately():
    async def scenario():
        await redis_store.initialize()
        url = "https://partner-portal.example.org/login"
        before = await analyze_url(url, use_llm=False)
        await redis_store.add_trusted_domain("partner-portal.example.org", "Verified partner")
        try:
            after = await analyze_url(url, use_llm=False)
        finally:
            await redis_store.remove_trusted_domain("partner-portal.example.org")
        return before, after

    before, after = asyncio.run(scenario())
    assert before.label == "Unverified domain"
    assert after.label == "Official domain match"


# ---------------------------------------------------------------- Safe Browsing must never fail silently

def test_safe_browsing_outage_is_reported_and_not_cached(monkeypatch):
    calls = []

    async def unreachable(url, key):
        calls.append(url)
        return None

    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "test-key")
    monkeypatch.setattr(url_scanner, "_query_google_safe_browsing", unreachable)
    url = "https://some-unknown-site.example.net/page"
    first = run(analyze_url(url, use_llm=False))
    second = run(analyze_url(url, use_llm=False))

    assert url_scanner.SAFE_BROWSING_UNREACHABLE in first.limitations
    assert "lists this link as dangerous" not in first.summary.finding
    assert len(calls) == 2  # the incomplete result was not cached


def test_safe_browsing_outage_shows_up_in_email_limitations(monkeypatch):
    async def unreachable(url, key):
        return None

    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "test-key")
    monkeypatch.setattr(url_scanner, "_query_google_safe_browsing", unreachable)
    eml = ("From: Shop <news@unknown-shop.example>\nSubject: Deals\n"
           "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n"
           "See https://unknown-shop.example/deals\n")
    r = run(orchestrator.analyze_raw_eml(eml, use_llm=False, record_memory=False))
    assert url_scanner.SAFE_BROWSING_UNREACHABLE in r.limitations


# ---------------------------------------------------------------- C1/C2: data minimisation

def test_ordinary_email_leaves_no_trace(fresh_memory):
    eml = ("From: Friend <friend@gmail.com>\nTo: me@uni.ac.id\nSubject: Private note\n"
           "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass header.from=gmail.com\n\n"
           f"{PRIVATE_MARKER}\n")
    r = run(orchestrator.analyze_raw_eml(eml, use_llm=False))
    assert r.risk_level.value in ("LOW", "MEDIUM")
    assert _db_text(fresh_memory).count("Private note") == 0
    con = sqlite3.connect(fresh_memory.db_path)
    assert con.execute("SELECT COUNT(*) FROM historical_outputs").fetchone()[0] == 0
    con.close()


def test_flagged_scam_keeps_only_the_attackers_side(fresh_memory):
    eml = SAMPLE_EMLS["paypal_phish"]["raw_eml"].replace("Sincerely,", f"{PRIVATE_MARKER}\nSincerely,")
    r = run(orchestrator.analyze_raw_eml(eml, use_llm=False))
    assert r.risk_level.value == "CRITICAL"
    stored = _db_text(fresh_memory)
    assert PRIVATE_MARKER not in stored                 # no email body
    assert "employee@acme-corp.internal" not in stored  # no recipient
    assert "security@paypai-support.com" not in stored  # no full sender address
    assert "paypai-support.com" in stored               # the attacker's domain is kept for correlation
    assert r.campaign_memory.campaign_id                # still correlated


def test_campaigns_endpoint_exposes_no_personal_fields(fresh_memory):
    with TestClient(app) as client:
        client.post("/api/v1/analyze", json={"raw_eml": SAMPLE_EMLS["paypal_phish"]["raw_eml"], "use_llm": False})
        client.post("/api/v1/analyze", json={"raw_eml": SAMPLE_EMLS["legit_github_alert"]["raw_eml"], "use_llm": False})
        data = client.get("/api/v1/campaigns").json()
    for row in data["recent_analyses"]:
        assert not {"sender_address", "subject", "short_analysis"} & set(row)
    assert all(c["last_risk_level"] in ("HIGH", "CRITICAL") for c in data["campaigns"])
    assert not any("github" in (c["sender_domain"] or "") for c in data["campaigns"])


def test_repeat_scam_still_gets_campaign_boost(fresh_memory):
    eml = SAMPLE_EMLS["paypal_phish"]["raw_eml"].replace("URGENT:", "URGENT NOTICE:")
    first = run(orchestrator.analyze_raw_eml(eml, use_llm=False))
    second = run(orchestrator.analyze_raw_eml(eml, use_llm=False))
    assert first.score_breakdown.campaign_history_boost == 0
    assert second.score_breakdown.campaign_history_boost == 15


# ---------------------------------------------------------------- D1: size limit on pasted email

def test_oversized_paste_is_rejected_with_a_field_error():
    with TestClient(app) as client:
        r = client.post("/api/v1/analyze", json={"raw_eml": "A" * (MAX_EML_CHARS + 1), "use_llm": False})
    assert r.status_code == 413
    assert r.json()["detail"]["field"] == "eml"


def test_oversized_paste_over_websocket_is_rejected():
    with TestClient(app) as client:
        with client.websocket_connect("/ws/analyze") as ws:
            ws.send_json({"raw_eml": "A" * (MAX_EML_CHARS + 1), "use_llm": False})
            msg = ws.receive_json()
    assert msg["stage"] == "ERROR"
    assert "5 MB" in msg["message"]
