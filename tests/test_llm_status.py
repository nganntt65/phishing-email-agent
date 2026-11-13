"""Fallbacks must never be silent. Gemini is mocked; no network calls."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from app import llm
from app.orchestrator import LLMUnavailableError, orchestrator
from app.redis_store import redis_store
from app.sample_emails import SAMPLE_EMLS
from app.schemas import LLMStatus

PAYPAL = SAMPLE_EMLS["paypal_phish"]["raw_eml"]


class FakeTypes:
    @staticmethod
    def GenerateContentConfig(**kw):
        return kw

    @staticmethod
    def HttpOptions(**kw):
        return SimpleNamespace(**kw)


CLIENT_KWARGS = []


def fake_genai(responder):
    class Models:
        def generate_content(self, model, contents, config):
            return responder(model, contents, config)

    class Client:
        def __init__(self, api_key, **kwargs):
            CLIENT_KWARGS.append(kwargs)
            self.models = Models()

    return SimpleNamespace(Client=Client)


class FakeAPIError(Exception):
    """Shaped like google.genai.errors.APIError: an int .code and a .details payload."""

    def __init__(self, code, details=""):
        super().__init__(f"{code} {details}")
        self.code = code
        self.details = details


class ReadTimeout(Exception):
    """Same class name as httpx's timeout, which is how llm.py recognises timeouts."""


@pytest.fixture
def fast_clock(monkeypatch):
    """Make backoff instant and observable: sleeping advances a fake clock."""
    state = {"now": 1000.0, "sleeps": []}
    monkeypatch.setattr(llm, "_monotonic", lambda: state["now"])

    def fake_sleep(seconds):
        state["sleeps"].append(seconds)
        state["now"] += seconds

    monkeypatch.setattr(llm, "_sleep", fake_sleep)
    return state


def use_fake(monkeypatch, responder):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.delenv("LLM_CACHE_DIR", raising=False)
    monkeypatch.setattr(llm, "types", FakeTypes)
    monkeypatch.setattr(llm, "genai", fake_genai(responder))


def run(coro):
    async def _wrap():
        await redis_store.initialize()
        return await coro
    return asyncio.run(_wrap())


GOOD_JSON = json.dumps({
    "psychological_urgency_score": 20,
    "psychological_tactics_detected": ["Urgency"],
    "prompt_injection_detected": False,
    "final_risk_score": 95,
    "risk_level": "CRITICAL",
    "escalated_action": "QUARANTINE_AND_BLOCK",
    "headline": "Phish",
    "short_analysis": "Bad.",
    "recommended_next_steps": ["Delete it."],
    "primary_finding": "This email asks you to restore your PayPal access.",
    "evidence": [
        {"quote": "will be permanently closed within 24 hours", "tactic": "Urgency", "points": 10},
        {"quote": "Send us your password now", "tactic": "Invented", "points": 5},
    ],
})


def test_no_key_reports_skipped_and_uses_rules(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "")
    r = run(orchestrator.analyze_raw_eml(PAYPAL, use_llm=True, record_memory=False))
    assert r.llm_status == LLMStatus.SKIPPED_NO_API_KEY
    assert "no Gemini API key" in r.llm_status_message
    assert r.engine_used.startswith("Rubric Engine")
    assert any("AI reasoning wasn't used" in l for l in r.limitations)


def test_successful_call_is_used_and_evidence_is_grounded(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(llm, "types", FakeTypes)
    monkeypatch.setattr(llm, "genai", fake_genai(lambda m, c, cfg: SimpleNamespace(text=GOOD_JSON)))
    r = run(orchestrator.analyze_raw_eml(PAYPAL, use_llm=True, record_memory=False))
    assert r.llm_status == LLMStatus.USED
    assert r.engine_used.startswith("Gemini Reasoning Engine")
    assert r.llm_final_risk_score == 95
    llm_ev = {e.quote: e.grounded for e in r.evidence if e.source == "llm"}
    assert llm_ev["will be permanently closed within 24 hours"] is True
    assert llm_ev["Send us your password now"] is False  # invented quote is flagged
    assert r.groundedness == 0.5


def test_failure_falls_back_visibly_and_hides_the_key(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSySECRETSECRETSECRETSECRET123")

    def boom(model, contents, config):
        raise RuntimeError("403 for url https://x/?key=AIzaSySECRETSECRETSECRETSECRET123")

    monkeypatch.setattr(llm, "types", FakeTypes)
    monkeypatch.setattr(llm, "genai", fake_genai(boom))
    events = []

    async def capture(e):
        events.append(e)

    r = run(orchestrator.analyze_raw_eml(PAYPAL, use_llm=True, step_callback=capture, record_memory=False))
    assert r.llm_status == LLMStatus.FAILED_FALLBACK_USED
    assert "SECRET" not in (r.llm_error or "")
    assert "LLM_FALLBACK" in [e["stage"] for e in events]
    assert llm.LAST_CALL["status"] == "FAILED_FALLBACK_USED"


def test_strict_mode_raises_instead_of_falling_back(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "")
    with pytest.raises(LLMUnavailableError):
        run(orchestrator.analyze_raw_eml(PAYPAL, use_llm=True, strict_llm=True, record_memory=False))


def test_disk_cache_avoids_second_call(monkeypatch, tmp_path):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("LLM_CACHE_DIR", str(tmp_path))
    calls = []

    def respond(model, contents, config):
        calls.append(model)
        return SimpleNamespace(text="A short explanation.")

    monkeypatch.setattr(llm, "types", FakeTypes)
    monkeypatch.setattr(llm, "genai", fake_genai(respond))
    first = llm.generate(system_instruction="s", prompt="p")
    second = llm.generate(system_instruction="s", prompt="p")
    assert first.used and second.used
    assert len(calls) == 1


# ---------------------------------------------------------------- robustness of Gemini answers

def test_every_call_has_a_timeout(monkeypatch, fast_clock):
    CLIENT_KWARGS.clear()
    configs = []

    def respond(model, contents, config):
        configs.append(config)
        return SimpleNamespace(text="ok")

    use_fake(monkeypatch, respond)
    llm.generate(system_instruction="s", prompt="p")
    assert CLIENT_KWARGS[-1]["http_options"].timeout == 20_000
    assert configs[-1]["http_options"].timeout <= 20_000


def test_rate_limit_is_retried_then_succeeds(monkeypatch, fast_clock):
    calls = []

    def respond(model, contents, config):
        calls.append(model)
        if len(calls) < 3:
            raise FakeAPIError(429, "RESOURCE_EXHAUSTED")
        return SimpleNamespace(text=GOOD_JSON)

    use_fake(monkeypatch, respond)
    r = llm.generate(system_instruction="s", prompt="p", response_schema=llm_schema())
    assert r.used
    assert calls == [llm.primary_model()] * 3          # retried on the same model
    assert fast_clock["sleeps"] == [1.0, 2.0]           # exponential backoff


def test_google_retry_delay_is_honoured(monkeypatch, fast_clock):
    calls = []

    def respond(model, contents, config):
        calls.append(model)
        if len(calls) == 1:
            raise FakeAPIError(429, "{'@type': 'RetryInfo', 'retryDelay': '7s'}")
        return SimpleNamespace(text="ok")

    use_fake(monkeypatch, respond)
    assert llm.generate(system_instruction="s", prompt="p").used
    assert fast_clock["sleeps"] == [7.0]


def test_rate_limit_never_waits_past_the_deadline(monkeypatch, fast_clock):
    def respond(model, contents, config):
        raise FakeAPIError(429, "{'retryDelay': '45s'}")  # longer than the 30 s deadline

    use_fake(monkeypatch, respond)
    r = llm.generate(system_instruction="s", prompt="p")
    assert r.status == LLMStatus.FAILED_FALLBACK_USED
    assert "rate limit reached" in r.error
    assert sum(fast_clock["sleeps"]) < llm.deadline_seconds()


def test_rejected_key_stops_immediately(monkeypatch, fast_clock):
    calls = []

    def respond(model, contents, config):
        calls.append(model)
        raise FakeAPIError(403, "PERMISSION_DENIED")

    use_fake(monkeypatch, respond)
    r = llm.generate(system_instruction="s", prompt="p")
    assert r.status == LLMStatus.FAILED_FALLBACK_USED
    assert len(calls) == 1                               # no retries, no second model
    assert "API key was rejected" in r.error


def test_unknown_model_moves_to_fallback_model(monkeypatch, fast_clock):
    calls = []

    def respond(model, contents, config):
        calls.append(model)
        if model == llm.primary_model():
            raise FakeAPIError(404, "NOT_FOUND")
        return SimpleNamespace(text="ok")

    use_fake(monkeypatch, respond)
    r = llm.generate(system_instruction="s", prompt="p")
    assert r.used and r.model == llm.FALLBACK_MODEL
    assert calls == [llm.primary_model(), llm.FALLBACK_MODEL]


def test_timeout_is_retried_and_reported(monkeypatch, fast_clock):
    def respond(model, contents, config):
        fast_clock["now"] += 5  # each attempt burns time before failing
        raise ReadTimeout("timed out")

    use_fake(monkeypatch, respond)
    r = llm.generate(system_instruction="s", prompt="p")
    assert r.status == LLMStatus.FAILED_FALLBACK_USED
    assert "didn't answer in time" in r.error


def test_fenced_json_is_accepted(monkeypatch, fast_clock):
    use_fake(monkeypatch, lambda m, c, cfg: SimpleNamespace(text="```json\n" + GOOD_JSON + "\n```"))
    assert llm.generate(system_instruction="s", prompt="p", response_schema=llm_schema()).used


def test_near_miss_values_are_clamped_not_rejected(monkeypatch, fast_clock):
    near_miss = json.loads(GOOD_JSON)
    near_miss.update(psychological_urgency_score=36, final_risk_score=104, risk_level="Somewhat risky")
    near_miss["evidence"][0]["points"] = 50
    use_fake(monkeypatch, lambda m, c, cfg: SimpleNamespace(text=json.dumps(near_miss)))
    r = llm.generate(system_instruction="s", prompt="p", response_schema=llm_schema())
    assert r.used
    assert r.data.psychological_urgency_score == 35
    assert r.data.final_risk_score == 100
    assert r.data.risk_level.value == "CRITICAL"         # derived from the score
    assert r.data.evidence[0].points == 35


def test_structurally_broken_answer_still_falls_back(monkeypatch, fast_clock):
    use_fake(monkeypatch, lambda m, c, cfg: SimpleNamespace(text=json.dumps({"psychological_urgency_score": 3})))
    r = llm.generate(system_instruction="s", prompt="p", response_schema=llm_schema())
    assert r.status == LLMStatus.FAILED_FALLBACK_USED
    assert "didn't match the expected format" in r.error


def test_llm_tactics_without_quotes_are_not_called_no_red_flags(monkeypatch, fast_clock):
    low = json.loads(GOOD_JSON)
    low.update(psychological_urgency_score=8, final_risk_score=10, risk_level="LOW",
               escalated_action="ALLOW", primary_finding="", evidence=[],
               psychological_tactics_detected=["Urgency: asks for a reply today"])
    use_fake(monkeypatch, lambda m, c, cfg: SimpleNamespace(text=json.dumps(low)))
    text = "From: someone@unknown.example\nSubject: Hello\n\nPlease reply today.\n"
    r = run(orchestrator.analyze_raw_eml(text, use_llm=True, record_memory=False))
    assert r.llm_status == LLMStatus.USED
    assert r.risk_level.value == "LOW"
    assert r.summary.label == "Low risk"
    assert "urgency" in r.summary.finding


def llm_schema():
    from app.schemas import LLMReasoningOutput
    return LLMReasoningOutput
