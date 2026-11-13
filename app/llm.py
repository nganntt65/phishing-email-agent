"""Single entry point for Gemini calls.

Every call returns an `LLMResult` whose `status` says whether the model was actually used.
Callers must surface that status; nothing here silently pretends the LLM ran.

Robustness:
- every HTTP attempt has a timeout (LLM_TIMEOUT_SECONDS, default 20),
- the whole call has a deadline (LLM_DEADLINE_SECONDS, default 30) after which the caller falls back,
- rate limits (429) and server errors (5xx) are retried with backoff, honouring Google's retryDelay,
- a rejected key (401/403) stops immediately; an unknown model (404) moves on to the fallback model,
- a reply wrapped in a ```json fence is unwrapped before parsing.

Set `LLM_CACHE_DIR` to cache responses on disk (used by the evaluation harness so re-runs
cost nothing and survive rate limits).
"""

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Type

from pydantic import BaseModel

from app.schemas import LLMStatus

try:
    from google import genai
    from google.genai import types
except ImportError:  # pragma: no cover - package is in requirements
    genai = None  # type: ignore
    types = None  # type: ignore

FALLBACK_MODEL = "gemini-2.5-flash"
PROMPT_VERSION = "2026-11-11.v2"

RETRYABLE_CODES = {429, 500, 502, 503, 504}
AUTH_CODES = {401, 403}
MAX_RETRIES_PER_MODEL = 3
_sleep = time.sleep          # replaced in tests
_monotonic = time.monotonic  # replaced in tests

# Last call outcome, exposed by /api/v1/health so the UI can show it.
LAST_CALL: Dict[str, Optional[str]] = {"status": None, "model": None, "error": None, "at": None}


class LLMUnavailableError(RuntimeError):
    """Raised in strict mode when the LLM could not be used."""

    def __init__(self, status: LLMStatus, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class LLMResult:
    status: LLMStatus
    model: Optional[str] = None
    error: Optional[str] = None
    data: Any = None

    @property
    def used(self) -> bool:
        return self.status == LLMStatus.USED


def api_key() -> str:
    return os.getenv("GEMINI_API_KEY", "").strip()


def primary_model() -> str:
    return os.getenv("GEMINI_MODEL", "gemini-3-flash-preview").strip() or "gemini-3-flash-preview"


def models_to_try() -> List[str]:
    return list(dict.fromkeys([primary_model(), FALLBACK_MODEL]))


def _env_seconds(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, "").strip() or default)
        return value if value > 0 else default
    except ValueError:
        return default


def timeout_seconds() -> float:
    return _env_seconds("LLM_TIMEOUT_SECONDS", 20.0)


def deadline_seconds() -> float:
    return _env_seconds("LLM_DEADLINE_SECONDS", 30.0)


def _error_code(exc: BaseException) -> Optional[int]:
    code = getattr(exc, "code", None)
    return code if isinstance(code, int) else None


def _is_timeout(exc: BaseException) -> bool:
    return any("timeout" in cls.__name__.lower() for cls in type(exc).__mro__)


_RETRY_DELAY = re.compile(r"retryDelay['\"]?\s*[:=]\s*['\"]?(\d+(?:\.\d+)?)s")


def _suggested_delay(exc: BaseException) -> Optional[float]:
    """Google puts a RetryInfo.retryDelay (e.g. "17s") in the details of a 429."""
    match = _RETRY_DELAY.search(f"{getattr(exc, 'details', '')} {exc}")
    return float(match.group(1)) if match else None


def _describe(exc: BaseException) -> str:
    """Plain-language cause first, technical detail after (both safe to show)."""
    code = _error_code(exc)
    if code == 429:
        cause = "rate limit reached"
    elif code in AUTH_CODES:
        cause = "the API key was rejected"
    elif code == 404:
        cause = "the model isn't available for this key"
    elif code is not None and code >= 500:
        cause = "Gemini had a server error"
    elif _is_timeout(exc):
        cause = "Gemini didn't answer in time"
    elif type(exc).__name__ == "ValidationError" or isinstance(exc, (ValueError, json.JSONDecodeError)):
        cause = "Gemini's answer didn't match the expected format"
    else:
        cause = "unexpected error"
    return f"{cause} — {sanitize_error(exc)}"


_FENCE = re.compile(r"^\s*```[a-zA-Z]*\s*\n?(.*?)\n?\s*```\s*$", re.DOTALL)


def _strip_fence(text: str) -> str:
    match = _FENCE.match(text or "")
    return match.group(1) if match else (text or "")


_SECRET_PATTERNS = [
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),
    re.compile(r"(key|api_key|apikey|token)=([^&\s'\"]+)", re.IGNORECASE),
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]+", re.IGNORECASE),
]


def sanitize_error(exc: BaseException) -> str:
    """Short, key-free description of an exception, safe to show in the UI."""
    message = f"{type(exc).__name__}: {exc}"
    key = api_key()
    if key:
        message = message.replace(key, "[redacted]")
    for pattern in _SECRET_PATTERNS:
        message = pattern.sub("[redacted]", message)
    message = re.sub(r"\s+", " ", message).strip()
    return message[:240] + ("…" if len(message) > 240 else "")


def status_message(status: LLMStatus, error: Optional[str] = None) -> str:
    """Plain-language reason shown to users when the LLM was not used."""
    if status == LLMStatus.USED:
        return "AI reasoning (Gemini) was used."
    if status == LLMStatus.SKIPPED_NO_API_KEY:
        return "AI reasoning is off because no Gemini API key is configured."
    if status == LLMStatus.SKIPPED_BY_REQUEST:
        return "AI reasoning was turned off for this scan."
    return f"Gemini could not be reached ({error or 'unknown error'})."


def _record(status: LLMStatus, model: Optional[str], error: Optional[str]) -> None:
    LAST_CALL.update(
        status=status.value,
        model=model,
        error=error,
        at=datetime.now(timezone.utc).isoformat(),
    )


def _cache_file(payload: Dict[str, Any]) -> Optional[str]:
    cache_dir = os.getenv("LLM_CACHE_DIR", "").strip()
    if not cache_dir:
        return None
    os.makedirs(cache_dir, exist_ok=True)
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    return os.path.join(cache_dir, f"{digest}.json")


def generate(
    *,
    system_instruction: str,
    prompt: str,
    response_schema: Optional[Type[BaseModel]] = None,
    use_llm: bool = True,
    temperature: float = 0.1,
) -> LLMResult:
    """Synchronous Gemini call. Run it with `asyncio.to_thread` from async code."""
    if not use_llm:
        result = LLMResult(LLMStatus.SKIPPED_BY_REQUEST)
        _record(result.status, None, None)
        return result

    key = api_key()
    if not key:
        result = LLMResult(LLMStatus.SKIPPED_NO_API_KEY)
        _record(result.status, None, None)
        return result

    if genai is None or types is None:
        result = LLMResult(LLMStatus.FAILED_FALLBACK_USED, error="google-genai package is not installed")
        _record(result.status, None, result.error)
        return result

    models = models_to_try()
    cache_path = _cache_file(
        {
            "v": PROMPT_VERSION,
            "models": models,
            "system": hashlib.sha256(system_instruction.encode("utf-8")).hexdigest(),
            "prompt": prompt,
            "schema": response_schema.__name__ if response_schema else None,
            "temperature": temperature,
        }
    )

    def _parse(text: str) -> Any:
        text = _strip_fence(text)
        if response_schema is not None:
            return response_schema.model_validate_json(text)
        cleaned = (text or "").strip()
        if not cleaned:
            raise ValueError("empty response")
        return cleaned

    if cache_path and os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as fh:
                cached = json.load(fh)
            result = LLMResult(LLMStatus.USED, model=cached["model"], data=_parse(cached["text"]))
            _record(result.status, result.model, None)
            return result
        except Exception:
            pass  # corrupt cache entry: fall through to a live call

    deadline = _monotonic() + deadline_seconds()
    per_attempt = timeout_seconds()
    last_error: Optional[BaseException] = None
    attempts = 0
    client = genai.Client(api_key=key, http_options=types.HttpOptions(timeout=int(per_attempt * 1000)))

    for model_id in models:
        retry = 0
        while True:
            remaining = deadline - _monotonic()
            if remaining < 1.0:
                break
            attempts += 1
            try:
                config_kwargs: Dict[str, Any] = {
                    "system_instruction": system_instruction,
                    "temperature": temperature,
                    # Never wait past the overall deadline, even on the last attempt.
                    "http_options": types.HttpOptions(timeout=int(min(per_attempt, remaining) * 1000)),
                }
                if response_schema is not None:
                    config_kwargs["response_mime_type"] = "application/json"
                    config_kwargs["response_schema"] = response_schema
                response = client.models.generate_content(
                    model=model_id,
                    contents=prompt,
                    config=types.GenerateContentConfig(**config_kwargs),
                )
                text = response.text or ""
                data = _parse(text)
                if cache_path:
                    with open(cache_path, "w", encoding="utf-8") as fh:
                        json.dump({"model": model_id, "text": _strip_fence(text)}, fh)
                result = LLMResult(LLMStatus.USED, model=model_id, data=data)
                _record(result.status, model_id, None)
                return result
            except Exception as exc:
                last_error = exc
                code = _error_code(exc)
                if code in AUTH_CODES:
                    break  # same key for every model: stop here
                retryable = code in RETRYABLE_CODES or _is_timeout(exc)
                if not retryable or retry + 1 >= MAX_RETRIES_PER_MODEL:
                    break  # next model (404, 400, bad output, or retries used up)
                delay = _suggested_delay(exc) or float(2 ** retry)  # 1s, 2s, 4s
                if delay >= deadline - _monotonic() - 1.0:
                    break  # waiting would blow the deadline; try the next model instead
                _sleep(delay)
                retry += 1
        if last_error is not None and _error_code(last_error) in AUTH_CODES:
            break

    if last_error is None:
        detail = "no time left before the deadline"
    else:
        detail = _describe(last_error)
    result = LLMResult(
        LLMStatus.FAILED_FALLBACK_USED,
        error=f"{detail} (after {attempts} attempt{'s' if attempts != 1 else ''})"[:300],
    )
    _record(result.status, None, result.error)
    return result
