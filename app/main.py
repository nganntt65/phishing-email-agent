from contextlib import asynccontextmanager
import os
from typing import Any, Dict

from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.framework_loader import framework_loader
from app.memory import campaign_memory
from app.orchestrator import orchestrator
from app.redis_store import redis_store
from app.sample_emails import SAMPLE_EMLS
from app.schemas import AnalyzeRawEmlRequest, FullAnalysisResponse


class TrustedDomainAddRequest(BaseModel):
    domain: str
    category: str = "Verified Partner Domain"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await redis_store.initialize()
    yield


app = FastAPI(
    title="Phishing Email Agentic AI System",
    description=(
        "Agentic Email Threat Detection API integrating .eml Sanitization, "
        "Git-backed Skill Playbooks (.md), SPF/DKIM/DMARC + Trusted Domains Redis DB, "
        "URL Threat Scan APIs, Campaign History Memory, and Gemini 3.x Flash Reasoning."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", include_in_schema=False)
async def serve_demo_ui():
    return FileResponse(os.path.join(static_dir, "index.html"))


@app.get("/api/v1/health")
async def health_check() -> Dict[str, Any]:
    return {
        "status": "ok",
        "redis_backend": redis_store.backend_mode,
        "gemini_api_key_configured": bool(os.getenv("GEMINI_API_KEY", "").strip()),
        "gemini_model": orchestrator.model_name,
    }


@app.get("/api/v1/samples")
async def get_sample_emails() -> Dict[str, Any]:
    return {"samples": list(SAMPLE_EMLS.values())}


@app.get("/api/v1/skills")
async def get_loaded_skills() -> Dict[str, Any]:
    return framework_loader.load_all()


@app.get("/api/v1/trusted-domains")
async def get_trusted_domains() -> Dict[str, Any]:
    domains = await redis_store.list_trusted_domains()
    return {
        "backend": redis_store.backend_mode,
        "count": len(domains),
        "domains": domains,
    }


@app.post("/api/v1/trusted-domains")
async def add_trusted_domain(req: TrustedDomainAddRequest) -> Dict[str, Any]:
    if not req.domain.strip():
        raise HTTPException(status_code=400, detail="Domain cannot be empty")
    domains = await redis_store.add_trusted_domain(req.domain, req.category)
    return {"backend": redis_store.backend_mode, "domains": domains}


@app.delete("/api/v1/trusted-domains/{domain}")
async def delete_trusted_domain(domain: str) -> Dict[str, Any]:
    domains = await redis_store.remove_trusted_domain(domain)
    return {"backend": redis_store.backend_mode, "domains": domains}


@app.get("/api/v1/campaigns")
async def get_campaign_history() -> Dict[str, Any]:
    return campaign_memory.list_recent_history(limit=20)


@app.post("/api/v1/analyze", response_model=FullAnalysisResponse)
async def analyze_email_rest(req: AnalyzeRawEmlRequest) -> FullAnalysisResponse:
    """
    HTTPS REST Integration Endpoint:
    Accepts raw .eml string, runs the full Agent Orchestrator loop, and returns
    the Escalated Action, Short Analysis Result, and full telemetry breakdown.
    """
    if not req.raw_eml.strip():
        raise HTTPException(status_code=400, detail="raw_eml cannot be empty")
    return await orchestrator.analyze_raw_eml(raw_eml=req.raw_eml, use_llm=req.use_llm)


@app.post("/api/v1/analyze/upload", response_model=FullAnalysisResponse)
async def analyze_email_file_upload(file: UploadFile = File(...)) -> FullAnalysisResponse:
    """Accepts a multipart `.eml` file upload from a web app or email client plugin."""
    raw_bytes = await file.read()
    raw_eml = raw_bytes.decode("utf-8", errors="replace")
    return await orchestrator.analyze_raw_eml(raw_eml=raw_eml, use_llm=True)


@app.websocket("/ws/analyze")
async def analyze_email_websocket(websocket: WebSocket) -> None:
    """
    WebSocket Streaming Integration Endpoint:
    Streams real-time Agent Orchestrator steps (Sanitizer -> Skill .md -> Tools + Redis ->
    Campaign Memory -> Gemini 3.x Flash -> Escalated Action Result) to the Contextual UI.
    """
    await websocket.accept()
    try:
        while True:
            payload = await websocket.receive_json()
            raw_eml = str(payload.get("raw_eml", "")).strip()
            use_llm = bool(payload.get("use_llm", True))
            if not raw_eml:
                await websocket.send_json({"stage": "ERROR", "message": "raw_eml cannot be empty"})
                continue

            async def _ws_step_callback(event: Dict[str, Any]) -> None:
                await websocket.send_json(event)

            await orchestrator.analyze_raw_eml(
                raw_eml=raw_eml,
                use_llm=use_llm,
                step_callback=_ws_step_callback,
            )
    except WebSocketDisconnect:
        return
    except Exception as exc:
        try:
            await websocket.send_json({"stage": "ERROR", "message": str(exc)})
        except Exception:
            pass

