from contextlib import asynccontextmanager
import json
import os
import random
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import config, eval_items, llm
from app.framework_loader import framework_loader
from app.link_scan import InvalidUrlError, analyze_url
from app.memory import campaign_memory
from app.orchestrator import orchestrator
from app.pdf_parser import MAX_PDF_BYTES, UnreadablePdfError
from app.redis_store import redis_store
from app.sample_emails import SAMPLE_EMLS
from app.schemas import AnalyzeRawEmlRequest, FullAnalysisResponse, ScanUrlRequest, UrlScanResponse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVAL_DIR = os.path.join(BASE_DIR, "eval")
EVAL_SUMMARY = os.path.join(EVAL_DIR, "results", "latest", "summary.json")


class TrustedDomainAddRequest(BaseModel):
    domain: str
    category: str = "Verified Partner Domain"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await redis_store.initialize()
    yield


app = FastAPI(
    title="CampusGuard AI — Phishing Email Agentic AI System",
    description=(
        "Agentic Email Threat Detection API integrating .eml / PDF / link scanning, "
        "Git-backed Skill Playbooks (.md), SPF/DKIM/DMARC + Trusted Domains Redis DB, "
        "URL Threat Scan APIs, Campaign History Memory, and Gemini 3.x Flash Reasoning."
    ),
    version="1.1.0",
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


def _field_error(status: int, field: str, message: str) -> HTTPException:
    """Errors the UI shows next to the input field that caused them."""
    return HTTPException(status_code=status, detail={"field": field, "message": message})


# Pasted / streamed email source gets the same ceiling as an uploaded file.
MAX_EML_CHARS = MAX_PDF_BYTES
EML_TOO_LARGE = "This email is larger than 5 MB. Remove attachments or save it as a PDF instead."


@app.get("/", include_in_schema=False)
async def serve_demo_ui():
    return FileResponse(os.path.join(static_dir, "index.html"))


@app.get("/api/v1/health")
async def health_check() -> Dict[str, Any]:
    return {
        "status": "ok",
        "redis_backend": redis_store.backend_mode,
        "gemini_api_key_configured": bool(llm.api_key()),
        "gemini_model": orchestrator.model_name,
        "llm_last_status": llm.LAST_CALL["status"],
        "llm_last_model": llm.LAST_CALL["model"],
        "llm_last_error": llm.LAST_CALL["error"],
        "llm_last_at": llm.LAST_CALL["at"],
        "safe_browsing_configured": bool(os.getenv("SAFE_BROWSING_API_KEY", "").strip()),
    }


@app.get("/api/v1/config")
async def get_public_config() -> Dict[str, Any]:
    return {
        "campus_name": config.CAMPUS_NAME,
        "campus_domains": config.CAMPUS_DOMAINS,
        "campus_portal_url": config.CAMPUS_PORTAL_URL,
        "phishing_threshold": config.PHISHING_THRESHOLD,
        "max_pdf_mb": MAX_PDF_BYTES // (1024 * 1024),
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
    Accepts raw .eml string (or pasted email text), runs the full Agent Orchestrator loop, and returns
    the Escalated Action, Short Analysis Result, and full telemetry breakdown.
    """
    if len(req.raw_eml) > MAX_EML_CHARS:
        raise _field_error(413, "eml", EML_TOO_LARGE)
    if not req.raw_eml.strip():
        raise HTTPException(status_code=400, detail="raw_eml cannot be empty")
    return await orchestrator.analyze_raw_eml(raw_eml=req.raw_eml, use_llm=req.use_llm)


@app.post("/api/v1/analyze/upload", response_model=FullAnalysisResponse)
async def analyze_email_file_upload(
    file: UploadFile = File(...),
    use_llm: bool = Query(default=True),
) -> FullAnalysisResponse:
    """Accepts a multipart upload: `.eml` / `.txt` email source, or an email saved as `.pdf`."""
    raw_bytes = await file.read(MAX_PDF_BYTES + 1)
    name = (file.filename or "").lower()
    content_type = (file.content_type or "").lower()

    is_pdf = name.endswith(".pdf") or content_type == "application/pdf" or raw_bytes[:5] == b"%PDF-"
    if is_pdf:
        try:
            return await orchestrator.analyze_pdf_bytes(raw_bytes, use_llm=use_llm)
        except UnreadablePdfError as exc:
            raise _field_error(422, "file", str(exc))

    if name and not name.endswith((".eml", ".txt", ".msg.txt")):
        raise _field_error(415, "file", "Upload the email as a PDF (Print → Save as PDF) or as an .eml file.")
    if len(raw_bytes) > MAX_PDF_BYTES:
        raise _field_error(413, "file", "This file is larger than 5 MB.")
    if b"\x00" in raw_bytes[:8192]:
        # Email source is text. NUL bytes mean a picture, archive or other binary file renamed to .eml.
        raise _field_error(422, "file", "This doesn't look like an email file. Upload a saved .eml file or the email as a PDF.")
    raw_eml = raw_bytes.decode("utf-8", errors="replace")
    if not raw_eml.strip():
        raise _field_error(422, "file", "The file is empty.")
    return await orchestrator.analyze_raw_eml(raw_eml=raw_eml, use_llm=use_llm)


@app.post("/api/v1/scan-url", response_model=UrlScanResponse)
async def scan_url(req: ScanUrlRequest) -> UrlScanResponse:
    """Stand-alone link scan for the student-facing CampusGuard AI view."""
    try:
        return await analyze_url(req.url, use_llm=req.use_llm)
    except InvalidUrlError as exc:
        raise _field_error(422, "url", str(exc))


@app.websocket("/ws/analyze")
async def analyze_email_websocket(websocket: WebSocket) -> None:
    """
    WebSocket Streaming Integration Endpoint:
    Streams real-time Agent Orchestrator steps (Sanitizer -> Skill .md -> Tools + Redis ->
    Campaign Memory -> Gemini 3.x Flash -> Escalated Action Result) to the Contextual UI.
    Emits an `LLM_FALLBACK` event whenever Gemini was not used.
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
            if len(raw_eml) > MAX_EML_CHARS:
                await websocket.send_json({"stage": "ERROR", "message": EML_TOO_LARGE})
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


# ----------------------------------------------------------------------------- evaluation

NO_DATASET = "No dataset yet. Run: python eval/generate_dataset.py (inside the project's virtual environment), or add your own items in the Evaluation tab."


def _dataset() -> List[Dict[str, Any]]:
    items = eval_items.all_items()
    if not items:
        raise HTTPException(status_code=404, detail=NO_DATASET)
    return items


@app.get("/api/v1/eval/latest")
async def get_latest_eval() -> JSONResponse:
    if not os.path.exists(EVAL_SUMMARY):
        raise HTTPException(
            status_code=404,
            detail="No evaluation results yet. Run: python eval/run_eval.py (inside the project's virtual environment)",
        )
    with open(EVAL_SUMMARY, "r", encoding="utf-8") as fh:
        summary = json.load(fh)
    # The evaluation ran without any campus configured; say so if this server has one.
    summary["campus_configured"] = bool(config.CAMPUS_DOMAINS)
    return JSONResponse(summary)


@app.get("/api/v1/eval/items")
async def list_eval_items() -> Dict[str, Any]:
    """Every dataset item's label and metadata (never its content), so the Evaluation tab can pick its own runs."""
    items = _dataset()
    return {
        "items": [eval_items.public(i) for i in items],
        "threshold": config.PHISHING_THRESHOLD,
        "added": sum(1 for i in items if i.get("source") == "added"),
    }


@app.post("/api/v1/eval/items")
async def add_eval_items(
    label: str = Form(default=""),
    links: str = Form(default=""),
    files: List[UploadFile] = File(default=[]),
) -> Dict[str, Any]:
    """Add labelled .eml / .pdf / .txt files and links to the evaluation dataset."""
    uploads = []
    for upload in files[: eval_items.MAX_FILES_PER_UPLOAD + 1]:
        uploads.append((upload.filename or "", await upload.read(MAX_PDF_BYTES + 1)))
    link_list = [line.strip() for line in links.splitlines() if line.strip()]
    try:
        added, rejected = eval_items.add_items(label.strip().lower(), uploads, link_list)
    except eval_items.ItemError as exc:
        raise _field_error(422, "dataset", str(exc))
    return {"added": [eval_items.public(i) for i in added], "rejected": rejected}


@app.delete("/api/v1/eval/items/{item_id}")
async def remove_eval_item(item_id: str) -> Dict[str, Any]:
    try:
        eval_items.remove_item(item_id)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown dataset item '{item_id}'")
    return {"removed": item_id}


@app.get("/api/v1/eval/sample")
async def get_eval_sample(n: int = Query(default=10, ge=1, le=10000), split: str = "all", seed: Optional[int] = None):
    """A balanced random set of dataset items."""
    items = [i for i in _dataset() if split == "all" or i["split"] == split]
    rng = random.Random(seed)
    phish = [i for i in items if i["label"] == "phishing"]
    legit = [i for i in items if i["label"] == "legit"]
    rng.shuffle(phish)
    rng.shuffle(legit)
    picked = phish[: (n + 1) // 2] + legit[: n // 2]
    rng.shuffle(picked)
    return {"items": [eval_items.public(i) for i in picked]}


@app.post("/api/v1/eval/run-item/{item_id}")
async def run_eval_item(item_id: str, use_llm: bool = Query(default=True)) -> Dict[str, Any]:
    """Run one dataset item through the live pipeline and compare with its label."""
    item = eval_items.find(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail=f"Unknown dataset item '{item_id}'")

    kind = item["input_kind"]
    try:
        if kind == "url":
            result = await analyze_url(item["url"], use_llm=use_llm)
        elif kind == "pdf":
            with open(eval_items.file_path(item), "rb") as fh:
                result = await orchestrator.analyze_pdf_bytes(fh.read(), use_llm=use_llm, record_memory=False)
        else:
            with open(eval_items.file_path(item), "r", encoding="utf-8", errors="replace") as fh:
                result = await orchestrator.analyze_raw_eml(fh.read(), use_llm=use_llm, record_memory=False)
    except (InvalidUrlError, UnreadablePdfError, FileNotFoundError) as exc:
        message = "The item's file is missing." if isinstance(exc, FileNotFoundError) else str(exc)
        return {"id": item_id, "label": item["label"], "error": message, "correct": None}

    predicted = "phishing" if result.risk_score >= config.PHISHING_THRESHOLD else "legit"
    return {
        "id": item_id,
        "label": item["label"],
        "predicted": predicted,
        "correct": predicted == item["label"],
        "risk_score": result.risk_score,
        "threshold": config.PHISHING_THRESHOLD,
        "llm_status": result.llm_status.value,
        "result": result.model_dump(mode="json"),
    }
