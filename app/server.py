"""FastAPI entrypoint."""

from __future__ import annotations

import hmac
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import pipeline, posture, vault
from .config import ROOT, settings

app = FastAPI(title="Secure ID Extract", docs_url="/docs", redoc_url=None)
STATIC = ROOT / "static"
SAMPLES = ROOT / "data" / "samples"

_hits: dict[str, deque] = defaultdict(deque)


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")


def _rate_limit(request: Request) -> None:
    now, window = time.time(), _hits[_client_ip(request)]
    while window and now - window[0] > 60:
        window.popleft()
    if len(window) >= settings.rate_limit_rpm:
        raise HTTPException(429, "Too many requests. Try again in a minute.")
    window.append(now)


def _require_api_key(x_api_key: str | None) -> None:
    if settings.api_key and not hmac.compare_digest(x_api_key or "", settings.api_key):
        raise HTTPException(401, "Missing or invalid API key.")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data: blob:; style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; script-src 'self'; connect-src 'self'"
    )
    return response


@app.get("/health")
async def health() -> dict:
    return {"ok": True, "model": settings.gemini_model, "vault_configured": vault.configured()}


@app.post("/api/extract")
async def extract(request: Request, file: UploadFile = File(...), x_api_key: str | None = Header(default=None)):
    _require_api_key(x_api_key)
    _rate_limit(request)
    raw = await file.read(settings.max_upload_bytes + 1)
    try:
        return await pipeline.run(raw)
    except pipeline.PipelineBlocked as blocked:
        return JSONResponse(status_code=blocked.status, content={
            "blocked": True, "stage": blocked.stage, "reason": blocked.reason, "stages": blocked.stages,
        })
    finally:
        del raw


class ReidentifyRequest(BaseModel):
    tokens: dict[str, str]


@app.post("/api/vault/reidentify")
async def reidentify(body: ReidentifyRequest, request: Request, x_vault_key: str | None = Header(default=None)):
    _rate_limit(request)
    if not settings.vault_api_key:
        raise HTTPException(403, "Re-identification is disabled (VAULT_API_KEY not set).")
    if not hmac.compare_digest(x_vault_key or "", settings.vault_api_key):
        raise HTTPException(401, "Invalid vault key.")
    if not body.tokens or not all(pipeline.valid_token(v) for v in body.tokens.values()):
        raise HTTPException(400, "Invalid tokens.")
    try:
        values, ms = await vault.reidentify(body.tokens)
    except vault.VaultError as exc:
        raise HTTPException(400, str(exc)) from exc
    pipeline.AUDIT.appendleft({"request_id": "vault", "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                               "outcome": "reidentified", "fields": sorted(values), "total_ms": ms})
    return {"values": values, "ms": ms}


@app.get("/api/posture")
async def get_posture() -> dict:
    return {"checks": await posture.collect()}


@app.get("/api/audit")
async def audit() -> dict:
    return {"events": list(pipeline.AUDIT)[:50]}


@app.get("/api/samples")
async def samples() -> dict:
    items = sorted(p.name for p in SAMPLES.glob("*.png")) if SAMPLES.exists() else []
    return {"samples": [{"name": n, "url": f"/samples/{n}"} for n in items]}


app.mount("/samples", StaticFiles(directory=SAMPLES), name="samples")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(Path(STATIC) / "index.html")
