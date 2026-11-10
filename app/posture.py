"""Read-only security posture checks. Nothing here changes project configuration."""

from __future__ import annotations

import asyncio

import httpx

from . import gcp, vault
from .config import settings


async def _get(url: str) -> tuple[int, dict]:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers=gcp.headers(settings.project))
        return resp.status_code, (resp.json() if resp.content else {})
    except (httpx.HTTPError, ValueError):
        return 0, {}


async def _cache_config() -> dict:
    code, body = await _get(f"https://us-central1-aiplatform.googleapis.com/v1/projects/{settings.project}/cacheConfig")
    if code != 200:
        return {"id": "vertex_cache", "label": "Vertex AI data caching", "status": "warn",
                "detail": f"Could not read cacheConfig (HTTP {code})."}
    if body.get("disableCache"):
        return {"id": "vertex_cache", "label": "Vertex AI data caching", "status": "ok",
                "detail": "Caching disabled for the project (zero data retention)."}
    retention = (body.get("retentionConfig") or {}).get("retentionType", "DURABLE")
    return {"id": "vertex_cache", "label": "Vertex AI data caching", "status": "warn",
            "detail": f"Caching on ({retention}). Prompts can be cached up to 24h, project-scoped. "
                      "For zero data retention, disable caching in the production KYC project."}


async def _armor_templates() -> dict:
    loc = settings.armor_location
    base = f"https://modelarmor.{loc}.rep.googleapis.com/v1/projects/{settings.project}/locations/{loc}/templates"
    codes = await asyncio.gather(*[_get(f"{base}/{t}") for t in
                                   (settings.armor_input_template, settings.armor_output_template)])
    ok = all(c == 200 for c, _ in codes)
    mods = (codes[0][1].get("templateMetadata") or {}).get("modalities", []) if ok else []
    return {"id": "model_armor", "label": "Model Armor templates", "status": "ok" if ok else "fail",
            "detail": (f"Input + output templates active in '{loc}' (input modalities: {', '.join(mods) or 'default'}). "
                       f"Fail-closed: {'no' if settings.armor_fail_open else 'yes'}.") if ok
            else "Templates missing. Run scripts/bootstrap_gcp.sh."}


async def _kms() -> dict:
    if not vault.configured():
        return {"id": "kms", "label": "Cloud KMS key for DLP", "status": "fail", "detail": "Not configured."}
    code, body = await _get(f"https://cloudkms.googleapis.com/v1/{settings.dlp_kms_key_name}")
    state = (body.get("primary") or {}).get("state", "UNKNOWN") if code == 200 else f"HTTP {code}"
    rotation = body.get("rotationPeriod", "")
    if rotation.endswith("s") and rotation[:-1].isdigit():
        rotation = f"every {int(rotation[:-1]) // 86400} days"
    rotation = rotation or "not set"
    return {"id": "kms", "label": "Cloud KMS key for DLP", "status": "ok" if state == "ENABLED" else "fail",
            "detail": f"Key {settings.dlp_kms_key_name.split('/')[-1]} is {state}, rotation {rotation}. "
                      "Only the KMS-wrapped data key is stored by the app."}


def _static_checks() -> list[dict]:
    endpoint_ok = settings.gemini_location not in ("global",)
    return [
        {"id": "gemini_endpoint", "label": "Gemini endpoint residency",
         "status": "ok" if endpoint_ok else "warn",
         "detail": (f"{settings.gemini_model} on '{settings.gemini_location}'. "
                    + ("Regional endpoint keeps processing in-region." if endpoint_ok else
                       "The global endpoint can serve from any region. For data residency use the "
                       "'us' or 'eu' multi-region endpoint in production."))},
        {"id": "storage", "label": "Upload persistence", "status": "ok",
         "detail": "Images are processed in memory, re-encoded without EXIF, and never written to disk or storage."},
        {"id": "vault_access", "label": "Re-identification access", "status": "ok" if settings.vault_api_key else "warn",
         "detail": "Re-identification requires the vault key." if settings.vault_api_key else
                   "VAULT_API_KEY is not set, so re-identification is disabled."},
        {"id": "logs", "label": "Application logs", "status": "ok",
         "detail": "Audit log stores image SHA-256, verdicts and timings only. No field values."},
    ]


async def collect() -> list[dict]:
    dynamic = await asyncio.gather(_armor_templates(), _kms(), _cache_config())
    return [*dynamic, *_static_checks()]
