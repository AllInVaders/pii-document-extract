"""Model Armor gate. Explicit REST calls so the gate is fail-closed (the native Vertex
floor-setting integration fails open when Model Armor is unreachable)."""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field

import httpx

from . import gcp
from .config import settings


class ArmorUnavailable(RuntimeError):
    """Model Armor could not give a verdict."""


@dataclass
class ArmorVerdict:
    blocked: bool
    matched_filters: list[str] = field(default_factory=list)
    filters: dict[str, str] = field(default_factory=dict)
    invocation: str = "SUCCESS"
    latency_ms: int = 0
    skipped: bool = False

    def as_dict(self) -> dict:
        return {
            "blocked": self.blocked,
            "matched_filters": self.matched_filters,
            "filters": self.filters,
            "invocation": self.invocation,
            "latency_ms": self.latency_ms,
            "skipped": self.skipped,
        }


_FILTER_KEYS = {
    "pi_and_jailbreak": "piAndJailbreakFilterResult",
    "malicious_uris": "maliciousUriFilterResult",
    "rai": "raiFilterResult",
    "csam": "csamFilterFilterResult",
}


def parse_result(body: dict) -> ArmorVerdict:
    result = body.get("sanitizationResult", {})
    invocation = result.get("invocationResult", "UNKNOWN")
    filters: dict[str, str] = {}
    matched: list[str] = []
    for name, wrapper in (result.get("filterResults") or {}).items():
        state = "UNKNOWN"
        inner_key = _FILTER_KEYS.get(name)
        if inner_key and inner_key in wrapper:
            inner = wrapper[inner_key]
            state = inner.get("matchState", "UNKNOWN")
            if inner.get("executionState") == "EXECUTION_SKIPPED":
                state = "SKIPPED"
        elif name == "sdp":
            sdp = wrapper.get("sdpFilterResult", {})
            inner = sdp.get("inspectResult") or sdp.get("deidentifyResult") or sdp.get("redactResult") or {}
            state = inner.get("matchState", "UNKNOWN")
        filters[name] = state
        if state == "MATCH_FOUND":
            matched.append(name)
    blocked = result.get("filterMatchState") == "MATCH_FOUND" or bool(matched)
    return ArmorVerdict(blocked=blocked, matched_filters=matched, filters=filters, invocation=invocation)


def _url(template: str, method: str) -> str:
    loc = settings.armor_location
    return (
        f"https://modelarmor.{loc}.rep.googleapis.com/v1/projects/{settings.project}"
        f"/locations/{loc}/templates/{template}:{method}"
    )


async def _call(template: str, method: str, payload: dict) -> ArmorVerdict:
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(_url(template, method), headers=gcp.headers(settings.project), json=payload)
        if resp.status_code != 200:
            raise ArmorUnavailable(f"Model Armor HTTP {resp.status_code}")
        verdict = parse_result(resp.json())
    except (httpx.HTTPError, ArmorUnavailable) as exc:
        if settings.armor_fail_open:
            return ArmorVerdict(blocked=False, invocation=f"FAIL_OPEN: {type(exc).__name__}",
                                latency_ms=int((time.perf_counter() - started) * 1000), skipped=True)
        raise ArmorUnavailable(str(exc)) from exc

    verdict.latency_ms = int((time.perf_counter() - started) * 1000)
    if verdict.invocation != "SUCCESS" and not settings.armor_fail_open:
        # A partial or failed scan is not a pass.
        raise ArmorUnavailable(f"Model Armor invocation {verdict.invocation}")
    return verdict


async def screen_image(image: bytes) -> ArmorVerdict:
    """Screens the uploaded image. Model Armor OCRs the text inside it and applies the
    prompt-injection, malicious-URL, RAI and CSAM filters. One image per request, <= 4 MB."""
    payload = {"userPromptData": {"byteItem": {"byteDataType": "IMAGE",
                                               "byteData": base64.b64encode(image).decode()}}}
    return await _call(settings.armor_input_template, "sanitizeUserPrompt", payload)


async def screen_text(text: str) -> ArmorVerdict:
    return await _call(settings.armor_input_template, "sanitizeUserPrompt", {"userPromptData": {"text": text}})


async def screen_response(text: str) -> ArmorVerdict:
    return await _call(settings.armor_output_template, "sanitizeModelResponse", {"modelResponseData": {"text": text}})
