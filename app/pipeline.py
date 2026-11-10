"""Orchestrates the secure extraction flow and builds role-scoped outputs.

Cleartext entity values only live inside `run()` and are dropped once tokenized.
Nothing in this module logs field values.
"""

from __future__ import annotations

import collections
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import extractor, image_guard, model_armor, redactor, validators, vault
from .config import settings

AUDIT: collections.deque = collections.deque(maxlen=200)


class PipelineBlocked(Exception):
    """A security gate stopped the request. `stage` and `reason` are safe to show."""

    def __init__(self, stage: str, reason: str, stages: list[dict], status: int = 422):
        super().__init__(reason)
        self.stage, self.reason, self.stages, self.status = stage, reason, stages, status


@dataclass
class _Trace:
    stages: list[dict] = field(default_factory=list)

    def add(self, name: str, status: str, ms: int, **detail) -> None:
        self.stages.append({"name": name, "status": status, "ms": ms, **detail})


def _sensitive_strings(values: dict[str, str]) -> list[str]:
    """All the cleartext forms a leak could take (used by the leak guard)."""
    out: set[str] = set()
    for key, value in values.items():
        if not value or len(value) < 4:
            continue
        out.add(value.upper())
        if key == "document_number":
            number, _ = validators.split_document_number(value)
            if len(number) >= 6:
                out.add(number)
        if key == "date_of_birth":
            d = validators.parse_date(value)
            if d:
                out.update({d.isoformat(), d.strftime("%d %m %Y"), d.strftime("%d/%m/%Y")})
        if key in ("surnames", "given_names"):
            out.update(w for w in value.upper().split() if len(w) >= 4)
    return sorted(out)


def leak_check(payload: dict, sensitive: list[str]) -> list[str]:
    blob = json.dumps(payload, ensure_ascii=False).upper()
    return [s for s in sensitive if s in blob]


def _ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)


async def run(raw: bytes) -> dict:
    trace = _Trace()
    request_id = uuid.uuid4().hex[:12]
    t_total = time.perf_counter()

    # 1. Upload hygiene ---------------------------------------------------------
    t = time.perf_counter()
    try:
        img = image_guard.sanitize(raw, settings.max_upload_bytes)
    except image_guard.ImageRejected as exc:
        trace.add("image_guard", "blocked", _ms(t), reason=str(exc))
        _audit(request_id, None, "rejected_upload", trace, t_total)
        raise PipelineBlocked("image_guard", str(exc), trace.stages, 400) from exc
    trace.add("image_guard", "pass", _ms(t), width=img.width, height=img.height,
              metadata_removed=img.metadata_removed, bytes_in=img.original_bytes, bytes_out=len(img.data))

    # 2. Model Armor on the image (fail-closed) ---------------------------------
    try:
        verdict = await model_armor.screen_image(img.data)
    except model_armor.ArmorUnavailable as exc:
        trace.add("model_armor_input", "error", 0, reason="Model Armor unavailable, request rejected (fail-closed)")
        _audit(request_id, img.sha256, "armor_unavailable", trace, t_total)
        raise PipelineBlocked("model_armor_input", "Security screening unavailable. Request rejected.",
                              trace.stages, 503) from exc
    if verdict.blocked:
        trace.add("model_armor_input", "blocked", verdict.latency_ms, **verdict.as_dict())
        _audit(request_id, img.sha256, "blocked_input", trace, t_total)
        raise PipelineBlocked("model_armor_input",
                              f"Image blocked by Model Armor: {', '.join(verdict.matched_filters)}", trace.stages)
    trace.add("model_armor_input", "pass", verdict.latency_ms, **verdict.as_dict())

    # 3. Multimodal extraction ---------------------------------------------------
    try:
        ext = await extractor.extract(img.data, img.mime_type)
    except extractor.ExtractionError as exc:
        trace.add("gemini_extract", "error", 0, reason=str(exc))
        _audit(request_id, img.sha256, "extraction_failed", trace, t_total)
        raise PipelineBlocked("gemini_extract", str(exc), trace.stages, 502) from exc
    data = ext.data
    trace.add("gemini_extract", "pass", ext.latency_ms, model=ext.model, location=ext.location,
              input_tokens=ext.input_tokens, output_tokens=ext.output_tokens)

    if data["contains_instructions"]:
        # Second, independent injection signal from the extractor itself.
        trace.add("instruction_check", "blocked", 0, reason="Document contains text addressed to an AI system")
        _audit(request_id, img.sha256, "blocked_instructions", trace, t_total)
        raise PipelineBlocked("instruction_check", "The document contains embedded instructions. Rejected.",
                              trace.stages)
    if data["document_type"] == "NOT_AN_ID":
        trace.add("document_check", "blocked", 0, reason="Not an identity document")
        _audit(request_id, img.sha256, "not_an_id", trace, t_total)
        raise PipelineBlocked("document_check", "The image is not an identity document.", trace.stages)

    fields = {k: v["value"] for k, v in data["fields"].items()}
    number, check = validators.split_document_number(fields["document_number"])
    fields["document_number"] = number
    fields["check_digit"] = fields["check_digit"] or check
    full_number = f"{number}-{fields['check_digit']}" if number and fields["check_digit"] else number

    # 4. Deterministic validation --------------------------------------------------
    t = time.perf_counter()
    claims = validators.evaluate(fields, data["document_type"])
    trace.add("validators", "pass", _ms(t))

    # 5. Redacted preview -----------------------------------------------------------
    t = time.perf_counter()
    preview = redactor.redact(img.data, data)
    trace.add("redaction", "withheld" if preview["withheld"] else "pass", _ms(t),
              boxes=preview["redacted_boxes"], missing=preview["missing"])

    # 6. Tokenize every PII value (Cloud DLP + KMS) -----------------------------------
    pii_values = {
        "document_number": full_number,
        "surnames": fields["surnames"],
        "given_names": fields["given_names"],
        "date_of_birth": fields["date_of_birth"],
        "card_number": fields["card_number"],
    }
    try:
        tokens, dlp_ms = await vault.tokenize(pii_values)
    except vault.VaultError as exc:
        trace.add("dlp_kms_tokenize", "error", 0, reason=str(exc))
        _audit(request_id, img.sha256, "vault_failed", trace, t_total)
        raise PipelineBlocked("dlp_kms_tokenize", "Tokenization failed. No data returned.", trace.stages, 503) from exc
    trace.add("dlp_kms_tokenize", "pass", dlp_ms, fields_tokenized=len(tokens))

    confidence = {k: v["confidence"] for k, v in data["fields"].items() if v["value"]}
    low_conf = sorted(k for k, c in confidence.items() if c < 0.8)

    agent_view = {
        "document_type": data["document_type"],
        "issuing_country": data["issuing_country"],
        "nationality": fields["nationality"],
        "expiry_date": fields["expiry_date"],
        "tokens": tokens,
        "kyc_claims": claims,
        "needs_human_review": bool(low_conf) or not data["legible"] or claims.get("document_number_checksum_valid") is False,
        "low_confidence_fields": low_conf,
    }
    banker_view = {
        "masked": {k: vault.mask(k, v) for k, v in pii_values.items() if v},
        "attributes": {
            "sex": fields["sex"],
            "nationality": fields["nationality"],
            "marital_status": fields["marital_status"],
            "issue_date": fields["issue_date"],
            "expiry_date": fields["expiry_date"],
        },
        "confidence": confidence,
        "quality_issues": data["quality_issues"],
        "legible": data["legible"],
    }

    # 7. Output gates: exact-match leak guard + Model Armor response screening ------------
    sensitive = _sensitive_strings(pii_values)
    leaks = leak_check({"agent": agent_view, "banker": banker_view}, sensitive)
    if leaks:
        trace.add("leak_guard", "blocked", 0, reason=f"{len(leaks)} cleartext value(s) found in output")
        _audit(request_id, img.sha256, "leak_guard", trace, t_total)
        raise PipelineBlocked("leak_guard", "Output contained cleartext PII. Blocked.", trace.stages, 500)
    trace.add("leak_guard", "pass", 0, checked_strings=len(sensitive))

    try:
        out_verdict = await model_armor.screen_response(json.dumps(agent_view, ensure_ascii=False))
    except model_armor.ArmorUnavailable as exc:
        trace.add("model_armor_output", "error", 0, reason="Model Armor unavailable, response withheld (fail-closed)")
        _audit(request_id, img.sha256, "armor_unavailable", trace, t_total)
        raise PipelineBlocked("model_armor_output", "Security screening unavailable. Response withheld.",
                              trace.stages, 503) from exc
    if out_verdict.blocked:
        trace.add("model_armor_output", "blocked", out_verdict.latency_ms, **out_verdict.as_dict())
        _audit(request_id, img.sha256, "blocked_output", trace, t_total)
        raise PipelineBlocked("model_armor_output", "Response blocked by Model Armor.", trace.stages)
    trace.add("model_armor_output", "pass", out_verdict.latency_ms, **out_verdict.as_dict())

    # Drop cleartext references before returning.
    del fields, pii_values, sensitive

    total_ms = _ms(t_total)
    _audit(request_id, img.sha256, "ok", trace, t_total, document_type=data["document_type"],
           fields_tokenized=len(tokens), kyc_claims=claims)
    return {
        "request_id": request_id,
        "total_ms": total_ms,
        "stages": trace.stages,
        "agent_view": agent_view,
        "banker_view": banker_view,
        "redacted_preview": preview,
        "image_sha256": img.sha256,
    }


def _audit(request_id: str, sha: str | None, outcome: str, trace: _Trace, t_total: float, **extra) -> None:
    """PII-free audit record: hashes, verdicts and timings only."""
    AUDIT.appendleft({
        "request_id": request_id,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "outcome": outcome,
        "image_sha256": sha,
        "total_ms": _ms(t_total),
        "stages": [{"name": s["name"], "status": s["status"], "ms": s["ms"]} for s in trace.stages],
        **extra,
    })


_TOKEN_RE = re.compile(r"^tok:[A-Za-z0-9+/=]+$")


def valid_token(value: str) -> bool:
    return bool(_TOKEN_RE.match(value or ""))
