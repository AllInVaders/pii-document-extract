"""Pipeline behaviour with the GCP calls faked: gates, fail-closed paths and the zero-PII output."""

import asyncio
import io
import json

import pytest
from PIL import Image

from app import extractor, model_armor, pipeline, vault
from app.model_armor import ArmorVerdict

SYNTHETIC = {
    "document_number": "41234567", "check_digit": "9", "surnames": "MENDEZ QUISPE",
    "given_names": "CARLOS ALBERTO", "sex": "M", "nationality": "PER", "date_of_birth": "1990-05-14",
    "marital_status": "SOLTERO", "issue_date": "2023-03-20", "expiry_date": "2031-03-20",
    "card_number": "1029384756",
}


def _image() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (1024, 660), (240, 235, 220)).save(buf, "PNG")
    return buf.getvalue()


def _extraction(**overrides):
    fields = {k: {"value": v, "confidence": 0.98, "box_2d": [100, 100, 150, 400]} for k, v in SYNTHETIC.items()}
    data = {"document_type": "PE_DNI", "issuing_country": "PER", "legible": True, "quality_issues": [],
            "contains_instructions": False, "fields": fields,
            "regions": [{"kind": "face_photo", "box_2d": [250, 50, 800, 320]}], "repeated_personal_data": []}
    data.update(overrides)
    return extractor.Extraction(data=data, latency_ms=5, model="fake", location="test", input_tokens=1, output_tokens=1)


@pytest.fixture
def fakes(monkeypatch):
    calls = {"armor_out_text": None}

    async def screen_image(_):
        return ArmorVerdict(blocked=False)

    async def screen_response(text):
        calls["armor_out_text"] = text
        return ArmorVerdict(blocked=False)

    async def extract(_, __):
        return _extraction()

    async def tokenize(values):
        return {k: "tok:" + "QUJD" + str(i) for i, k in enumerate(values) if values[k]}, 1

    monkeypatch.setattr(model_armor, "screen_image", screen_image)
    monkeypatch.setattr(model_armor, "screen_response", screen_response)
    monkeypatch.setattr(extractor, "extract", extract)
    monkeypatch.setattr(vault, "tokenize", tokenize)
    return calls


def test_happy_path_returns_no_cleartext(fakes):
    out = asyncio.run(pipeline.run(_image()))
    assert [s["status"] for s in out["stages"]] == ["pass"] * 8
    blob = json.dumps({k: v for k, v in out.items() if k != "redacted_preview"}).upper()
    for value in ("41234567", "MENDEZ", "QUISPE", "CARLOS", "ALBERTO", "1990-05-14", "1029384756"):
        assert value not in blob, value
    assert out["agent_view"]["kyc_claims"]["document_number_checksum_valid"] is True
    assert set(out["agent_view"]["tokens"]) == set(vault.PII_FIELDS)
    # Model Armor's output screen only ever sees the tokenized agent payload.
    assert "MENDEZ" not in fakes["armor_out_text"]


def test_armor_unavailable_fails_closed(fakes, monkeypatch):
    async def down(_):
        raise model_armor.ArmorUnavailable("timeout")
    monkeypatch.setattr(model_armor, "screen_image", down)
    with pytest.raises(pipeline.PipelineBlocked) as exc:
        asyncio.run(pipeline.run(_image()))
    assert exc.value.status == 503 and exc.value.stage == "model_armor_input"


def test_armor_match_blocks_before_gemini(fakes, monkeypatch):
    called = {"gemini": False}

    async def blocked(_):
        return ArmorVerdict(blocked=True, matched_filters=["pi_and_jailbreak"])

    async def extract(_, __):
        called["gemini"] = True
        return _extraction()

    monkeypatch.setattr(model_armor, "screen_image", blocked)
    monkeypatch.setattr(extractor, "extract", extract)
    with pytest.raises(pipeline.PipelineBlocked) as exc:
        asyncio.run(pipeline.run(_image()))
    assert exc.value.stage == "model_armor_input" and called["gemini"] is False


def test_embedded_instructions_blocked(fakes, monkeypatch):
    async def extract(_, __):
        return _extraction(contains_instructions=True)
    monkeypatch.setattr(extractor, "extract", extract)
    with pytest.raises(pipeline.PipelineBlocked) as exc:
        asyncio.run(pipeline.run(_image()))
    assert exc.value.stage == "instruction_check"


def test_vault_failure_returns_nothing(fakes, monkeypatch):
    async def broken(_):
        raise vault.VaultError("down")
    monkeypatch.setattr(vault, "tokenize", broken)
    with pytest.raises(pipeline.PipelineBlocked) as exc:
        asyncio.run(pipeline.run(_image()))
    assert exc.value.stage == "dlp_kms_tokenize"


def test_leak_guard_trips_on_cleartext(fakes, monkeypatch):
    async def leaky(values):
        return {k: v for k, v in values.items() if v}, 1  # "tokens" that are really cleartext
    monkeypatch.setattr(vault, "tokenize", leaky)
    with pytest.raises(pipeline.PipelineBlocked) as exc:
        asyncio.run(pipeline.run(_image()))
    assert exc.value.stage == "leak_guard"


def test_low_confidence_flags_review(fakes, monkeypatch):
    async def extract(_, __):
        ext = _extraction()
        ext.data["fields"]["surnames"]["confidence"] = 0.4
        return ext
    monkeypatch.setattr(extractor, "extract", extract)
    out = asyncio.run(pipeline.run(_image()))
    assert out["agent_view"]["needs_human_review"] is True
    assert out["agent_view"]["low_confidence_fields"] == ["surnames"]
