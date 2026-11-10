"""Live checks against GCP (synthetic images only). Run with: RUN_LIVE=1 pytest tests/test_live.py"""

import asyncio
import os
from pathlib import Path

import pytest

from app import pipeline, vault

pytestmark = pytest.mark.skipif(os.environ.get("RUN_LIVE") != "1", reason="set RUN_LIVE=1 for live GCP tests")
SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


def test_live_synthetic_dni_end_to_end():
    out = asyncio.run(pipeline.run((SAMPLES / "synthetic_pe_dni.png").read_bytes()))
    assert out["agent_view"]["document_type"] == "PE_DNI"
    assert out["agent_view"]["kyc_claims"]["document_number_checksum_valid"] is True
    assert out["redacted_preview"]["withheld"] is False
    values, _ = asyncio.run(vault.reidentify(out["agent_view"]["tokens"]))
    assert values["document_number"] == "41234567-9"
    assert values["surnames"] == "MENDEZ QUISPE"


def test_live_tokens_are_deterministic():
    a, _ = asyncio.run(vault.tokenize({"surnames": "MENDEZ QUISPE"}))
    b, _ = asyncio.run(vault.tokenize({"surnames": "MENDEZ QUISPE"}))
    assert a == b and a["surnames"].startswith("tok:")


def test_live_injection_card_blocked_by_model_armor():
    with pytest.raises(pipeline.PipelineBlocked) as exc:
        asyncio.run(pipeline.run((SAMPLES / "synthetic_pe_dni_injection.png").read_bytes()))
    assert exc.value.stage in {"model_armor_input", "instruction_check"}
