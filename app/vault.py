"""PII vault: Cloud DLP deterministic encryption (AES-SIV) with a Cloud KMS-wrapped key.

Tokens are deterministic (same value -> same token, so systems can join on them) and
reversible only by callers that can use the KMS key through DLP reidentify.
"""

from __future__ import annotations

import re
import time

import httpx

from . import gcp
from .config import settings

TOKEN_PREFIX = "tok:"
PII_FIELDS = ("document_number", "surnames", "given_names", "date_of_birth", "card_number")


class VaultError(RuntimeError):
    """Cloud DLP could not tokenize or re-identify."""


def configured() -> bool:
    return bool(settings.dlp_kms_key_name and settings.dlp_wrapped_key)


def _crypto() -> dict:
    return {
        "cryptoDeterministicConfig": {
            "cryptoKey": {
                "kmsWrapped": {
                    "wrappedKey": settings.dlp_wrapped_key,
                    "cryptoKeyName": settings.dlp_kms_key_name,
                }
            }
        }
    }


def _url(method: str) -> str:
    return f"https://dlp.googleapis.com/v2/projects/{settings.project}/locations/{settings.dlp_location}/content:{method}"


async def _table_call(method: str, values: dict[str, str]) -> tuple[dict[str, str], int]:
    names = list(values)
    cfg_key = "deidentifyConfig" if method == "deidentify" else "reidentifyConfig"
    body = {
        cfg_key: {
            "recordTransformations": {
                "fieldTransformations": [
                    {"fields": [{"name": n} for n in names], "primitiveTransformation": _crypto()}
                ]
            }
        },
        "item": {
            "table": {
                "headers": [{"name": n} for n in names],
                "rows": [{"values": [{"stringValue": values[n]} for n in names]}],
            }
        },
    }
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(_url(method), headers=gcp.headers(settings.project), json=body)
    except httpx.HTTPError as exc:
        raise VaultError(f"DLP {method} unreachable ({type(exc).__name__})") from exc
    if resp.status_code != 200:
        raise VaultError(f"DLP {method} HTTP {resp.status_code}")
    row = resp.json()["item"]["table"]["rows"][0]["values"]
    out = {n: (cell.get("stringValue") or "") for n, cell in zip(names, row)}
    return out, int((time.perf_counter() - started) * 1000)


async def tokenize(values: dict[str, str]) -> tuple[dict[str, str], int]:
    """{'surnames': 'MENDEZ QUISPE'} -> {'surnames': 'tok:AR...'}; empty values are skipped."""
    present = {k: v for k, v in values.items() if v}
    if not present:
        return {}, 0
    if not configured():
        raise VaultError("DLP/KMS vault is not configured (run scripts/bootstrap_gcp.sh)")
    out, ms = await _table_call("deidentify", present)
    return {k: TOKEN_PREFIX + v for k, v in out.items()}, ms


async def reidentify(tokens: dict[str, str]) -> tuple[dict[str, str], int]:
    clean = {}
    for k, v in tokens.items():
        if k not in PII_FIELDS or not isinstance(v, str) or not v.startswith(TOKEN_PREFIX):
            raise VaultError(f"Invalid token for field '{k}'")
        clean[k] = v[len(TOKEN_PREFIX):]
    if not clean:
        return {}, 0
    return await _table_call("reidentify", clean)


def mask(field: str, value: str) -> str:
    """Display masking for the front-office view (never reversible)."""
    if not value:
        return ""
    if field == "document_number":
        digits = re.sub(r"\s", "", value)
        keep = 4 if "-" in digits else 2
        return "*" * max(0, len(digits) - keep) + digits[-keep:]
    if field in ("surnames", "given_names"):
        return " ".join(w[0] + "***" for w in value.split() if w)
    if field == "date_of_birth":
        return value[:4] + "-**-**" if re.match(r"\d{4}-", value) else "**/**/****"
    if field == "card_number":
        return "*" * max(0, len(value) - 4) + value[-4:]
    return value
