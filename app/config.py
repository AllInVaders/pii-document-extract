"""Runtime configuration. Reads .env.local (gitignored) without overriding real env vars."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


_load_env_file(ROOT / ".env.local")


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    project: str = os.environ.get("GOOGLE_CLOUD_PROJECT", "")

    # Gemini (multimodal extractor)
    gemini_model: str = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")
    gemini_location: str = os.environ.get("GEMINI_LOCATION", "global")
    gemini_thinking_level: str = os.environ.get("GEMINI_THINKING_LEVEL", "low")

    # Model Armor
    armor_location: str = os.environ.get("MODEL_ARMOR_LOCATION", "us")
    armor_input_template: str = os.environ.get("MODEL_ARMOR_INPUT_TEMPLATE", "secure-id-input")
    armor_output_template: str = os.environ.get("MODEL_ARMOR_OUTPUT_TEMPLATE", "secure-id-output")
    armor_fail_open: bool = _bool("MODEL_ARMOR_FAIL_OPEN", False)

    # Cloud DLP + KMS
    dlp_location: str = os.environ.get("DLP_LOCATION", "us-central1")
    dlp_kms_key_name: str = os.environ.get("DLP_KMS_KEY_NAME", "")
    dlp_wrapped_key: str = os.environ.get("DLP_WRAPPED_KEY", "")

    # API protection
    api_key: str = os.environ.get("API_KEY", "")
    vault_api_key: str = os.environ.get("VAULT_API_KEY", "")
    rate_limit_rpm: int = int(os.environ.get("RATE_LIMIT_RPM", "30"))
    max_upload_bytes: int = int(os.environ.get("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))


settings = Settings()
