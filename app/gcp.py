"""Access-token helper: ADC first (Cloud Run / workstation), gcloud CLI as a local fallback."""

from __future__ import annotations

import subprocess
import threading
import time

import google.auth
import google.auth.transport.requests

_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
_lock = threading.Lock()
_cache: dict[str, float | str] = {"token": "", "expires": 0.0}


def access_token() -> str:
    with _lock:
        if _cache["token"] and time.time() < float(_cache["expires"]) - 120:
            return str(_cache["token"])
        token, ttl = _fetch()
        _cache["token"], _cache["expires"] = token, time.time() + ttl
        return token


def _fetch() -> tuple[str, float]:
    try:
        creds, _ = google.auth.default(scopes=_SCOPES)
        creds.refresh(google.auth.transport.requests.Request())
        ttl = (creds.expiry.timestamp() - time.time()) if creds.expiry else 3000
        return creds.token, ttl
    except Exception:  # pylint: disable=broad-exception-caught
        out = subprocess.run(
            ["gcloud", "auth", "print-access-token"],
            check=True, capture_output=True, text=True, timeout=30,
        )
        return out.stdout.strip(), 3000


def headers(project: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token()}",
        "Content-Type": "application/json",
        "x-goog-user-project": project,
    }
