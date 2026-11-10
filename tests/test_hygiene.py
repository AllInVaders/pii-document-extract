"""Repository hygiene: only synthetic identity data may be committed."""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SYNTHETIC_DNIS = {"41234567"}
ALLOWED_IMAGES = {"data/samples/synthetic_pe_dni.png", "data/samples/synthetic_pe_dni_injection.png"}
TEXT_SUFFIXES = {".py", ".js", ".html", ".css", ".md", ".sh", ".txt", ".toml", ".json", ".yaml", ".yml", ""}


def _repo_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    return [ROOT / p for p in out]


def test_only_synthetic_images_in_repo():
    images = {str(p.relative_to(ROOT)) for p in _repo_files()
              if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp", ".heic", ".pdf"}}
    # UI screenshots in docs/ are captured from the synthetic samples only.
    unexpected = {p for p in images - ALLOWED_IMAGES if not p.startswith("docs/screenshots/")}
    assert not unexpected, f"Unexpected document images: {unexpected}"


def test_no_unknown_dni_numbers_in_text():
    pattern = re.compile(r"(?<!\d)(\d{8})-[0-9A-Z](?![0-9A-Za-z])")
    offenders = []
    for path in _repo_files():
        if path.suffix not in TEXT_SUFFIXES or not path.is_file():
            continue
        for match in pattern.finditer(path.read_text(errors="ignore")):
            if match.group(1) not in SYNTHETIC_DNIS:
                offenders.append(f"{path.relative_to(ROOT)}: {match.group(0)}")
    assert not offenders, offenders


def test_secrets_are_ignored():
    check = subprocess.run(["git", "check-ignore", ".env.local", ".local_samples/x.png"],
                           cwd=ROOT, capture_output=True, text=True)
    assert ".env.local" in check.stdout and ".local_samples/x.png" in check.stdout
    tracked = {str(p.relative_to(ROOT)) for p in _repo_files()}
    assert not any(p.startswith(".env") and p != ".env.example" for p in tracked)


CREDENTIAL_PATTERNS = {
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "oauth_access_token": re.compile(r"ya29\.[0-9A-Za-z_\-]{20,}"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "service_account_json": re.compile(r'"type"\s*:\s*"service_account"'),
    "kms_ciphertext": re.compile(r"CiQA[0-9A-Za-z+/]{40,}"),
    "github_token": re.compile(r"gh[pousr]_[0-9A-Za-z]{30,}"),
}


def test_no_credentials_in_repo():
    offenders = []
    for path in _repo_files():
        if path.suffix not in TEXT_SUFFIXES or not path.is_file():
            continue
        text = path.read_text(errors="ignore")
        for name, pattern in CREDENTIAL_PATTERNS.items():
            if pattern.search(text):
                offenders.append(f"{path.relative_to(ROOT)}: {name}")
    assert not offenders, offenders
