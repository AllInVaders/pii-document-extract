"""Deterministic checks. The LLM reads the card; plain code decides validity."""

from __future__ import annotations

import re
from datetime import date

_RENIEC_WEIGHTS = (3, 2, 7, 6, 5, 4, 3, 2)
_RENIEC_NUMERIC = "67890112345"
_RENIEC_ALPHA = "KABCDEFGHIJ"


def reniec_check_digit(dni: str) -> tuple[str, str]:
    """Returns the (numeric, alphabetic) RENIEC check characters for an 8-digit DNI."""
    if not re.fullmatch(r"\d{8}", dni or ""):
        raise ValueError("DNI must have exactly 8 digits")
    total = sum(int(d) * w for d, w in zip(dni, _RENIEC_WEIGHTS))
    key = 11 - (total % 11)
    index = 0 if key == 11 else key
    return _RENIEC_NUMERIC[index], _RENIEC_ALPHA[index]


def reniec_valid(dni: str, check: str) -> bool | None:
    """True/False when both parts are readable, None when the check cannot be evaluated."""
    dni = re.sub(r"\D", "", dni or "")
    check = (check or "").strip().upper()
    if len(dni) != 8 or len(check) != 1:
        return None
    return check in reniec_check_digit(dni)


def split_document_number(raw: str) -> tuple[str, str]:
    """'41234567-9' -> ('41234567', '9'); '41234567' -> ('41234567', '')."""
    raw = (raw or "").strip().upper()
    m = re.fullmatch(r"(\d{8})\s*-?\s*([0-9A-Z])?", raw)
    if not m:
        return re.sub(r"[^0-9A-Z]", "", raw), ""
    return m.group(1), m.group(2) or ""


def parse_date(raw: str) -> date | None:
    """Accepts YYYY-MM-DD, DD MM YYYY, DD/MM/YYYY or DD.MM.YYYY."""
    raw = (raw or "").strip()
    if not raw:
        return None
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", raw)
    try:
        if m:
            return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        m = re.fullmatch(r"(\d{1,2})[\s/.\-]+(\d{1,2})[\s/.\-]+(\d{4})", raw)
        if m:
            return date(int(m.group(3)), int(m.group(2)), int(m.group(1)))
    except ValueError:
        return None
    return None


def age_on(dob: date, today: date) -> int:
    return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))


def age_band(age: int) -> str:
    if age < 18:
        return "<18"
    for lo, hi in ((18, 24), (25, 34), (35, 44), (45, 54), (55, 64)):
        if lo <= age <= hi:
            return f"{lo}-{hi}"
    return "65+"


def evaluate(fields: dict[str, str], doc_type: str, today: date | None = None) -> dict:
    """Builds the boolean KYC claims that downstream systems are allowed to see."""
    today = today or date.today()
    out: dict = {"checked_on": today.isoformat()}

    number, check = split_document_number(fields.get("document_number", ""))
    check = fields.get("check_digit", "") or check
    if doc_type == "PE_DNI":
        out["document_number_checksum_valid"] = reniec_valid(number, check)
    else:
        out["document_number_checksum_valid"] = None

    dob = parse_date(fields.get("date_of_birth", ""))
    expiry = parse_date(fields.get("expiry_date", ""))
    issue = parse_date(fields.get("issue_date", ""))

    if dob:
        age = age_on(dob, today)
        out["is_adult"] = age >= 18
        out["age_band"] = age_band(age)
    else:
        out["is_adult"] = None
        out["age_band"] = None

    out["is_expired"] = (expiry < today) if expiry else None
    out["dates_consistent"] = (
        bool(dob and issue and expiry and dob < issue < expiry) if (dob and issue and expiry) else None
    )
    return out
