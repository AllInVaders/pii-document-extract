import io
from datetime import date

import pytest
from PIL import Image

from app import image_guard, model_armor, redactor, validators, vault


# ---------- validators ----------
def test_reniec_check_digit_synthetic():
    assert validators.reniec_check_digit("41234567") == ("9", "C")
    assert validators.reniec_valid("41234567", "9") is True
    assert validators.reniec_valid("41234567", "0") is False
    assert validators.reniec_valid("4123", "9") is None


def test_split_and_dates():
    assert validators.split_document_number("41234567-9") == ("41234567", "9")
    assert validators.split_document_number("41234567") == ("41234567", "")
    assert validators.parse_date("14 05 1990") == date(1990, 5, 14)
    assert validators.parse_date("1990-05-14") == date(1990, 5, 14)
    assert validators.parse_date("31 02 1990") is None


def test_evaluate_claims():
    fields = {"document_number": "41234567", "check_digit": "9", "date_of_birth": "1990-05-14",
              "issue_date": "2023-03-20", "expiry_date": "2031-03-20"}
    out = validators.evaluate(fields, "PE_DNI", today=date(2026, 11, 10))
    assert out["document_number_checksum_valid"] is True
    assert out["is_adult"] is True and out["age_band"] == "35-44"
    assert out["is_expired"] is False and out["dates_consistent"] is True
    minor = validators.evaluate({**fields, "date_of_birth": "2012-01-01"}, "PE_DNI", today=date(2026, 11, 10))
    assert minor["is_adult"] is False and minor["age_band"] == "<18"


# ---------- image guard ----------
def _jpeg_with_exif() -> bytes:
    img = Image.new("RGB", (320, 200), (200, 180, 160))
    exif = Image.Exif()
    exif[0x010F] = "SyntheticCam"  # Make
    exif[0x0132] = "2026:01:01 00:00:00"  # DateTime
    buf = io.BytesIO()
    img.save(buf, "JPEG", exif=exif.tobytes())
    return buf.getvalue()


def test_image_guard_strips_metadata():
    raw = _jpeg_with_exif()
    clean = image_guard.sanitize(raw, 10_000_000)
    assert clean.metadata_removed is True
    with Image.open(io.BytesIO(clean.data)) as out:
        assert not out.getexif()
        assert "exif" not in out.info
    assert len(clean.sha256) == 64


def test_image_guard_rejects_non_images():
    with pytest.raises(image_guard.ImageRejected):
        image_guard.sanitize(b"%PDF-1.7 not an image", 10_000_000)
    with pytest.raises(image_guard.ImageRejected):
        image_guard.sanitize(b"\x89PNG\r\n\x1a\n" + b"garbage", 10_000_000)
    with pytest.raises(image_guard.ImageRejected):
        image_guard.sanitize(_jpeg_with_exif(), 100)


def test_image_guard_bounds_size():
    big = Image.new("RGB", (5000, 3000), (10, 20, 30))
    buf = io.BytesIO()
    big.save(buf, "PNG")
    clean = image_guard.sanitize(buf.getvalue(), 50_000_000)
    assert max(clean.width, clean.height) <= image_guard.MAX_SIDE
    assert len(clean.data) <= image_guard.TARGET_MAX_BYTES


# ---------- redactor ----------
def _extraction(with_face=True, name_box=True):
    fields = {k: {"value": "", "confidence": 0.0, "box_2d": []} for k in
              ("document_number", "check_digit", "surnames", "given_names", "date_of_birth", "card_number")}
    fields["surnames"] = {"value": "MENDEZ QUISPE", "confidence": 1.0, "box_2d": [100, 100, 200, 500] if name_box else []}
    regions = [{"kind": "face_photo", "box_2d": [300, 50, 900, 300]}] if with_face else []
    return {"document_type": "PE_DNI", "fields": fields, "regions": regions, "repeated_personal_data": []}


def _blank_jpeg() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (1000, 1000), (250, 250, 250)).save(buf, "JPEG")
    return buf.getvalue()


def test_redactor_masks_boxes():
    import base64
    out = redactor.redact(_blank_jpeg(), _extraction())
    assert out["withheld"] is False and out["redacted_boxes"] == 2
    img = Image.open(io.BytesIO(base64.b64decode(out["data_url"].split(",", 1)[1])))
    assert max(img.getpixel((300, 150))) < 60   # inside the surname box
    assert min(img.getpixel((800, 50))) > 200   # untouched area


def test_redactor_withholds_when_coverage_incomplete():
    assert redactor.redact(_blank_jpeg(), _extraction(name_box=False))["withheld"] is True
    assert redactor.redact(_blank_jpeg(), _extraction(with_face=False))["missing"] == ["face_photo"]


# ---------- model armor parsing ----------
def test_model_armor_parse_match_and_clean():
    body = {"sanitizationResult": {"filterMatchState": "MATCH_FOUND", "invocationResult": "SUCCESS", "filterResults": {
        "pi_and_jailbreak": {"piAndJailbreakFilterResult": {"executionState": "EXECUTION_SUCCESS", "matchState": "MATCH_FOUND"}},
        "csam": {"csamFilterFilterResult": {"executionState": "EXECUTION_SUCCESS", "matchState": "NO_MATCH_FOUND"}}}}}
    v = model_armor.parse_result(body)
    assert v.blocked and v.matched_filters == ["pi_and_jailbreak"]
    clean = model_armor.parse_result({"sanitizationResult": {"filterMatchState": "NO_MATCH_FOUND",
                                                             "invocationResult": "SUCCESS", "filterResults": {}}})
    assert not clean.blocked


# ---------- masking ----------
def test_masking_hides_values():
    assert vault.mask("document_number", "41234567-9") == "******67-9"
    assert vault.mask("surnames", "MENDEZ QUISPE") == "M*** Q***"
    assert vault.mask("date_of_birth", "1990-05-14") == "1990-**-**"
    assert vault.mask("card_number", "1029384756") == "******4756"
