"""Builds the redacted preview from the boxes Gemini returned. Solid fills only (no blur or
pixelation, which can be partially reversed)."""

from __future__ import annotations

import base64
import io

from PIL import Image, ImageDraw

REDACT_FIELDS = ("document_number", "check_digit", "surnames", "given_names", "date_of_birth", "card_number")
FILL = (31, 31, 31)


def _to_px(box: list[int], w: int, h: int, pad: float) -> tuple[int, int, int, int]:
    y0, x0, y1, x1 = box
    px, py = int(w * pad), int(h * pad)
    return (
        max(0, int(x0 / 1000 * w) - px),
        max(0, int(y0 / 1000 * h) - py),
        min(w, int(x1 / 1000 * w) + px),
        min(h, int(y1 / 1000 * h) + py),
    )


def redact(image: bytes, extraction: dict) -> dict:
    """Returns the redacted JPEG (data URL) or withholds it when coverage is incomplete."""
    fields = extraction["fields"]
    boxes: list[tuple[str, list[int], float]] = []
    missing: list[str] = []

    for name in REDACT_FIELDS:
        f = fields.get(name, {})
        if not f.get("value"):
            continue
        if f.get("box_2d"):
            boxes.append((name, f["box_2d"], 0.012))
        else:
            missing.append(name)
    for region in extraction["regions"]:
        boxes.append((region["kind"], region["box_2d"], 0.01))
    for rep in extraction["repeated_personal_data"]:
        boxes.append(("repeated", rep["box_2d"], 0.01))

    has_face = any(r["kind"] == "face_photo" for r in extraction["regions"])
    is_id = extraction["document_type"] != "NOT_AN_ID"
    if is_id and not has_face:
        missing.append("face_photo")

    if missing:
        # Fail closed: a preview with an unmasked name or face is worse than no preview.
        return {"withheld": True, "missing": missing, "redacted_boxes": 0, "data_url": None}

    with Image.open(io.BytesIO(image)) as src:
        img = src.convert("RGB")
    draw = ImageDraw.Draw(img)
    for _, box, pad in boxes:
        draw.rectangle(_to_px(box, img.width, img.height, pad), fill=FILL)

    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=85)
    return {
        "withheld": False,
        "missing": [],
        "redacted_boxes": len(boxes),
        "data_url": "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode(),
    }
