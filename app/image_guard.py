"""Upload hygiene: validate the file type, decode safely, drop all metadata, bound the size.

Re-encoding from raw pixels removes EXIF (GPS coordinates, device serials, timestamps),
ICC profiles and any trailing bytes appended to the file. The output stays in memory.
"""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass

from PIL import Image, ImageOps

Image.MAX_IMAGE_PIXELS = 40_000_000  # decompression-bomb guard

MAX_SIDE = 2400
TARGET_MAX_BYTES = 3_900_000  # Model Armor screens images up to 4 MB

_MAGIC = {
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
}


class ImageRejected(ValueError):
    """The upload is not an acceptable image."""


@dataclass(frozen=True)
class CleanImage:
    data: bytes
    mime_type: str
    width: int
    height: int
    sha256: str
    original_bytes: int
    metadata_removed: bool


def sniff_mime(raw: bytes) -> str:
    for magic, mime in _MAGIC.items():
        if raw.startswith(magic):
            return mime
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "image/webp"
    raise ImageRejected("Only PNG, JPEG or WEBP images are accepted.")


def sanitize(raw: bytes, max_bytes: int) -> CleanImage:
    if not raw:
        raise ImageRejected("Empty upload.")
    if len(raw) > max_bytes:
        raise ImageRejected(f"File is larger than {max_bytes // (1024 * 1024)} MB.")
    sniff_mime(raw)

    try:
        with Image.open(io.BytesIO(raw)) as probe:
            probe.verify()
        with Image.open(io.BytesIO(raw)) as src:
            had_metadata = bool(src.info.get("exif") or src.getexif())
            img = ImageOps.exif_transpose(src).convert("RGB")
    except Image.DecompressionBombError as exc:
        raise ImageRejected("Image dimensions are too large.") from exc
    except ImageRejected:
        raise
    except Exception as exc:  # pylint: disable=broad-exception-caught
        raise ImageRejected("The file could not be decoded as an image.") from exc

    # Fresh image from pixels only: nothing from the original container survives.
    clean = Image.new("RGB", img.size)
    clean.paste(img)
    clean.thumbnail((MAX_SIDE, MAX_SIDE), Image.Resampling.LANCZOS)

    quality = 92
    while True:
        buf = io.BytesIO()
        clean.save(buf, "JPEG", quality=quality, optimize=True)
        data = buf.getvalue()
        if len(data) <= TARGET_MAX_BYTES or quality <= 60:
            break
        quality -= 8

    return CleanImage(
        data=data,
        mime_type="image/jpeg",
        width=clean.width,
        height=clean.height,
        sha256=hashlib.sha256(data).hexdigest(),
        original_bytes=len(raw),
        metadata_removed=had_metadata,
    )
