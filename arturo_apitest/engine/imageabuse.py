"""Generate API4 resource-abuse image inputs locally (no network).

These are deliberately malformed/oversized inputs for the image parser in
front of the ML models: decompression bomb, pixel flood, polyglot, truncated.
Pillow is optional; if absent, only the byte-level cases are produced.
"""
from __future__ import annotations

import io
import struct
from pathlib import Path


def build(out_dir: str | Path) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    made: dict[str, Path] = {}

    # polyglot: valid tiny JPEG header + HTML tail
    p = out / "polyglot_jpg_html.jpg"
    p.write_bytes(_min_jpeg() + b"<html><script>/*x*/</script></html>")
    made["polyglot_jpg_html"] = p

    # truncated: JPEG SOI only
    p = out / "malformed_truncated.jpg"
    p.write_bytes(b"\xff\xd8\xff\xe0")
    made["malformed_truncated"] = p

    try:
        from PIL import Image  # type: ignore
    except ImportError:
        return made

    # pixel flood: huge declared dimensions, highly compressible content
    p = out / "pixel_flood.png"
    img = Image.new("RGB", (12000, 12000), (255, 255, 255))
    img.save(p, format="PNG", optimize=True)
    made["pixel_flood_png"] = p

    # decompression bomb: large but uniform -> tiny file, huge decode
    p = out / "decompression_bomb.png"
    Image.new("L", (20000, 20000), 0).save(p, format="PNG", optimize=True)
    made["decompression_bomb_png"] = p

    return made


def _min_jpeg() -> bytes:
    # smallest-ish valid JPEG: SOI + APP0 JFIF + EOI
    return (
        b"\xff\xd8"                      # SOI
        b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xff\xd9"                      # EOI
    )
