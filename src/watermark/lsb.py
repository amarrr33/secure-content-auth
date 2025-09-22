from __future__ import annotations
from pathlib import Path
import numpy as np
from PIL import Image

class WatermarkError(Exception):
    pass

HEADER_BITS = 32  # payload length (bytes), little-endian

def _ensure_png(path: Path):
    if path.suffix.lower() != ".png":
        raise WatermarkError("Use PNG (lossless) for LSB watermarking.")

def _bytes_to_bits(b: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(b, dtype=np.uint8))

def _bits_to_bytes(bits: np.ndarray) -> bytes:
    pad = (-len(bits)) % 8
    if pad:
        bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)])
    return np.packbits(bits).tobytes()

def _i32le(n: int) -> bytes:
    return int(n).to_bytes(4, "little")

def _u32le(b: bytes) -> int:
    return int.from_bytes(b, "little")

def embed(image_path: Path, payload: bytes, output_path: Path) -> None:
    """
    Embed payload (bytes) into LSB of blue channel of PNG image.
    Header: 4 bytes (little-endian) length of payload in bytes.
    """
    _ensure_png(image_path)
    img = Image.open(image_path).convert("RGB")
    arr = np.array(img)
    blue = arr[:, :, 2].copy()

    header = _i32le(len(payload))
    bits = _bytes_to_bits(header + payload)

    if bits.size > blue.size:
        raise WatermarkError("Insufficient capacity; larger image or smaller payload needed.")

    flat = blue.flatten()
    flat[: bits.size] = (flat[: bits.size] & ~1) | bits
    arr[:, :, 2] = flat.reshape(blue.shape)

    Image.fromarray(arr, "RGB").save(output_path, format="PNG")

def extract(image_path: Path) -> bytes:
    _ensure_png(image_path)
    img = Image.open(image_path).convert("RGB")
    arr = np.array(img)
    flat = arr[:, :, 2].flatten()

    hdr_bits = flat[:HEADER_BITS] & 1
    hdr = _bits_to_bytes(hdr_bits)
    n = _u32le(hdr)

    data_bits = flat[HEADER_BITS : HEADER_BITS + n * 8] & 1
    if data_bits.size < n * 8:
        raise WatermarkError("Truncated watermark payload.")
    return _bits_to_bytes(data_bits)[:n]
