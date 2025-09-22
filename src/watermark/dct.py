from __future__ import annotations
from pathlib import Path
import numpy as np
from PIL import Image
from scipy.fftpack import dct, idct

class DCTWatermarkError(Exception):
    pass

BLOCK = 8
ALPHA = 8.0  # tweak for quality vs robustness

def _to_gray(img: Image.Image) -> np.ndarray:
    return np.array(img.convert("L"), dtype=np.float32)

def _from_gray(arr: np.ndarray) -> Image.Image:
    arr = np.clip(arr, 0, 255).astype(np.uint8)
    return Image.fromarray(arr, mode="L").convert("RGB")

def _bytes_to_bits(b: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(b, dtype=np.uint8))

def _bits_to_bytes(bits: np.ndarray) -> bytes:
    pad = (-len(bits)) % 8
    if pad:
        bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)])
    return np.packbits(bits).tobytes()

def embed(image_path: Path, payload_bits: np.ndarray, output_path: Path) -> None:
    """
    Embed bits by modifying mid-frequency DCT coefficients.
    One bit per 8x8 block (therefore capacity ~ (h/8)*(w/8) ).
    payload_bits: numpy array of 0/1
    """
    img = Image.open(image_path)
    Y = _to_gray(img)
    h, w = Y.shape
    if h % BLOCK or w % BLOCK:
        Y = Y[: h - (h % BLOCK), : w - (w % BLOCK)]
        h, w = Y.shape

    num_blocks = (h // BLOCK) * (w // BLOCK)
    if payload_bits.size > num_blocks:
        raise DCTWatermarkError("Payload too large for DCT scheme (one bit per block).")

    k = 0
    Yw = Y.copy()
    for by in range(0, h, BLOCK):
        for bx in range(0, w, BLOCK):
            block = Y[by:by+BLOCK, bx:bx+BLOCK]
            B = dct(dct(block.T, norm='ortho').T, norm='ortho')
            # Use a pair of mid-frequency coefficients
            c1, c2 = (2, 3), (3, 2)
            bit = payload_bits[k] if k < payload_bits.size else 0
            if bit == 1:
                if B[c1] < B[c2]:
                    B[c1] += ALPHA
            else:
                if B[c1] > B[c2]:
                    B[c2] += ALPHA
            block_w = idct(idct(B.T, norm='ortho').T, norm='ortho')
            Yw[by:by+BLOCK, bx:bx+BLOCK] = block_w
            k += 1
            if k >= payload_bits.size:
                break
        if k >= payload_bits.size:
            break

    _from_gray(Yw).save(output_path, format="PNG")

def extract(image_path: Path, num_bits: int) -> np.ndarray:
    """
    Extract num_bits bits from DCT embedding.
    Returns numpy array of 0/1 bits length num_bits.
    """
    img = Image.open(image_path)
    Y = _to_gray(img)
    h, w = Y.shape
    h -= h % BLOCK
    w -= w % BLOCK

    bits = np.zeros(num_bits, dtype=np.uint8)
    k = 0
    for by in range(0, h, BLOCK):
        for bx in range(0, w, BLOCK):
            block = Y[by:by+BLOCK, bx:bx+BLOCK]
            B = dct(dct(block.T, norm='ortho').T, norm='ortho')
            c1, c2 = (2, 3), (3, 2)
            bits[k] = 1 if B[c1] > B[c2] else 0
            k += 1
            if k >= num_bits:
                return bits
    return bits
