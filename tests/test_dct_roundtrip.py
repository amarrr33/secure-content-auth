from pathlib import Path
import sys
import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.watermark import dct as wm_dct

def make_png(path: Path):
    Image.new("RGB", (256, 256), (250, 250, 250)).save(path, "PNG")

def test_dct_embed_extract_roundtrip(tmp_path: Path):
    src = tmp_path / "in.png"; make_png(src)
    payload = b"hello dct payload"
    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    outp = tmp_path / "out.png"
    wm_dct.embed(src, bits, outp)

    bits_out = wm_dct.extract(outp, len(bits))
    raw = np.packbits(bits_out).tobytes()[: len(payload)]
    assert raw == payload
