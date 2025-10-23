from pathlib import Path
import sys
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.watermark import lsb as wm_lsb

def make_png(path: Path):
    Image.new("RGB", (200, 140), (240, 240, 240)).save(path, "PNG")

def test_lsb_embed_extract_roundtrip(tmp_path: Path):
    src = tmp_path / "in.png"; make_png(src)
    payload = b'{"k":"v","n":1}'
    outp = tmp_path / "out.png"
    wm_lsb.embed(src, payload, outp)
    raw = wm_lsb.extract(outp)
    assert raw == payload
