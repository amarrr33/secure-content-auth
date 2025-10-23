from pathlib import Path
import sys
import json
import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.crypto.keys import gen_rsa_3072
from src.crypto.signature import sign_file, verify_file
from src.pipeline.bind import build_payload
from src.watermark import dct as wm_dct

def make_png(path: Path):
    img = Image.new("RGB", (320, 200), (230, 240, 250))
    img.save(path, "PNG")

def test_sign_verify_ok_and_fail(tmp_path: Path):
    # prepare watermarked file
    img = tmp_path / "in.png"; make_png(img)
    payload = build_payload(img, "Tester", "rsa", {"course":"class"})
    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    out_wm = tmp_path / "out_wm.png"
    wm_dct.embed(img, bits, out_wm)

    priv, pub = gen_rsa_3072()
    sig = sign_file(out_wm, priv, algo="rsa")
    assert verify_file(out_wm, sig, pub, algo="rsa")

    # modify 1 pixel -> signature must fail
    im = Image.open(out_wm).convert("RGB")
    im.putpixel((0,0), (0,0,0))
    tampered = tmp_path / "tampered.png"
    im.save(tampered, "PNG")
    assert not verify_file(tampered, sig, pub, algo="rsa")
