#!/usr/bin/env python3
"""
Generate demo assets under docs/demo/:
- demo_public.pem
- demo_out_wm.png
- demo_out_wm.sig.txt (Base64)
- demo_tampered_soft.png, demo_tampered_crop.png, demo_tampered_hard.png
"""
import base64
import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageEnhance
import numpy as np

# Make src importable when run from repo root
import sys
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.crypto.keys import gen_rsa_3072
from src.crypto.signature import sign_file
from src.pipeline.bind import build_payload
from src.watermark import dct as wm_dct  # use DCT for robustness

DEMO_DIR = ROOT / "docs" / "demo"
DEMO_DIR.mkdir(parents=True, exist_ok=True)

def make_sample_png(path: Path):
    im = Image.new("RGB", (880, 520), (244, 246, 255))
    d = ImageDraw.Draw(im)
    d.text((24, 24), "Secure Content Authentication", fill=(10,10,10))
    d.text((24, 64), "Digital Signatures + Watermarking (DCT)", fill=(20,20,20))
    d.text((24, 104), "Demo image for grading", fill=(30,30,30))
    im.save(path, "PNG")

def write_b64_sig(sig_bytes: bytes, path: Path):
    path.write_text(base64.b64encode(sig_bytes).decode("ascii"))

def main():
    # 0) sample input
    sample = DEMO_DIR / "demo_input.png"
    make_sample_png(sample)

    # 1) demo keys (RSA). We only ship public key; private stays ephemeral
    priv_pem, pub_pem = gen_rsa_3072()
    (DEMO_DIR / "demo_public.pem").write_bytes(pub_pem)

    # 2) embed watermark payload using DCT
    out_wm = DEMO_DIR / "demo_out_wm.png"
    payload = build_payload(sample, signer="DemoUser", algo="rsa", extra={"project": "SCA-Demo"})
    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    wm_dct.embed(sample, bits, out_wm)

    # 3) sign the watermarked file with the ephemeral private key
    sig = sign_file(out_wm, priv_pem, algo="rsa")
    write_b64_sig(sig, DEMO_DIR / "demo_out_wm.sig.txt")

    # 4) generate tampered variants
    im = Image.open(out_wm).convert("RGB")
    # soft brightness
    ImageEnhance.Brightness(im).enhance(1.01).save(DEMO_DIR / "demo_tampered_soft.png", "PNG")
    # crop border
    w, h = im.size
    im.crop((10, 10, w - 10, h - 10)).save(DEMO_DIR / "demo_tampered_crop.png", "PNG")
    # jpeg round-trip
    tmp_jpg = DEMO_DIR / "_tmp.jpg"
    im.save(tmp_jpg, "JPEG", quality=80)
    Image.open(tmp_jpg).save(DEMO_DIR / "demo_tampered_hard.png", "PNG")
    tmp_jpg.unlink(missing_ok=True)

    print("✅ Demo assets generated in docs/demo/")
    for f in ["demo_public.pem", "demo_out_wm.png", "demo_out_wm.sig.txt",
              "demo_tampered_soft.png", "demo_tampered_crop.png", "demo_tampered_hard.png"]:
        print(" -", f)

if __name__ == "__main__":
    main()
