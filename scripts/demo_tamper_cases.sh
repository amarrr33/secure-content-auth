#!/usr/bin/env bash
set -euo pipefail
IMG=${1:-out_wm.png}
# Make a mild edit (brightness +1%)
python - <<'PY'
from PIL import Image, ImageEnhance
im = Image.open(''''${IMG}''''').convert('RGB')
im = ImageEnhance.Brightness(im).enhance(1.01)
im.save('tampered_soft.png', format='PNG')
PY

echo "Signature verify (should FAIL):"
python -m src.cli verify tampered_soft.png --algo rsa --sig out_wm.sig || true

echo "DCT extract (maybe OK if DCT used):"
python -m src.cli extract tampered_soft.png --scheme dct --bits 512 || true

# Aggressive tamper via JPEG roundtrip
python - <<'PY'
from PIL import Image
im = Image.open(''''${IMG}''''').convert('RGB')
im.save('lossy.jpg', quality=80)
Image.open('lossy.jpg').save('tampered_hard.png', format='PNG')
PY

echo "Signature verify on tampered_hard (should FAIL):"
python -m src.cli verify tampered_hard.png --algo rsa --sig out_wm.sig || true

echo "LSB extract (likely FAIL):"
python -m src.cli extract tampered_hard.png --scheme lsb || true

echo "DCT extract (may or may not succeed depending on strength):"
python -m src.cli extract tampered_hard.png --scheme dct --bits 512 || true
