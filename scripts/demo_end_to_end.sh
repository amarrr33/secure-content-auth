#!/usr/bin/env bash
set -euo pipefail
IMG=${1:-sample_data/sample_image.png}
# 1) gen keys (rsa)
python -m src.cli genkeys --scheme rsa
# 2) embed watermark into image
python -m src.cli embed "$IMG" --scheme lsb --signer "Amar" --algo rsa --out out_wm.png --extra '{"purpose":"demo"}'
# 3) sign the watermarked image
python -m src.cli sign out_wm.png --algo rsa --out out_wm.sig
# 4) verify
python -m src.cli verify out_wm.png --algo rsa --sig out_wm.sig
# 5) extract watermark
python -m src.cli extract out_wm.png --scheme lsb
