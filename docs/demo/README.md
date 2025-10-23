# Demo Assets (For Grading)

This folder holds **demo-only** artifacts created by `scripts/generate_demo_artifacts.py`:

- `demo_public.pem` — public key (safe to share)
- `demo_out_wm.png` — watermarked image (PNG)
- `demo_out_wm.sig.txt` — Base64-encoded signature of the **watermarked** PNG
- `demo_tampered_soft.png` — brightness +1%
- `demo_tampered_crop.png` — 10px border crop
- `demo_tampered_hard.png` — JPEG round-trip → PNG

> No private key is included. Signatures are precomputed for demonstration.
> Regenerate everything with:
>
> ```bash
> python scripts/generate_demo_artifacts.py
> ```