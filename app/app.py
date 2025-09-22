# app/app.py
import json
from io import BytesIO
from pathlib import Path
from typing import Optional

import numpy as np
import streamlit as st
from PIL import Image, ImageEnhance  # ImageEnhance unused here but ok to keep

# --- ensure project root on sys.path (so 'src' is importable) ---
import sys
ROOT = Path(__file__).resolve().parents[1]  # project root
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# ---------------------------------------------------------------

from src.crypto.keys import gen_rsa_3072, gen_ecc_p256
from src.crypto.signature import sign_file, verify_file
from src.pipeline.bind import build_payload, parse_payload
from src.watermark import lsb as wm_lsb
from src.watermark import dct as wm_dct

st.set_page_config(page_title="Secure Auth + Watermark", layout="wide")
st.title("🔐 Secure Content Authentication: Signatures + Watermarking")

# -------------------------
# Helpers
# -------------------------
def pil_to_png_bytes(img: Image.Image) -> bytes:
    b = BytesIO()
    img.save(b, "PNG")
    return b.getvalue()

def save_and_show(path: Path, caption: str):
    """Show an image and a download button with a unique key."""
    img = Image.open(path)
    st.image(img, caption=caption, use_container_width=True)
    st.download_button(
        label=f"⬇️ Download {path.name}",
        data=path.read_bytes(),
        file_name=path.name,
        mime="image/png",
        use_container_width=True,
        key=f"dl_{path.name}_{caption}",   # UNIQUE KEY
    )

def verify_and_extract(
    img_path: Path,
    wm_scheme: str,
    bits: int = 512,
    sig_path: Optional[Path] = None,
    pub_path: Optional[Path] = None,
    block_key: str = "",
):
    """Verify signature (if sig+pub provided) and extract watermark."""
    cols = st.columns(3)

    with cols[0]:
        if sig_path and pub_path and sig_path.exists() and pub_path.exists():
            ok = verify_file(
                img_path,
                sig_path.read_bytes(),
                pub_path.read_bytes(),
                algo=st.session_state.get("sig_scheme", "rsa"),
            )
            st.info(f"Verify: {'OK' if ok else 'FAIL'}")
        else:
            st.caption("Signature verify: (need public.pem & .sig)")

    with cols[1]:
        try:
            if wm_scheme == "lsb":
                raw = wm_lsb.extract(img_path)
            else:
                bits_arr = wm_dct.extract(img_path, bits)
                raw = np.packbits(bits_arr).tobytes()
            meta = parse_payload(raw)
            st.code(json.dumps(meta, indent=2))
        except Exception as e:
            st.warning("Watermark not decodable or not JSON.")
            st.caption(str(e))

    with cols[2]:
        st.download_button(
            "⬇️ Download .sig (if exists)",
            data=sig_path.read_bytes() if sig_path and sig_path.exists() else b"",
            file_name=sig_path.name if sig_path else "file.sig",
            disabled=not (sig_path and sig_path.exists()),
            use_container_width=True,
            key=f"dl_sig_{block_key}_{sig_path.name if sig_path else 'none'}",  # UNIQUE KEY
        )

# -------------------------
# Tabs
# -------------------------
tab_keys, tab_flow = st.tabs(["Keys", "Workflow"])

# -------------------------
# 1) KEYS
# -------------------------
with tab_keys:
    st.header("Key Generation")
    scheme = st.selectbox("Signature Scheme", ["rsa", "ecc"], index=0, key="sig_scheme")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Generate Keys"):
            if scheme == "rsa":
                priv, pub = gen_rsa_3072()
            else:
                priv, pub = gen_ecc_p256()
            Path("private.pem").write_bytes(priv)
            Path("public.pem").write_bytes(pub)
            st.success("Keys saved: private.pem, public.pem")
    with c2:
        st.caption("Current: " + ("RSA-3072" if scheme == "rsa" else "ECC P-256"))
        if Path("public.pem").exists():
            st.download_button("⬇️ public.pem", data=Path("public.pem").read_bytes(), file_name="public.pem", key="dl_pub_pem")
        if Path("private.pem").exists():
            st.download_button("⬇️ private.pem", data=Path("private.pem").read_bytes(), file_name="private.pem", key="dl_priv_pem")

# -------------------------
# 2) WORKFLOW
# -------------------------
with tab_flow:
    st.header("Choose Source")
    source_mode = st.radio("Source image", ["Upload PNG", "Camera"], horizontal=True)

    wm_scheme = st.selectbox("Watermark Scheme", ["lsb", "dct"], index=0)
    signer = st.text_input("Signer", value="Bharath")
    extra = st.text_area("Extra JSON (optional)", value='{"project":"SCA"}')

    img_path: Optional[Path] = None

    if source_mode == "Upload PNG":
        up = st.file_uploader("Upload PNG image", type=["png"], key="up_png")
        if up:
            img_path = Path("_input.png")
            img_path.write_bytes(up.read())
            st.image(Image.open(img_path), caption="Uploaded", use_container_width=True)
            st.download_button(
                "⬇️ Download input image",
                data=img_path.read_bytes(),
                file_name=img_path.name,
                use_container_width=True,
                key="dl_input_img"
            )
    else:
        photo = st.camera_input("Take a photo", key="cam_input")
        if photo:
            img_path = Path("_camera.png")
            img_path.write_bytes(photo.read())
            st.image(Image.open(img_path), caption="Captured", use_container_width=True)
            st.download_button(
                "⬇️ Download captured image",
                data=img_path.read_bytes(),
                file_name=img_path.name,
                use_container_width=True,
                key="dl_captured_img"
            )

    if img_path:
        st.divider()
        st.subheader("Embed → Sign → Download")

        c1, c2, c3 = st.columns(3)
        out_png = Path("out_wm.png")
        sig_path = Path("out_wm.sig")

        with c1:
            if st.button("Embed Watermark (out_wm.png)", key="btn_embed"):
                payload = build_payload(
                    img_path,
                    signer,
                    st.session_state.get("sig_scheme", "rsa"),
                    json.loads(extra) if extra.strip() else {},
                )
                if wm_scheme == "lsb":
                    wm_lsb.embed(img_path, payload, out_png)
                else:
                    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
                    wm_dct.embed(img_path, bits, out_png)
                st.success("Watermark embedded → out_wm.png")
                save_and_show(out_png, "Watermarked")

        with c2:
            if st.button("Sign out_wm.png → out_wm.sig", key="btn_sign"):
                if out_png.exists() and Path("private.pem").exists():
                    sig = sign_file(
                        out_png,
                        Path("private.pem").read_bytes(),
                        algo=st.session_state.get("sig_scheme", "rsa"),
                    )
                    sig_path.write_bytes(sig)
                    st.success("Signature created → out_wm.sig")
                    st.download_button(
                        "⬇️ Download out_wm.sig",
                        data=sig_path.read_bytes(),
                        file_name="out_wm.sig",
                        use_container_width=True,
                        key="dl_out_sig"
                    )
                else:
                    st.error("Need out_wm.png and private.pem")

        with c3:
            if out_png.exists():
                st.download_button(
                    "⬇️ Download out_wm.png",
                    data=out_png.read_bytes(),
                    file_name="out_wm.png",
                    use_container_width=True,
                    key="dl_out_png_top"
                )
            else:
                st.caption("Embed first to enable download.")

        # Verify / Extract for base
        if out_png.exists():
            st.markdown("**Verify & Extract (Base)**")
            verify_and_extract(
                out_png,
                wm_scheme,
                sig_path=sig_path if sig_path.exists() else None,
                pub_path=Path("public.pem") if Path("public.pem").exists() else None,
                block_key="base",
            )

        st.divider()
        st.subheader("🧪 Manual Testcases: Upload your edited images and verify")

        with st.expander("Open testcase verifier", expanded=True):
            st.caption("Upload the signature (.sig) created for the original watermarked image, then upload any number of PNG test images you edited (brightness/crop/etc.). We will verify each image with the signature and attempt watermark extraction.")
            up_sig = st.file_uploader("Upload signature (.sig)", type=None, key="tc_sig")
            wm_scheme_tc = st.selectbox("Watermark Scheme used to embed (for extraction)", ["lsb","dct"], index=0, key="tc_scheme")
            tests = st.file_uploader("Upload one or more PNG test images", type=["png"], accept_multiple_files=True, key="tc_imgs")

            # Save the uploaded signature to disk if provided
            tc_sig_path: Optional[Path] = None
            if up_sig:
                tc_sig_path = Path("_tc.sig")
                tc_sig_path.write_bytes(up_sig.read())
                st.success("Signature loaded for testcase verification.")

            # Optional quick verify of baseline if user re-uploads it here
            up_baseline = st.file_uploader("Optional: Upload baseline out_wm.png to sanity-check signature", type=["png"], key="tc_baseline")
            if up_baseline and tc_sig_path:
                p_base = Path("_tc_base.png"); p_base.write_bytes(up_baseline.read())
                st.image(Image.open(p_base), caption="Baseline (from user)", use_container_width=True)
                if Path("public.pem").exists():
                    ok = verify_file(p_base, tc_sig_path.read_bytes(), Path("public.pem").read_bytes(), algo=st.session_state.get("sig_scheme","rsa"))
                    st.info(f"Baseline signature verify: {'OK' if ok else 'FAIL'}")
                else:
                    st.warning("Generate/Upload public.pem first in Keys tab.")

            # Process each test image
            if tests and tc_sig_path:
                st.markdown("---")
                st.subheader("Results per test image")
                for idx, f in enumerate(tests):
                    p = Path(f"_tc_{idx}.png")
                    p.write_bytes(f.read())
                    st.image(Image.open(p), caption=f"Test image {idx+1}: {p.name}", use_container_width=True)

                    # Verify signature against this test image using the provided signature
                    if Path("public.pem").exists():
                        ok = verify_file(p, tc_sig_path.read_bytes(), Path("public.pem").read_bytes(), algo=st.session_state.get("sig_scheme","rsa"))
                        st.write(f"Signature verify: **{'OK' if ok else 'FAIL'}**")
                    else:
                        st.warning("Generate/Upload public.pem first in Keys tab.")

                    # Extract watermark according to selected scheme
                    try:
                        if wm_scheme_tc == "lsb":
                            raw = wm_lsb.extract(p)
                        else:
                            bits_arr = wm_dct.extract(p, 512)
                            raw = np.packbits(bits_arr).tobytes()
                        meta = parse_payload(raw)
                        st.code(json.dumps(meta, indent=2))
                    except Exception as e:
                        st.warning(f"Watermark not decodable or not JSON: {e}")

                    st.download_button(
                        label=f"⬇️ Download this test image ({p.name})",
                        data=p.read_bytes(),
                        file_name=p.name,
                        use_container_width=True,
                        key=f"dl_tc_{idx}"
                    )
                    st.markdown("---")
            elif tests and not up_sig:
                st.warning("Please upload the signature (.sig) created for the original watermarked file.")
