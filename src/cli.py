from __future__ import annotations
import json
from pathlib import Path
import click
import numpy as np

from src.crypto.keys import gen_rsa_3072, gen_ecc_p256, save_key
from src.crypto.signature import sign_file, verify_file
from src.pipeline.bind import build_payload, parse_payload
from src.watermark import lsb as wm_lsb
from src.watermark import dct as wm_dct

@click.group()
def cli():
    """Secure content authentication: signatures + watermarking."""

@cli.command()
@click.option("--scheme", type=click.Choice(["rsa", "ecc"]), default="rsa")
@click.option("--priv", type=click.Path(path_type=Path), default=Path("private.pem"))
@click.option("--pub", type=click.Path(path_type=Path), default=Path("public.pem"))
def genkeys(scheme: str, priv: Path, pub: Path):
    """Generate keypair (rsa or ecc)."""
    if scheme == "rsa":
        prv, pb = gen_rsa_3072()
    else:
        prv, pb = gen_ecc_p256()
    save_key(prv, priv)
    save_key(pb, pub)
    click.echo(f"Keys written → {priv} | {pub}")

@cli.command()
@click.argument("file", type=click.Path(path_type=Path))
@click.option("--priv", type=click.Path(path_type=Path), default=Path("private.pem"))
@click.option("--algo", type=click.Choice(["rsa", "ecc"]), default="rsa")
@click.option("--out", type=click.Path(path_type=Path), default=Path("file.sig"))
def sign(file: Path, priv: Path, algo: str, out: Path):
    """Sign a file (detached signature)."""
    sig = sign_file(file, priv.read_bytes(), algo=algo)
    out.write_bytes(sig)
    click.echo(f"Signature → {out}")

@cli.command()
@click.argument("file", type=click.Path(path_type=Path))
@click.option("--pub", type=click.Path(path_type=Path), default=Path("public.pem"))
@click.option("--algo", type=click.Choice(["rsa", "ecc"]), default="rsa")
@click.option("--sig", type=click.Path(path_type=Path), default=Path("file.sig"))
def verify(file: Path, pub: Path, algo: str, sig: Path):
    """Verify a file signature."""
    ok = verify_file(file, sig.read_bytes(), pub.read_bytes(), algo=algo)
    click.echo("VERIFY: OK" if ok else "VERIFY: FAIL")

@cli.command()
@click.argument("image", type=click.Path(path_type=Path))
@click.option("--scheme", type=click.Choice(["lsb", "dct"]), default="lsb")
@click.option("--signer", type=str, required=True)
@click.option("--algo", type=click.Choice(["rsa", "ecc"]), default="rsa")
@click.option("--out", type=click.Path(path_type=Path), default=Path("out_wm.png"))
@click.option("--extra", type=str, default="{}", help="JSON string of extra metadata")
def embed(image: Path, scheme: str, signer: str, algo: str, out: Path, extra: str):
    """Embed watermark payload into image."""
    payload = build_payload(image, signer, algo, json.loads(extra))
    if scheme == "lsb":
        wm_lsb.embed(image, payload, out)
    else:
        bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
        wm_dct.embed(image, bits, out)
    click.echo(f"Embedded watermark → {out}")

@cli.command()
@click.argument("image", type=click.Path(path_type=Path))
@click.option("--scheme", type=click.Choice(["lsb", "dct"]), default="lsb")
@click.option("--bits", type=int, default=512, help="For DCT extraction: number of bits")
def extract(image: Path, scheme: str, bits: int):
    """Extract watermark payload from image."""
    if scheme == "lsb":
        raw = wm_lsb.extract(image)
    else:
        bit_arr = wm_dct.extract(image, bits)
        raw = np.packbits(bit_arr).tobytes()
    try:
        meta = parse_payload(raw)
        click.echo(json.dumps(meta, indent=2))
    except Exception:
        click.echo("[!] Could not parse payload as JSON; raw bytes written to stdout.")
        import sys
        sys.stdout.buffer.write(raw)

if __name__ == "__main__":
    cli()
