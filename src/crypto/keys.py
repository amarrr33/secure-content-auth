from __future__ import annotations
from typing import Tuple
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# -------------------------------
# RSA + ECC key generation
# -------------------------------

def gen_rsa_3072() -> Tuple[bytes, bytes]:
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
        backend=default_backend()
    )
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem

def gen_ecc_p256() -> Tuple[bytes, bytes]:
    priv = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem

# -------------------------------
# Save / Load helpers
# -------------------------------

def save_key(pem: bytes, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)

def load_private(path: Path):
    return serialization.load_pem_private_key(
        path.read_bytes(), password=None, backend=default_backend()
    )

def load_public(path: Path):
    return serialization.load_pem_public_key(
        path.read_bytes(), backend=default_backend()
    )

