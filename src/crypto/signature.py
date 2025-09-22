from __future__ import annotations
from pathlib import Path
from typing import Literal
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec

Algo = Literal["rsa", "ecc"]

def sign_bytes(data: bytes, private_pem: bytes, algo: Algo = "rsa") -> bytes:
    """
    Sign bytes using either RSA (PSS+SHA256) or ECDSA P-256 (SHA256).
    private_pem: raw PEM bytes of private key
    """
    key = serialization.load_pem_private_key(private_pem, password=None)
    if algo == "rsa":
        return key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    elif algo == "ecc":
        return key.sign(data, ec.ECDSA(hashes.SHA256()))
    raise ValueError("Unknown algo")

def verify_bytes(data: bytes, signature: bytes, public_pem: bytes, algo: Algo = "rsa") -> bool:
    pub = serialization.load_pem_public_key(public_pem)
    try:
        if algo == "rsa":
            pub.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        else:
            pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def sign_file(path: Path, private_pem: bytes, algo: Algo = "rsa") -> bytes:
    return sign_bytes(path.read_bytes(), private_pem, algo=algo)

def verify_file(path: Path, signature: bytes, public_pem: bytes, algo: Algo = "rsa") -> bool:
    return verify_bytes(path.read_bytes(), signature, public_pem, algo=algo)

