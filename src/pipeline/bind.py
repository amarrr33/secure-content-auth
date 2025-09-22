# src/pipeline/bind.py
from __future__ import annotations
import json
from pathlib import Path
from typing import Optional

from ..crypto.hashing import sha256_file

def build_payload(file_path: Path, signer: str, algo: str, extra: Optional[dict] = None) -> bytes:
    data = {
        "sha256": sha256_file(file_path),
        "signer": signer,
        "algo": algo,
    }
    if extra:
        data.update(extra)
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def parse_payload(b: bytes) -> dict:
    return json.loads(b.decode("utf-8"))
