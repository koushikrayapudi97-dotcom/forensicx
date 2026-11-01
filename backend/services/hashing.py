"""SHA-256 hashing and integrity verification."""

import hashlib
from pathlib import Path


def calculate_sha256(file_path: str | Path) -> dict[str, str]:
    digest = hashlib.sha256()
    with Path(file_path).open("rb") as evidence_file:
        for chunk in iter(lambda: evidence_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"algorithm": "SHA-256", "hash": digest.hexdigest()}


def verify_sha256(file_path: str | Path, expected_hash: str) -> bool:
    if not expected_hash or len(expected_hash) != 64:
        return False
    try:
        actual = calculate_sha256(file_path)["hash"]
    except FileNotFoundError:
        return False
    return actual.lower() == expected_hash.lower()