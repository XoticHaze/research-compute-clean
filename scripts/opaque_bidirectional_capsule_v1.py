from __future__ import annotations

import base64
import hashlib
import json
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SCHEMA = "opaque-capsule-v1"
INFO = b"opaque-capsule-v1"
BUCKETS = (4096, 16384, 65536, 262144, 1048576)
FIELDS = {
    "schema",
    "run_id",
    "direction",
    "recipient_key_id",
    "sender_public_b64",
    "nonce_b64",
    "ciphertext_b64",
    "ciphertext_sha256",
}

def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")

def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)

def _key_id(public_raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(public_raw).hexdigest()

def generate_keypair() -> tuple[str, str, str]:
    private = x25519.X25519PrivateKey.generate()
    private_raw = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return _b64e(private_raw), _b64e(public_raw), _key_id(public_raw)

def _aad(*, run_id: str, direction: str, recipient_key_id: str) -> bytes:
    if direction not in {"request", "result"}:
        raise RuntimeError("direction_rejected")
    return json.dumps(
        {
            "schema": SCHEMA,
            "run_id": str(run_id),
            "direction": direction,
            "recipient_key_id": recipient_key_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

def _derive(shared: bytes, aad: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(aad).digest(),
        info=INFO,
    ).derive(shared)

def _pad(payload: bytes) -> bytes:
    inner = len(payload).to_bytes(8, "big") + payload
    bucket = next((size for size in BUCKETS if len(inner) <= size), None)
    if bucket is None:
        raise RuntimeError("payload_too_large")
    return inner + os.urandom(bucket - len(inner))

def _unpad(padded: bytes) -> bytes:
    if len(padded) not in BUCKETS or len(padded) < 8:
        raise RuntimeError("padding_rejected")
    length = int.from_bytes(padded[:8], "big")
    if length < 0 or length > len(padded) - 8:
        raise RuntimeError("length_rejected")
    return padded[8:8 + length]

def seal(
    payload: bytes,
    *,
    recipient_public_b64: str,
    run_id: str,
    direction: str,
) -> dict:
    recipient_raw = _b64d(recipient_public_b64)
    if len(recipient_raw) != 32:
        raise RuntimeError("recipient_key_rejected")
    recipient_key_id = _key_id(recipient_raw)
    sender = x25519.X25519PrivateKey.generate()
    sender_public_raw = sender.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    aad = _aad(
        run_id=str(run_id),
        direction=direction,
        recipient_key_id=recipient_key_id,
    )
    shared = sender.exchange(x25519.X25519PublicKey.from_public_bytes(recipient_raw))
    key = _derive(shared, aad)
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, _pad(payload), aad)
    return {
        "schema": SCHEMA,
        "run_id": str(run_id),
        "direction": direction,
        "recipient_key_id": recipient_key_id,
        "sender_public_b64": _b64e(sender_public_raw),
        "nonce_b64": _b64e(nonce),
        "ciphertext_b64": _b64e(ciphertext),
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
    }

def open_capsule(
    envelope: dict,
    *,
    recipient_private_b64: str,
    expected_run_id: str,
    expected_direction: str,
) -> bytes:
    if not isinstance(envelope, dict) or set(envelope) != FIELDS:
        raise RuntimeError("envelope_fields_rejected")
    if envelope.get("schema") != SCHEMA:
        raise RuntimeError("schema_rejected")
    if str(envelope.get("run_id")) != str(expected_run_id):
        raise RuntimeError("run_id_rejected")
    if envelope.get("direction") != expected_direction:
        raise RuntimeError("direction_rejected")

    private_raw = _b64d(recipient_private_b64)
    if len(private_raw) != 32:
        raise RuntimeError("private_key_rejected")
    private = x25519.X25519PrivateKey.from_private_bytes(private_raw)
    recipient_public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    recipient_key_id = _key_id(recipient_public_raw)
    if recipient_key_id != envelope.get("recipient_key_id"):
        raise RuntimeError("recipient_rejected")

    sender_public_raw = _b64d(str(envelope.get("sender_public_b64")))
    nonce = _b64d(str(envelope.get("nonce_b64")))
    ciphertext = _b64d(str(envelope.get("ciphertext_b64")))
    if len(sender_public_raw) != 32 or len(nonce) != 12:
        raise RuntimeError("transport_fields_rejected")
    if hashlib.sha256(ciphertext).hexdigest() != envelope.get("ciphertext_sha256"):
        raise RuntimeError("ciphertext_digest_rejected")

    aad = _aad(
        run_id=str(expected_run_id),
        direction=expected_direction,
        recipient_key_id=recipient_key_id,
    )
    shared = private.exchange(x25519.X25519PublicKey.from_public_bytes(sender_public_raw))
    padded = ChaCha20Poly1305(_derive(shared, aad)).decrypt(nonce, ciphertext, aad)
    return _unpad(padded)
