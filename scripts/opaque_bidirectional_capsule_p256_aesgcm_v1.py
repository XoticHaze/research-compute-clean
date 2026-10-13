from __future__ import annotations

import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SCHEMA = "opaque-capsule-p256-aesgcm-v1"
INFO = b"opaque-capsule-p256-aesgcm-v1"
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

def _public_raw(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )

def _key_id(public_raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(public_raw).hexdigest()

def generate_keypair() -> tuple[str, str, str]:
    private = ec.generate_private_key(ec.SECP256R1())
    private_der = private.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_raw = _public_raw(private.public_key())
    return _b64e(private_der), _b64e(public_raw), _key_id(public_raw)

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
    if length > len(padded) - 8:
        raise RuntimeError("length_rejected")
    return padded[8:8 + length]

def seal(payload: bytes, *, recipient_public_b64: str, run_id: str, direction: str) -> dict:
    recipient_raw = _b64d(recipient_public_b64)
    try:
        recipient = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), recipient_raw)
    except ValueError as exc:
        raise RuntimeError("recipient_key_rejected") from exc

    recipient_key_id = _key_id(recipient_raw)
    sender = ec.generate_private_key(ec.SECP256R1())
    sender_public_raw = _public_raw(sender.public_key())
    aad = _aad(run_id=str(run_id), direction=direction, recipient_key_id=recipient_key_id)
    shared = sender.exchange(ec.ECDH(), recipient)
    key = _derive(shared, aad)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, _pad(payload), aad)
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

    try:
        private = serialization.load_der_private_key(_b64d(recipient_private_b64), password=None)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("private_key_rejected") from exc
    if not isinstance(private, ec.EllipticCurvePrivateKey) or not isinstance(private.curve, ec.SECP256R1):
        raise RuntimeError("private_key_rejected")

    recipient_public_raw = _public_raw(private.public_key())
    recipient_key_id = _key_id(recipient_public_raw)
    if recipient_key_id != envelope.get("recipient_key_id"):
        raise RuntimeError("recipient_rejected")

    sender_public_raw = _b64d(str(envelope.get("sender_public_b64")))
    try:
        sender = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), sender_public_raw)
    except ValueError as exc:
        raise RuntimeError("sender_key_rejected") from exc
    nonce = _b64d(str(envelope.get("nonce_b64")))
    ciphertext = _b64d(str(envelope.get("ciphertext_b64")))
    if len(nonce) != 12:
        raise RuntimeError("nonce_rejected")
    if hashlib.sha256(ciphertext).hexdigest() != envelope.get("ciphertext_sha256"):
        raise RuntimeError("ciphertext_digest_rejected")

    aad = _aad(
        run_id=str(expected_run_id),
        direction=expected_direction,
        recipient_key_id=recipient_key_id,
    )
    shared = private.exchange(ec.ECDH(), sender)
    padded = AESGCM(_derive(shared, aad)).decrypt(nonce, ciphertext, aad)
    return _unpad(padded)
