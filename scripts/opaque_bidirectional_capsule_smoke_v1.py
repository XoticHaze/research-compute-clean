from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.opaque_bidirectional_capsule_v1 import FIELDS, SCHEMA, generate_keypair, open_capsule, seal

def verify_public_envelopes(
    request_envelope: dict, result_envelope: dict, private_body: bytes, run_id: str,
) -> None:
    """Fail before artifact write if private markers or digest cross public boundary."""
    marker_b64 = base64.b64encode(private_body).decode("ascii").encode("ascii")
    private_digest = hashlib.sha256(private_body).hexdigest().encode("ascii")
    for direction, envelope in (("request", request_envelope), ("result", result_envelope)):
        if (
            not isinstance(envelope, dict)
            or set(envelope) != FIELDS
            or envelope.get("schema") != SCHEMA
            or envelope.get("direction") != direction
            or envelope.get("run_id") != run_id
        ):
            raise RuntimeError("public_envelope_allowlist_rejected")
        public_bytes = json.dumps(
            envelope, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        if (
            private_body in public_bytes
            or marker_b64 in public_bytes
            or private_digest in public_bytes
        ):
            raise RuntimeError("private_canary_publication_rejected")


def main() -> int:
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    worker_private, worker_public, _ = generate_keypair()
    return_private, return_public, _ = generate_keypair()

    # Fresh synthetic private data generated after GitHub checkout. Neither
    # its value nor its digest is written to tracked files or public logs.
    opaque_body = b"PRIVATE-RUNTIME-CANARY-" + os.urandom(32).hex().encode("ascii")
    request_plaintext = json.dumps(
        {
            "return_public_b64": return_public,
            "opaque_body_b64": base64.b64encode(opaque_body).decode("ascii"),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    request_envelope = seal(
        request_plaintext,
        recipient_public_b64=worker_public,
        run_id=run_id,
        direction="request",
    )
    worker_view = json.loads(
        open_capsule(
            request_envelope,
            recipient_private_b64=worker_private,
            expected_run_id=run_id,
            expected_direction="request",
        ).decode("utf-8")
    )

    body = base64.b64decode(worker_view["opaque_body_b64"].encode("ascii"), validate=True)
    # Echo the *actual* synthetic private body inside encrypted result only.
    # A hash-only response would not prove that account-like return data stays
    # confidential through the public result storage boundary.
    result_plaintext = json.dumps({
        "private_echo_b64": base64.b64encode(body).decode("ascii"),
        "private_digest": hashlib.sha256(body).hexdigest(),
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    result_envelope = seal(
        result_plaintext,
        recipient_public_b64=worker_view["return_public_b64"],
        run_id=run_id,
        direction="result",
    )

    requester_view = open_capsule(
        result_envelope,
        recipient_private_b64=return_private,
        expected_run_id=run_id,
        expected_direction="result",
    )
    if requester_view != result_plaintext:
        raise SystemExit("opaque_roundtrip_rejected")
    recovered = json.loads(requester_view.decode("utf-8"))
    if (
        base64.b64decode(recovered["private_echo_b64"], validate=True) != opaque_body
        or recovered["private_digest"] != hashlib.sha256(opaque_body).hexdigest()
    ):
        raise SystemExit("opaque_private_return_rejected")

    verify_public_envelopes(request_envelope, result_envelope, opaque_body, run_id)

    Path("opaque-result-envelope.json").write_text(
        json.dumps(result_envelope, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("OPAQUE_CAPSULE_PROTOCOL_PASS=1")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
