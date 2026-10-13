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

from scripts.opaque_bidirectional_capsule_v1 import generate_keypair, open_capsule, seal

def main() -> int:
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    worker_private, worker_public, _ = generate_keypair()
    return_private, return_public, _ = generate_keypair()

    opaque_body = os.urandom(96)
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
    result_plaintext = hashlib.sha256(body).digest()
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
    if requester_view != hashlib.sha256(opaque_body).digest():
        raise SystemExit("opaque_roundtrip_rejected")

    Path("opaque-result-envelope.json").write_text(
        json.dumps(result_envelope, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("OPAQUE_CAPSULE_PROTOCOL_PASS=1")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
