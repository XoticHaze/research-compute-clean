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
    """Refuse private plaintext/encoded digest in public-only envelope fields."""
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
        if (private_body in public_bytes or marker_b64 in public_bytes
                or private_digest in public_bytes):
            raise RuntimeError("private_canary_publication_rejected")


def main() -> int:
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    worker_private, worker_public, _ = generate_keypair()
    return_private, return_public, _ = generate_keypair()

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
    if (base64.b64decode(recovered["private_echo_b64"], validate=True) != opaque_body
            or recovered["private_digest"] != hashlib.sha256(opaque_body).hexdigest()):
        raise SystemExit("opaque_private_return_rejected")
    verify_public_envelopes(request_envelope, result_envelope, opaque_body, run_id)

    Path("opaque-result-envelope.json").write_text(
        json.dumps(result_envelope, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("OPAQUE_CAPSULE_PROTOCOL_PASS=1")
    return 0


# An additional two-process acceptance path, not a second crypto protocol.
# Parent owns the one-time private RESULT key; worker child owns the private
# REQUEST key. Only worker public-key offer, AEAD ciphertext envelopes and
# the requester's result PUBLIC key cross the subprocess boundary.
def worker_process(run_id: str) -> int:
    try:
        request_private, request_public, request_key_id = generate_keypair()
        offer = {
            "schema": "clean-room-ephemeral-worker-offer-v1",
            "run_id": run_id,
            "recipient_public_b64": request_public,
            "recipient_key_id": request_key_id,
        }
        sys.stdout.write(json.dumps(offer, sort_keys=True, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        raw = sys.stdin.buffer.readline(200_001)
        if not raw or len(raw) > 200_000:
            return 1
        envelope = json.loads(raw)
        inner = json.loads(open_capsule(
            envelope,
            recipient_private_b64=request_private,
            expected_run_id=run_id,
            expected_direction="request",
        ))
        if not isinstance(inner, dict) or set(inner) != {"return_public_b64", "opaque_body_b64"}:
            return 1
        body = base64.b64decode(inner["opaque_body_b64"], validate=True)
        if not 0 < len(body) <= 256:
            return 1
        result = seal(
            hashlib.sha256(body).digest(),
            recipient_public_b64=inner["return_public_b64"],
            run_id=run_id,
            direction="result",
        )
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        return 0
    except Exception:
        # No private values, error text, stack traces, or key contents may
        # reach the public hosted runner's logs.
        return 1


def two_process_proof(mode: str) -> int:
    import subprocess
    import re
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    if not re.fullmatch(r"[0-9]{1,24}", run_id):
        print("CLEAN_ROOM_PROCESS_BOUNDARY=FAIL_CLOSED")
        return 1
    child = None
    try:
        child = subprocess.Popen(
            [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", run_id],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=str(ROOT),
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "PYTHONDONTWRITEBYTECODE": "1",
                "GITHUB_RUN_ID": run_id,
            },
        )
        assert child.stdin is not None and child.stdout is not None
        offer_bytes = child.stdout.readline(8192)
        if not offer_bytes or len(offer_bytes) >= 8192:
            raise RuntimeError("invalid_worker_offer")
        offer = json.loads(offer_bytes)
        if set(offer) != {
            "schema", "run_id", "recipient_public_b64", "recipient_key_id"
        } or offer["schema"] != "clean-room-ephemeral-worker-offer-v1" or offer["run_id"] != run_id:
            raise RuntimeError("worker_offer_identity_rejected")
        worker_public = base64.b64decode(offer["recipient_public_b64"], validate=True)
        if len(worker_public) != 32 or "sha256:" + hashlib.sha256(worker_public).hexdigest() != offer["recipient_key_id"]:
            raise RuntimeError("worker_offer_key_rejected")

        return_private, return_public, _ = generate_keypair()
        private_body = b"PRIVATE-RUNTIME-CANARY-" + os.urandom(32).hex().encode("ascii")
        request_body = json.dumps({
            "return_public_b64": return_public,
            "opaque_body_b64": base64.b64encode(private_body).decode(),
        }, sort_keys=True, separators=(",", ":")).encode()
        send_run = (run_id + "9") if mode == "wrong-run" else run_id
        request = seal(
            request_body, recipient_public_b64=offer["recipient_public_b64"],
            run_id=send_run, direction="request",
        )
        if mode == "tamper":
            request["ciphertext_b64"] = base64.b64encode(b"tampered-ciphertext").decode()
        outgoing = (json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n").encode()
        response_bytes, _ = child.communicate(input=outgoing, timeout=20)
        if mode != "success":
            if child.returncode == 0 or response_bytes.strip():
                raise RuntimeError("negative_case_not_rejected")
            print("CLEAN_ROOM_PROCESS_BOUNDARY_NEGATIVE_PASS=1")
            return 0
        if child.returncode != 0 or len(response_bytes) > 200_000:
            raise RuntimeError("worker_result_missing_or_oversized")
        response = json.loads(response_bytes)
        result_plaintext = open_capsule(
            response, recipient_private_b64=return_private,
            expected_run_id=run_id, expected_direction="result",
        )
        if result_plaintext != hashlib.sha256(private_body).digest():
            raise RuntimeError("independent_private_result_ack_rejected")
        # This ACK is from the parent in the same GitHub job and is synthetic.
        # It is NOT durable independent private-consumer acknowledgement.
        verify_public_envelopes(request, response, private_body, run_id)
        Path("opaque-result-envelope.json").write_text(
            json.dumps(response, sort_keys=True) + "\n", encoding="utf-8",
        )
        print("CLEAN_ROOM_TWO_PROCESS_ENCRYPTED_ROUNDTRIP_PASS=1")
        print("CLEAN_ROOM_PRIVATE_CONSUMER_DURABLE_ACK=0")
        return 0
    except Exception:
        print("CLEAN_ROOM_PROCESS_BOUNDARY=FAIL_CLOSED")
        return 1
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            try:
                child.communicate(timeout=5)
            except Exception:
                pass

if __name__ == "__main__":
    # Preserves the initial single-process acceptance for comparison.
    args = sys.argv[1:]
    if args == ["--two-process"]:
        raise SystemExit(two_process_proof("success"))
    if args == ["--two-process-tamper"]:
        raise SystemExit(two_process_proof("tamper"))
    if args == ["--two-process-wrong-run"]:
        raise SystemExit(two_process_proof("wrong-run"))
    if len(args) == 2 and args[0] == "--worker":
        raise SystemExit(worker_process(args[1]))
    if args:
        raise SystemExit("CLEAN_ROOM_PROOF_REJECTED")
    raise SystemExit(main())
