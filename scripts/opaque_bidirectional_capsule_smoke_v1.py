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


# External synthetic-only private authority rendezvous. Uses the canonical
# P-256/AES-GCM module already installed; not a new crypto or router profile.
# Never accepts job commands, arbitrary source code, or sensitive real data.
def external_execute_capsule(envelope: dict, request_private: str, run_id: str) -> dict:
    from scripts.opaque_bidirectional_capsule_p256_aesgcm_v1 import (
        open_capsule as p256_open, seal as p256_seal,
    )
    raw = p256_open(envelope, recipient_private_b64=request_private,
                    expected_run_id=run_id, expected_direction="request")
    if len(raw) > 4096:
        raise RuntimeError("external_request_oversized")
    body = json.loads(raw)
    if (not isinstance(body, dict) or
            set(body) != {"schema", "opaque_input_b64", "return_public_b64"}
            or body["schema"] != "clean-external-synthetic-v1"):
        raise RuntimeError("external_request_schema_rejected")
    source = base64.b64decode(body["opaque_input_b64"], validate=True)
    if not (16 <= len(source) <= 160) or not source.startswith(b"SYNTHETIC-EXTERNAL-CANARY-"):
        raise RuntimeError("external_input_scope_rejected")
    result_body = json.dumps({
        "schema": "clean-external-synthetic-result-v1",
        "private_echo_b64": base64.b64encode(source).decode("ascii"),
        "private_digest": hashlib.sha256(source).hexdigest(),
    }, sort_keys=True, separators=(",", ":")).encode()
    response = p256_seal(result_body, recipient_public_b64=body["return_public_b64"],
                         run_id=run_id, direction="result")
    # Only AEAD envelope is permitted beyond worker.
    if set(response) != __import__(
            "scripts.opaque_bidirectional_capsule_p256_aesgcm_v1",
            fromlist=["FIELDS"]).FIELDS:
        raise RuntimeError("external_result_fields_rejected")
    return response


def external_worker(publish_offer: bool = False) -> int:
    import re
    import time
    import urllib.request
    import urllib.error
    from scripts.opaque_bidirectional_capsule_p256_aesgcm_v1 import generate_keypair as generate_p256
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not re.fullmatch(r"[1-9][0-9]{0,19}", run_id) or repo != "XoticHaze/research-compute-clean":
        print("CLEAN_EXTERNAL_WORKER=FAIL_CLOSED")
        return 1
    if publish_offer and (
        os.environ.get("GITHUB_EVENT_NAME") != "pull_request_target"
        or os.environ.get("GITHUB_BASE_REF") != "main"
        or os.environ.get("GITHUB_REPOSITORY_ID") != "1416551057"
        or not re.fullmatch(r"security/clean-external-probe-[0-9]{8}",
                            os.environ.get("GITHUB_HEAD_REF", ""))
    ):
        print("CLEAN_EXTERNAL_WORKER=FAIL_CLOSED")
        return 1
    try:
        private, public, key_id = generate_p256()
        offer = {
            "schema": "clean-external-worker-offer-v1",
            "run_id": run_id,
            "recipient_public_b64": public,
            "recipient_key_id": key_id,
            "repository_id": "1416551057",
        }

        def publish_public_exchange(kind: str, node: dict) -> None:
            if kind not in {"offer", "result"}:
                raise RuntimeError("exchange_publish_kind_rejected")
            token = os.environ.get("GH_TOKEN", "")
            if not token:
                raise RuntimeError("exchange_write_token_missing")
            path = f"rendezvous/{run_id}/{kind}.json"
            content = base64.b64encode(
                (json.dumps(node, sort_keys=True, separators=(",", ":")) + "\n").encode()
            ).decode()
            posted = json.dumps({
                "message": "proof: publish encrypted external synthetic exchange object",
                "content": content, "branch": "clean-synthetic-exchange",
            }, separators=(",", ":")).encode()
            put = urllib.request.Request(
                f"https://api.github.com/repos/{repo}/contents/{path}",
                data=posted, method="PUT", headers={
                    "Authorization": "Bearer " + token,
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "Content-Type": "application/json",
                    "User-Agent": "clean-external-proof-v1",
                })
            with urllib.request.urlopen(put, timeout=15) as response:
                if response.status != 201:
                    raise RuntimeError("exchange_publish_rejected")
                response.read(100)

        if publish_offer:
            publish_public_exchange("offer", offer)
            print("CLEAN_EXTERNAL_PUBLIC_OFFER_PUBLISHED=1", flush=True)
        else:
            # Old read-only source acceptance mode still prints only the
            # public offer for diagnostic compatibility, without secret keys.
            print("CLEAN_EXTERNAL_OFFER_JSON=" + json.dumps(
                offer, sort_keys=True, separators=(",", ":")), flush=True)
        url = (f"https://api.github.com/repos/{repo}/contents/"
               f"rendezvous/{run_id}/request.json?ref=clean-synthetic-exchange")
        token = os.environ.get("GH_TOKEN", "")
        if not token:
            raise RuntimeError("read_only_github_token_unavailable")
        payload = None
        for _ in range(72):
            req = urllib.request.Request(url, headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "clean-external-proof-v1",
            })
            try:
                with urllib.request.urlopen(req, timeout=8) as response:
                    node_bytes = response.read(120_001)
                if len(node_bytes) > 120_000:
                    raise RuntimeError("external_exchange_oversized")
                node = json.loads(node_bytes)
                content = base64.b64decode(str(node["content"]).encode(), validate=False)
                if len(content) > 80_000:
                    raise RuntimeError("external_envelope_oversized")
                payload = json.loads(content)
                break
            except urllib.error.HTTPError as exc:
                if exc.code != 404:
                    raise RuntimeError("external_exchange_read_rejected") from None
                time.sleep(3)
        if payload is None:
            raise RuntimeError("external_request_not_received")
        result = external_execute_capsule(payload, private, run_id)
        line = json.dumps(result, sort_keys=True, separators=(",", ":"))
        if len(line) > 120_000:
            raise RuntimeError("external_result_oversized")
        Path("opaque-result-envelope.json").write_text(line + "\n", encoding="utf-8")
        if publish_offer:
            publish_public_exchange("result", result)
            print("CLEAN_EXTERNAL_PUBLIC_CIPHERTEXT_RESULT_PUBLISHED=1", flush=True)
        else:
            print("CLEAN_EXTERNAL_RESULT_JSON=" + line, flush=True)
        print("CLEAN_EXTERNAL_PUBLIC_ENCRYPTED_RESULT=PASS", flush=True)
        print("CLEAN_EXTERNAL_DURABLE_PRIVATE_ACK=0", flush=True)
        return 0
    except Exception:
        # An untrusted request must not dump tracebacks, private keys, payload,
        # URL details, or API error bodies to public Actions logs.
        print("CLEAN_EXTERNAL_WORKER=FAIL_CLOSED")
        return 1

if __name__ == "__main__":
    # Preserves the initial single-process acceptance for comparison.
    args = sys.argv[1:]
    if args == ["--external-synthetic-worker"]:
        raise SystemExit(external_worker())
    if args == ["--external-synthetic-worker-publish"]:
        raise SystemExit(external_worker(publish_offer=True))
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
