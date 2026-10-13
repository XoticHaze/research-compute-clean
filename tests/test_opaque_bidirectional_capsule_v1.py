import base64
import hashlib
import json
import unittest

from scripts.opaque_bidirectional_capsule_v1 import BUCKETS, generate_keypair, open_capsule, seal
from scripts.opaque_bidirectional_capsule_smoke_v1 import verify_public_envelopes

class OpaqueBidirectionalCapsuleTests(unittest.TestCase):
    def setUp(self):
        self.private, self.public, _ = generate_keypair()

    def test_roundtrip(self):
        payload = b"opaque-test-payload"
        envelope = seal(payload, recipient_public_b64=self.public, run_id="12345", direction="request")
        self.assertEqual(
            payload,
            open_capsule(
                envelope,
                recipient_private_b64=self.private,
                expected_run_id="12345",
                expected_direction="request",
            ),
        )

    def test_wrong_run_fails_closed(self):
        envelope = seal(b"x", recipient_public_b64=self.public, run_id="12345", direction="request")
        with self.assertRaisesRegex(RuntimeError, "run_id_rejected"):
            open_capsule(
                envelope,
                recipient_private_b64=self.private,
                expected_run_id="99999",
                expected_direction="request",
            )

    def test_wrong_direction_fails_closed(self):
        envelope = seal(b"x", recipient_public_b64=self.public, run_id="12345", direction="request")
        with self.assertRaisesRegex(RuntimeError, "direction_rejected"):
            open_capsule(
                envelope,
                recipient_private_b64=self.private,
                expected_run_id="12345",
                expected_direction="result",
            )

    def test_tamper_fails_closed(self):
        envelope = seal(b"x", recipient_public_b64=self.public, run_id="12345", direction="request")
        altered = dict(envelope)
        altered["ciphertext_sha256"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "ciphertext_digest_rejected"):
            open_capsule(
                altered,
                recipient_private_b64=self.private,
                expected_run_id="12345",
                expected_direction="request",
            )

    def test_plaintext_not_serialized_in_envelope(self):
        payload = b"NEVER_PUBLISH_THIS_MARKER"
        envelope = seal(payload, recipient_public_b64=self.public, run_id="12345", direction="result")
        rendered = json.dumps(envelope, sort_keys=True).encode("utf-8")
        self.assertNotIn(payload, rendered)

    def test_runtime_private_echo_stays_inside_request_result_ciphertext(self):
        private_body = b"PRIVATE-RUNTIME-CANARY-dynamic-synthetic-value"
        worker_private, worker_public, _ = generate_keypair()
        return_private, return_public, _ = generate_keypair()
        request = seal(
            private_body, recipient_public_b64=worker_public,
            run_id="12345", direction="request",
        )
        decrypted_request = open_capsule(
            request, recipient_private_b64=worker_private,
            expected_run_id="12345", expected_direction="request",
        )
        self.assertEqual(decrypted_request, private_body)
        result = seal(
            decrypted_request, recipient_public_b64=return_public,
            run_id="12345", direction="result",
        )
        self.assertEqual(
            open_capsule(
                result, recipient_private_b64=return_private,
                expected_run_id="12345", expected_direction="result",
            ),
            private_body,
        )
        verify_public_envelopes(request, result, private_body, "12345")

    def test_runtime_canary_gate_rejects_plaintext_base64_digest_and_extra_fields(self):
        body = b"PRIVATE-SYNTHETIC-CANARY-never-publish"
        _, worker_public, _ = generate_keypair()
        _, return_public, _ = generate_keypair()
        request = seal(body, recipient_public_b64=worker_public,
                       run_id="12345", direction="request")
        result = seal(body, recipient_public_b64=return_public,
                      run_id="12345", direction="result")
        variants = (
            {"plaintext": body.decode("ascii")},
            {"private_encoded": base64.b64encode(body).decode("ascii")},
            {"private_digest": hashlib.sha256(body).hexdigest()},
            {"plaintext_sha256": "0" * 64},
        )
        for extra in variants:
            with self.subTest(extra_key=list(extra)[0]):
                with self.assertRaisesRegex(RuntimeError, "rejected"):
                    verify_public_envelopes(
                        request, {**result, **extra}, body, "12345",
                    )
        with self.assertRaisesRegex(RuntimeError, "allowlist_rejected"):
            verify_public_envelopes(
                request, {**result, "run_id": "12346"}, body, "12345",
            )

    def test_ciphertext_uses_fixed_padding_bucket(self):
        envelope = seal(b"x", recipient_public_b64=self.public, run_id="12345", direction="result")
        import base64
        ciphertext = base64.b64decode(envelope["ciphertext_b64"].encode("ascii"), validate=True)
        self.assertIn(len(ciphertext) - 16, BUCKETS)

if __name__ == "__main__":
    unittest.main()
