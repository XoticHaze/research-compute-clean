import base64
import json
import unittest

from scripts.opaque_bidirectional_capsule_p256_aesgcm_v1 import (
    BUCKETS,
    generate_keypair,
    open_capsule,
    seal,
)

class P256AesGcmCapsuleTests(unittest.TestCase):
    def setUp(self):
        self.private, self.public, _ = generate_keypair()

    def test_roundtrip(self):
        payload = b"opaque-test-payload"
        envelope = seal(payload, recipient_public_b64=self.public, run_id="12345", direction="request")
        restored = open_capsule(
            envelope,
            recipient_private_b64=self.private,
            expected_run_id="12345",
            expected_direction="request",
        )
        self.assertEqual(payload, restored)

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
        changed = dict(envelope)
        changed["ciphertext_sha256"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "ciphertext_digest_rejected"):
            open_capsule(
                changed,
                recipient_private_b64=self.private,
                expected_run_id="12345",
                expected_direction="request",
            )

    def test_plaintext_not_serialized(self):
        marker = b"NEVER_PUBLISH_THIS_MARKER"
        envelope = seal(marker, recipient_public_b64=self.public, run_id="12345", direction="result")
        self.assertNotIn(marker, json.dumps(envelope, sort_keys=True).encode())


    def test_wrong_recipient_key_fails_closed(self):
        envelope = seal(b"x", recipient_public_b64=self.public, run_id="12345", direction="request")
        other_private, _, _ = generate_keypair()
        with self.assertRaises(RuntimeError):
            open_capsule(
                envelope,
                recipient_private_b64=other_private,
                expected_run_id="12345",
                expected_direction="request",
            )

    def test_same_plaintext_encrypts_differently(self):
        payload = b"same-private-payload"
        first = seal(payload, recipient_public_b64=self.public, run_id="12345", direction="request")
        second = seal(payload, recipient_public_b64=self.public, run_id="12345", direction="request")
        self.assertNotEqual(first["ciphertext_b64"], second["ciphertext_b64"])
        self.assertNotEqual(first["nonce_b64"], second["nonce_b64"])

    def test_fixed_padding_bucket(self):
        envelope = seal(b"x", recipient_public_b64=self.public, run_id="12345", direction="result")
        ciphertext = base64.b64decode(envelope["ciphertext_b64"].encode("ascii"), validate=True)
        self.assertIn(len(ciphertext) - 16, BUCKETS)


class ExternalPrivateAuthorityCapsuleTests(unittest.TestCase):
    """Synthetic protocol acceptance. Real independent owner remains an extra gate."""
    def setUp(self):
        self.worker_private, self.worker_public, _ = generate_keypair()
        self.return_private, self.return_public, _ = generate_keypair()
        self.raw = b"SYNTHETIC-EXTERNAL-CANARY-" + b"z" * 32
        self.body = json.dumps({
            "schema": "clean-external-synthetic-v1",
            "opaque_input_b64": base64.b64encode(self.raw).decode(),
            "return_public_b64": self.return_public,
        }, sort_keys=True).encode()

    def _envelope(self, *, run="12345"):
        return seal(self.body, recipient_public_b64=self.worker_public,
                    run_id=run, direction="request")

    def _execute(self, envelope):
        from scripts.opaque_bidirectional_capsule_smoke_v1 import external_execute_capsule
        return external_execute_capsule(envelope, self.worker_private, "12345")

    def test_separate_key_custody_and_encrypted_private_return(self):
        response = self._execute(self._envelope())
        recovered = open_capsule(response, recipient_private_b64=self.return_private,
                                 expected_run_id="12345", expected_direction="result")
        inner = json.loads(recovered)
        self.assertEqual(set(inner), {"schema", "private_echo_b64", "private_digest"})
        self.assertEqual(base64.b64decode(inner["private_echo_b64"], validate=True), self.raw)
        import hashlib
        self.assertEqual(inner["private_digest"], hashlib.sha256(self.raw).hexdigest())
        serialized = json.dumps(response).encode()
        self.assertNotIn(self.raw, serialized)
        self.assertNotIn(base64.b64encode(self.raw), serialized)
        self.assertNotIn(hashlib.sha256(self.raw).hexdigest().encode(), serialized)
        self.assertEqual(response["schema"], "opaque-capsule-p256-aesgcm-v1")

    def test_wrong_run_rejected(self):
        with self.assertRaises(Exception):
            self._execute(self._envelope(run="9999"))

    def test_wrong_recipient_rejected(self):
        wrong, _, _ = generate_keypair()
        from scripts.opaque_bidirectional_capsule_smoke_v1 import external_execute_capsule
        with self.assertRaises(Exception):
            external_execute_capsule(self._envelope(), wrong, "12345")

    def test_invalid_public_metadata_rejected(self):
        altered = {**self._envelope(), "plaintext_sha256": "a" * 64}
        with self.assertRaises(Exception):
            self._execute(altered)

    def test_tampered_ciphertext_rejected(self):
        altered = {**self._envelope(), "ciphertext_sha256": "b" * 64}
        with self.assertRaises(Exception):
            self._execute(altered)

    def test_forbidden_private_command_rejected(self):
        bad = json.dumps({
            "schema": "clean-external-synthetic-v1",
            "opaque_input_b64": base64.b64encode(self.raw).decode(),
            "return_public_b64": self.return_public,
            "command": "do-not-run",
        }).encode()
        with self.assertRaises(Exception):
            self._execute(seal(bad, recipient_public_b64=self.worker_public,
                               run_id="12345", direction="request"))

    def test_non_synthetic_input_rejected(self):
        bad = json.dumps({
            "schema": "clean-external-synthetic-v1",
            "opaque_input_b64": base64.b64encode(b"REAL-PRIVATE-CONTENT-" + b"x" * 32).decode(),
            "return_public_b64": self.return_public,
        }).encode()
        with self.assertRaises(Exception):
            self._execute(seal(bad, recipient_public_b64=self.worker_public,
                               run_id="12345", direction="request"))

if __name__ == "__main__":
    unittest.main()
