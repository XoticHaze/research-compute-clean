import json
import unittest

from scripts.opaque_bidirectional_capsule_v1 import BUCKETS, generate_keypair, open_capsule, seal

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

    def test_ciphertext_uses_fixed_padding_bucket(self):
        envelope = seal(b"x", recipient_public_b64=self.public, run_id="12345", direction="result")
        import base64
        ciphertext = base64.b64decode(envelope["ciphertext_b64"].encode("ascii"), validate=True)
        self.assertIn(len(ciphertext) - 16, BUCKETS)

if __name__ == "__main__":
    unittest.main()
