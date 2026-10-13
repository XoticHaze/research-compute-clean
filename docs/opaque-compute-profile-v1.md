# Opaque Compute Profile v1

## Scope

This repository is a generic public execution plane. Workload meaning belongs outside the public plane.

Publicly observable material must be limited to generic protocol implementation, opaque run identifiers, cryptographic envelope fields, constant process state, and encrypted artifacts.

## Bidirectional rule

Every private workload uses:

1. encrypted request envelope;
2. transient execution;
3. encrypted result envelope.

Readable workload results, source identities, capability meaning, endpoints, business identifiers, private source hashes, detailed errors, and decision receipts stay inside the encrypted payload or the private authority.

## Cryptographic profiles

### Profile M1

- X25519 ephemeral ECDH
- HKDF-SHA-256
- ChaCha20-Poly1305
- fixed-size padding buckets

Implementation: `scripts/opaque_bidirectional_capsule_v1.py`

### Profile A1

- NIST P-256 ephemeral ECDH
- HKDF-SHA-256
- AES-256-GCM
- fixed-size padding buckets

Implementation: `scripts/opaque_bidirectional_capsule_p256_aesgcm_v1.py`

Profile A1 uses algorithms commonly available in FIPS-capable ecosystems. This repository does not claim that a normal hosted runner or its Python/OpenSSL stack is operating through a FIPS 140-3 validated module.

## Data-in-use boundary

Encryption before and after execution does not encrypt plaintext while the workload is executing on an ordinary hosted runner.

For workloads requiring protection from the compute host/control plane itself, use a confidential-compute worker with:

- measured worker image;
- hardware-backed isolated/encrypted memory;
- remote attestation;
- private authority verification of the attestation;
- capsule/key release only after measurement approval;
- encrypted result return;
- no plaintext persistence.

A hosted-runner success must never be described as confidential-compute or data-in-use protection.

## Metadata rules

Do not place workload-specific meaning in:

- repository names;
- branch names;
- workflow names;
- job names;
- workflow inputs;
- artifact names;
- file paths;
- logs;
- commit messages;
- issue text;
- public receipts.

Opaque run IDs may be exposed when required by the execution platform.

Avoid exposing hashes of private plaintext because they can act as correlation fingerprints.

## Logs

The workload process may emit only constant generic state, for example:

`OPAQUE_CAPSULE_PROTOCOL_PASS=1`

Detailed validation/error information belongs in the encrypted result whenever execution reaches the result-return stage.

## Artifact rule

Only encrypted envelope/ciphertext artifacts are allowed for private workloads.

## Supply chain

- Pin third-party actions to immutable commits.
- Pin cryptographic/runtime dependencies.
- Keep workflow permissions minimal.
- Prefer OIDC and short-lived credentials over repository secrets.
- Treat any privilege expansion as a reviewed security change.

## Acceptance

A reusable public-compute consumer must prove:

- request decrypts only for the expected run;
- request/result direction cannot be swapped;
- wrong recipient fails;
- ciphertext tamper fails;
- plaintext marker never appears in serialized envelope;
- padded ciphertext uses approved buckets;
- result is encrypted to a one-time return key;
- public artifact contains no plaintext result;
- runner cleanup executes on success and failure;
- private authority can decrypt and validate the returned result.

Confidential-compute acceptance additionally requires remote-attestation proof and key-release binding.
