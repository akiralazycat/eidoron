# ADR-0003 — Password-wrapped random root and immutable authenticated objects

- Decision date: **2026-10-31 JST**
- Status: **Accepted as candidate for design review**; no implementation or independent security audit
- Scope: P1.3 — Vault v0 only, not Shadow/Specter
- Detailed draft: [Eidoron Vault Envelope v0](../09_ENVELOPE_FORMAT_V0.md)
- Prior decisions: [ADR-0001](0001-foundation.md), [ADR-0002](0002-crypto-dependencies-ffi.md)

## Context

We need a reproducible, independently reviewable file-format and key schedule before writing Rust encryption code. Cryptography, cloud synchronization, metadata authentication and password changes must be treated together. Hidden-volume research must not contaminate baseline claims.

## Decision

1. **Random RootSecret** (32 bytes) is wrapped with a passphrase-derived key, rather than making the password-derived output the permanent data encryption key. This permits password-only header rewrapping without re-encrypting all content.
2. **Argon2id → HKDF-SHA256 → XChaCha20-Poly1305**; fixed public format IDs, authenticated header, bounded Argon2 parameters and fresh nonces.
3. **Derived per-object keys** via HKDF(root, vault ID, object ID); 32-byte cryptographically random immutable object IDs; random 24-byte nonce for every first encryption, never intentionally reused. Defer optional per-file sharing/delegation.
4. **Three clear public artifacts:** `vault.header` (136 bytes, wrapped root), encrypted object envelopes (88-byte public prefix + authenticated ciphertext/tag), `vault.head` (66-byte untrusted mutable root selector).
5. **Sensitive metadata inside authenticated objects**; deterministic bounded RFC 8949 CBOR for commit roots, directories and file descriptors. Authenticated reference validation prevents arbitrary swapping/mislabeling when trusted root/head state permits.
6. **Replay is separate from authentication:** retain high-water trusted checkpoint when available, and label new-device freshness unknown. A malicious cloud can withhold/delete data; conditional commit updates await P3.
7. **Password change ≠ revocation:** header rewrap does not defeat an attacker with old header/ciphertext snapshots. Full root rotation is separate, expensive and does not erase historical copies.
8. **No hidden realm claims:** visible header and metadata make this a conventional encrypted Vault; multi-credential deniability requires independent protocol in P6/P7.

Candidate byte constants and schemas are specified precisely in `docs/09_ENVELOPE_FORMAT_V0.md`. They are **not frozen production compatibility promises** until tests/review resolve any errors.

## Alternatives considered

- **Password-derived permanent data root:** rejected as baseline because password change requires mass re-encryption and simplifies key management at the expense of migration/recovery flexibility.
- **Independent random per-file keys + key-wrap table:** deferred; adds state and metadata complexity without a v0 sharing requirement.
- **Content-derived IDs/deduplication:** rejected because content equality and deterministic reuse could leak correlations.
- **Single large monolithic container:** rejected for poor incremental cloud synchronization.
- **Unversioned/JSON ciphertext envelopes:** rejected because noncanonical representations and implicit format changes enlarge malleability and interoperability risk.
- **Treating AEAD tag as anti-rollback evidence:** rejected; old authenticated data remains valid if replayed.
- **Multiple visible hidden-slot headers:** rejected and not part of Vault v0.
- **Automatic downgrade on low-memory device:** rejected; unsupported resource policy must fail rather than weaken encoded protection.

## Consequences and open issues

- New immutable objects cause additional cloud requests and require safe garbage collection after remote consistency (P3).
- A visible `vault.header` directly reveals baseline encrypted vault existence; appropriate for Vault, not Shadow.
- Metadata and chunk length leak through ciphertext sizes; padding and cover traffic are future independent research topics.
- Password rewrap rotates only the header salt and nonce while retaining RootSecret; old versions can remain decryptable.
- A file/directory rename causes new authenticated metadata/commit objects but not necessarily file-content changes.
- The HEAD pointer's own metadata is untrusted; its consistency/freshness needs more than AEAD.
- Model/encoding bounds may constrain huge files or directories until reviewed sharding is implemented.
- P1.4 must generate exact-byte fixtures and failure matrix; P1.5 must review full protocol, domain separation, object graph validation, corrupted ciphertext failures and key lifecycle.

## Verification status

- [x] Candidate decision and full binary layout documented.
- [x] Cross-platform and adversarial fixture requirements mapped.
- [ ] Implementation, published primitive KAT execution or parser fuzz.
- [ ] Independent cryptographic design review.
- [ ] Durable CAS/commit protocol and mobile performance tests.

## References

- RFC 9106: https://www.rfc-editor.org/rfc/rfc9106
- RFC 5869: https://www.rfc-editor.org/rfc/rfc5869
- RFC 8949: https://www.rfc-editor.org/rfc/rfc8949
- RustCrypto XChaCha20Poly1305: https://docs.rs/chacha20poly1305/latest/chacha20poly1305/
