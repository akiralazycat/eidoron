# Cryptographic Architecture — Protocol Candidate (NOT FINAL)

- Created / updated: 2026-10-31 JST
- Status: design draft. **No cryptographic implementation, format or audit exists yet.**
- Decision references: [ADR-0001](decisions/0001-foundation.md) and [ADR-0002](decisions/0002-crypto-dependencies-ffi.md) and [ADR-0003](decisions/0003-envelope-and-key-hierarchy.md)
- P1.2 recorded implementation **candidates**. P1.3 selected a **candidate (unreviewed) Vault v0 binary layout and derived per-object key schedule**; versions, software implementation and security properties remain unverified. See [09_ENVELOPE_FORMAT_V0.md](09_ENVELOPE_FORMAT_V0.md).

## 1. Candidate building blocks

- Password-based key material: **Argon2id** (RFC 9106), per-vault 128-bit or greater random salt; benchmark candidate RFC's memory-constrained profile (64 MiB, t=3, p=4) on real mobile devices before locking parameters.
- Domain separation: **HKDF-SHA256** (RFC 5869) with explicit, versioned purpose strings and optional stable context.
- Authenticated encryption: **XChaCha20-Poly1305** for independent chunks/metadata with fresh 192-bit random nonces; vetted library, not handwritten primitives.
- For large sequential streams, evaluate libsodium **secretstream_xchacha20poly1305** but do not mix formats without a carefully specified versioned envelope.
- Device RNG: OS cryptographically secure entropy provider; fail closed on errors. No custom PRNG.
- Object encryption keys: **P1.3 candidate decision = HKDF-derived per-object 256-bit keys** from a random RootSecret and random object ID. This replaces the earlier undecided random per-file vs derived key alternatives for *Vault v0 only*. Review required before coding. Unique cryptographic separation for index vs data vs wrapping keys.
- Optional future sharing: X25519-based envelope scheme only after separate protocol/security review; not part of v1.

Implementation preference recorded 2026-10-31: RustCrypto `chacha20poly1305` / `argon2` / `hkdf` + `sha2`, `secrecy` / `zeroize`, OS CSPRNG, and Mozilla UniFFI Swift/Kotlin bindings. See [ADR-0002](decisions/0002-crypto-dependencies-ffi.md). These are **design choices**, not installed or security-audited dependencies; final versions and APIs will be pinned at implementation. No package is secure merely due to past audits.

## 2. Candidate key tree (conceptual)

P1.3 candidate Vault v0: passphrase UTF-8 + random 16-byte KDF salt -> Argon2id raw 32-byte key -> HKDF(password-wrap context) -> password wrapping key -> authenticated encryption of a separate random 32-byte RootSecret. ObjectKey = HKDF(RootSecret, vault ID and random 32-byte object ID). Full byte schedule, AAD and protocol constraints: [09_ENVELOPE_FORMAT_V0.md](09_ENVELOPE_FORMAT_V0.md). **Hidden-space locator/search keys are not part of v0 and remain P6 research.**

Every unlock path must have indistinguishable failure shape where reasonable. Avoid explicit hidden-slot identifiers, plaintext realm counts or a different visible KDF record for each hidden password. **A single shared salt does not itself solve key discovery or deny hidden namespace existence.** Research protocol required.

Do not put actual master keys or real sample credentials into test fixtures. Document passphrase changes, key rotation, KDF version migration and recovery as separate operations. Recovery that stores a universal bypass key threatens denial properties.

## 3. Candidate Vault v0 format (P1.3)

The detailed proposed binary format is defined in [09_ENVELOPE_FORMAT_V0.md](09_ENVELOPE_FORMAT_V0.md): **136-byte public wrapped-root header**, **88-byte public immutable object prefix + AEAD payload**, **66-byte untrusted HEAD**, deterministic RFC 8949 CBOR for authenticated commit, directory and file metadata, and a derived per-object key. Chunk body sizes are capped; public ciphertext sizes and upload metadata are NOT hidden. No padding, secret namespace or ORAM is claimed in v0.

The format is **candidate for P1.4/P1.5 security review**, not frozen; altering bytes/suites requires updating ADR, test vectors and any future migration policy.

## 4. Anti-rollback and tampering

AEAD alone does not detect valid older ciphertext restored by a malicious provider. Cross-device anti-rollback requires trusted per-device high-water marks or independent witnesses; fully offline new devices have weaker guarantees. Record exactly what is and isn't detected.

Index children and file-content bindings must detect object substitution, inconsistent generations and partial commits. Metadata transactions should be crash-safe and restartable. Treat accidental and malicious conflict separately.

## 5. API boundaries for phase 1 prototype

Design-only Rust interface (not committed as code yet):
- `derive_root(passphrase, vault_salt, kdf_params) -> RootSecret`;
- `derive_namespace_keys(root, purpose, format_version) -> KeySet`;
- `encrypt_chunk(key, nonce, plaintext, aad) -> Ciphertext`;
- `decrypt_chunk(...) -> Result<VerifiedPlaintext, AuthError>`;
- `wrap_file_key / unwrap_file_key`;
- `seal_index / open_index`;
- `zeroize_session / lock` (best effort, not forensic wipe).

Production interfaces must have opaque secret types, no accidental debug formatting or `Clone` for key material, and error redaction. Avoid password-derived hashes as persistent identity signals.

## 6. Required tests before any sync

- published known-answer tests for primitives;
- same plaintext encrypted twice yields different ciphertext under fresh random nonce;
- bit flips / wrong password / reordered chunks rejected;
- cross-platform deterministic *decryption* fixtures and version compatibility;
- property testing for round-trip / malformed lengths / truncation / overflow;
- fuzz parser, format migration and state transitions; no panic on attacker bytes;
- benchmark KDF performance, memory, battery on supported iPhones and Android devices;
- memory/key lifecycle review and reproducible dependency inventory.

## 7. References

- Argon2id: https://www.rfc-editor.org/rfc/rfc9106
- HKDF: https://www.rfc-editor.org/rfc/rfc5869
- libsodium XChaCha20-Poly1305: https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305
- libsodium secretstream: https://doc.libsodium.org/secret-key_cryptography/secretstream
