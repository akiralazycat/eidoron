# Cryptographic Architecture — Protocol Candidate (NOT FINAL)

- Created / updated: 2026-10-31 JST
- Status: design draft. **No cryptographic implementation, format or audit exists yet.**
- Decision reference: [ADR-0001](decisions/0001-foundation.md)

## 1. Candidate building blocks

- Password-based key material: **Argon2id** (RFC 9106), per-vault 128-bit or greater random salt; benchmark candidate RFC's memory-constrained profile (64 MiB, t=3, p=4) on real mobile devices before locking parameters.
- Domain separation: **HKDF-SHA256** (RFC 5869) with explicit, versioned purpose strings and optional stable context.
- Authenticated encryption: **XChaCha20-Poly1305** for independent chunks/metadata with fresh 192-bit random nonces; vetted library, not handwritten primitives.
- For large sequential streams, evaluate libsodium **secretstream_xchacha20poly1305** but do not mix formats without a carefully specified versioned envelope.
- Device RNG: OS cryptographically secure entropy provider; fail closed on errors. No custom PRNG.
- File encryption keys: random 256-bit keys wrapped under a namespace key, or per-object keys derived by a reviewed scheme; choose exactly one before implementation. Unique cryptographic separation for index vs data vs wrapping keys.
- Optional future sharing: X25519-based envelope scheme only after separate protocol/security review; not part of v1.

Libraries are candidates until audit of Rust bindings, supply chain, platform build and memory handling.

## 2. Candidate key tree (conceptual)

Passphrase + vault-level public salt -> Argon2id root secret -> HKDF(domain-separated):
  * namespace/index encryption key
  * file-key wrapping key
  * locator/search key
  * context verification key (if needed and non-oracular)

Every unlock path must have indistinguishable failure shape where reasonable. Avoid explicit hidden-slot identifiers, plaintext realm counts or a different visible KDF record for each hidden password. **A single shared salt does not itself solve key discovery or deny hidden namespace existence.** Research protocol required.

Do not put actual master keys or real sample credentials into test fixtures. Document passphrase changes, key rotation, KDF version migration and recovery as separate operations. Recovery that stores a universal bypass key threatens denial properties.

## 3. File format proposal

Versioned, canonical binary encoding (e.g., compact CBOR with validated deterministic encoding or an explicitly described binary format). Prototype format layout:

- `opaque object ID` (transport-visible; may leak relationships if reused);
- `versioned generic envelope` (no flag identifying hidden content);
- `nonce`;
- `ciphertext and AEAD tag`;
- `padding` to the fixed cell class when applicable.

Authenticated Additional Data must bind protocol version, object identity, content kind, chunk ordinal, logical parent and generation **without exposing sensitive metadata in plaintext**; if public AAD is needed, only nonsensitive fields may be public. Use an explicit canonical encoding and reject all ambiguity. Do not re-encrypt with same key+nonce. Mutating immutable objects creates new IDs and ciphertexts.

File chunk sizing (e.g., 256 KiB / 1 MiB), padding sizes, fixed/variable object lengths, index B-tree vs append-only log and encrypted manifest design remain benchmark/attack-model decisions, not adopted constants.

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
