# Research Sources, Evidence and Open Questions

- Created / updated: 2026-10-31 JST
- Purpose: grounding and evaluation; links are sources, not proof of Eidoron's security.

## Reference specifications and implementation docs

- RFC 9106 Argon2: https://www.rfc-editor.org/rfc/rfc9106
  - Mobile parameter selection requires benchmark; RFC describes 64 MiB/t=3/p=4 as its memory-constrained recommendation.
- RFC 5869 HKDF: https://www.rfc-editor.org/rfc/rfc5869
- libsodium XChaCha20-Poly1305: https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305
- libsodium secretstream: https://doc.libsodium.org/secret-key_cryptography/secretstream
- Cryptomator security architecture: https://docs.cryptomator.org/security/architecture/
- Cryptomator explicit security target / metadata leakage: https://docs.cryptomator.org/security/security-target/

- NIST SP 800-38D, Appendix D: authenticated decryption alone does not prevent replay; a trusted freshness mechanism is separate: https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf

## P1.2 library / platform sources (reviewed 2026-10-31)

- RustCrypto XChaCha20: https://docs.rs/chacha20poly1305/latest/chacha20poly1305/
- RustCrypto Argon2: https://docs.rs/argon2/latest/argon2/
- RustCrypto HKDF: https://docs.rs/hkdf/latest/hkdf/
- RustCrypto secrecy and zeroize: https://docs.rs/secrecy/latest/secrecy/ , https://docs.rs/zeroize/latest/zeroize/
- Mozilla UniFFI: https://mozilla.github.io/uniffi-rs/
- Apple Keychain / Secure Enclave: https://developer.apple.com/documentation/Security/protecting-keys-with-the-secure-enclave
- Android Keystore: https://developer.android.com/privacy-and-security/keystore
- cargo-deny: https://github.com/EmbarkStudios/cargo-deny
- Detailed decisions, caveats and implementation gates: [ADR-0002](decisions/0002-crypto-dependencies-ffi.md).

## P1.3 binary envelope research (reviewed 2026-10-31)

- RFC 8949 §4.2 core deterministic CBOR, including rejection of duplicate map keys: https://www.rfc-editor.org/rfc/rfc8949
- NIST SP 800-38D Appendix D, replay is not inherently prevented by authenticated encryption: https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
- Vault v0 candidate byte-format, KDF schedule and design limits: [09_ENVELOPE_FORMAT_V0.md](09_ENVELOPE_FORMAT_V0.md).
- Design rationale and deferred alternatives: [ADR-0003](decisions/0003-envelope-and-key-hierarchy.md).
- No published Eidoron test vectors or protocol audit yet.

## P1.4 future test and fuzz tooling (reviewed 2026-10-31)

- Rust Fuzz Book / cargo-fuzz: https://rust-fuzz.github.io/book/cargo-fuzz.html
- Rust proptest property-based tests: https://docs.rs/proptest/latest/proptest/
- Test/fuzz design and open P1.5 blockers: [10_TEST_AND_FUZZ_PLAN.md](10_TEST_AND_FUZZ_PLAN.md).
- **No fuzz campaign, vector suite, or runtime test has been executed.**

## Deniable storage background

- DataLair (PoPETs 2017), multi-snapshot adversary and write-only ORAM: https://crysp.petsymposium.org/popets/2017/popets-2017-0035.php
- DataLair arXiv abstract: https://arxiv.org/abs/1706.10276
- Search subsequent peer-reviewed work on deniable cloud storage, multi-client ORAM, and traffic analysis before adopting a construction. No source implies a drop-in secure cloud implementation.

## Distinguish scientific claims

1. **Encryption**: confidentiality/integrity of chunks against T0/T1 can be tested through specified cryptography.
2. **Hiding names/structure**: encrypted index protects names but not necessarily total bytes/updates.
3. **Deniability**: a formal observational game; never inferred just because storage looks random.
4. **Unlinkability/traffic secrecy**: separate network-level goal.
5. **Forensic protection**: device and OS boundary; not promised.

## Open evaluation questions

- Can a cloud object store expose enough history to distinguish even padded Shadow writes?
- How does a public-key-only client avoid hidden data corruption while maintaining an ordinary-only explanation?
- Is fixed-size pooling practical for growing media without anomalous storage expansions?
- Does object version retention defeat garbage collection or cover traffic?
- Can two offline devices modify one hidden namespace without a trusted allocation ledger?
- How large is the mobile latency/battery tradeoff of Argon2id and ORAM?
- How can onboarding, biometric integration and backup avoid making hidden-space existence visible?

## P1.1 security target

The normative proposed claim IDs, falsification test IDs and W0/W1 games are in [08_SECURITY_TARGET.md](08_SECURITY_TARGET.md). This is **planning evidence only** and must not be cited as passing security tests.

## Required evidence deliverables

- Written adversary model and clear nonclaims.
- Normative envelope design, cross-language test vectors, fuzz harness.
- Deterministic local fault injection and provider trace collection.
- Pre-registered comparator workloads and independent evaluators.
- Security audit with fixed findings and reproducible release tag.
