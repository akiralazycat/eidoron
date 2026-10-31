# Synthetic fixtures and published primitive vectors

The helpers in `src/lib.rs` still create **untrusted, invalid-ciphertext shapes** for the public v0 parser. They are not authenticated files, not a valid encrypted archive, and not sample user passwords.

Published primitive known-answer tests live in `crates/crypto/src/published_kat.rs`. Expected bytes were copied from the documents below. They were not produced by running this crate and pasting the output back.

- Argon2id: RFC 9106 section 5.3 (version 19, 32 KiB, 3 passes, 4 lanes, 32-byte tag, with the published secret and associated data). <https://www.rfc-editor.org/rfc/rfc9106>
- HKDF-SHA-256: RFC 5869 appendix A.1 test case 1 (PRK and 42-byte OKM). <https://www.rfc-editor.org/rfc/rfc5869>
- XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03 appendix A.3.1 (`AEAD_XCHACHA20_POLY1305`). Key 32 bytes, IV 24 bytes, tag 16 bytes. <https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt>

`encrypt_authenticated` does not return ciphertext. The vault key schedule is the next milestone.
