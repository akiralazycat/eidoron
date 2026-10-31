# Synthetic fixtures and published primitive vectors

The helpers in `src/lib.rs` still create **untrusted, invalid-ciphertext shapes** for the public v0 parser. They are not authenticated files, not a valid encrypted archive, and not sample user passwords.

Published primitive known-answer tests live in `crates/crypto/src/published_kat.rs`. Expected bytes were copied from the documents below. They were not produced by running this crate and pasting the output back.

- Argon2id: RFC 9106 section 5.3 (version 19, 32 KiB, 3 passes, 4 lanes, 32-byte tag, with the published secret and associated data). <https://www.rfc-editor.org/rfc/rfc9106>
- HKDF-SHA-256: RFC 5869 appendix A.1 test case 1 (PRK and 42-byte OKM). <https://www.rfc-editor.org/rfc/rfc5869>
- XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03 appendix A.3.1 (`AEAD_XCHACHA20_POLY1305`). Key 32 bytes, IV 24 bytes, tag 16 bytes. <https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt>

The synthetic key schedule lives in `src/key_schedule.rs`. Its expected bytes were printed by `scripts/key_schedule_kat.py` using argon2-cffi 25.1.0, the RFC 5869 HKDF construction on Python's `hmac`, and PyNaCl 1.6.2. Inputs are the passphrase `synthetic-only`, salt `0x22`×16, vault id `0x11`×16, object id `0x55`×32, and root secret `0x42`×32. Argon2id uses m=65536 KiB, t=3, lanes=4. `ObjectKey` is derived from the root secret. The passphrase path produces `RawPwdKey` and `WrapKey`. Re-run the script to check the constants. Do not replace them with output from the Rust tests.

The object AEAD vector lives in `src/object_aead.rs`. Its ciphertext was printed by `scripts/object_aead_kat.py` using PyNaCl 1.6.2 and the M2 `OBJECT_KEY` bytes. Plaintext is kind `0x04`, schema `0x00`, and the ASCII payload `synthetic`. The nonce is 24 bytes of `0x66`. Re-run the script to check the constant. Do not replace it with output from the Rust tests.

`encrypt_authenticated` now seals an object body. `status()` is still `NotImplemented` because there is no vault session. The next milestone checks a decrypted commit's predecessor without a CBOR decoder.
