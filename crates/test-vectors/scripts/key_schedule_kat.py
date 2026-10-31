#!/usr/bin/env python3
"""Independent oracle for the synthetic M2 key schedule.

Computes RawPwdKey, WrapKey, ObjectKey, and the wrapped RootSecret with
libraries other than the Rust crate:

- Argon2id via argon2-cffi (libargon2), no pepper and no associated data
- HKDF-SHA256 via the RFC 5869 construction on hashlib HMAC
- XChaCha20-Poly1305 via PyNaCl (libsodium)

Inputs match docs/09_ENVELOPE_FORMAT_V0.md and the synthetic header in
src/lib.rs bytes 0..88. Do not replace this output with bytes printed by
the Rust tests.

Requires: python3 -m pip install 'argon2-cffi' 'PyNaCl'
"""

from __future__ import annotations

import hashlib
import hmac

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

PASSPHRASE = "synthetic-only"
SALT = bytes([0x22]) * 16
VAULT_ID = bytes([0x11]) * 16
OBJECT_ID = bytes([0x55]) * 32
ROOT_SECRET = bytes([0x42]) * 32
MEMORY_KIB = 65536
ITERATIONS = 3
LANES = 4
WRAP_INFO = b"eidoron/v0/password-wrap" + VAULT_ID
OBJECT_INFO = b"eidoron/v0/object-aead" + OBJECT_ID


def synthetic_aad() -> bytes:
    """Public header bytes 0..88. The wrap nonce occupies bytes 64..88."""
    out = bytearray(88)
    out[0:8] = b"EIDORON\x00"
    out[12:14] = (1).to_bytes(2, "big")
    out[16:32] = VAULT_ID
    out[32:48] = SALT
    out[48:52] = (0x13).to_bytes(4, "big")
    out[52:56] = MEMORY_KIB.to_bytes(4, "big")
    out[56:60] = ITERATIONS.to_bytes(4, "big")
    out[60:64] = LANES.to_bytes(4, "big")
    out[64:88] = bytes([0x33]) * 24
    return bytes(out)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def rust_array(name: str, data: bytes) -> None:
    body = ", ".join(f"0x{byte:02x}" for byte in data)
    print(f"pub const {name}: [u8; {len(data)}] = [{body}];")


def main() -> None:
    raw = hash_secret_raw(
        secret=PASSPHRASE.encode("utf-8"),
        salt=SALT,
        time_cost=ITERATIONS,
        memory_cost=MEMORY_KIB,
        parallelism=LANES,
        hash_len=32,
        type=Type.ID,
        version=19,
    )
    wrap_key = hkdf_expand(hkdf_extract(VAULT_ID, raw), WRAP_INFO, 32)
    object_key = hkdf_expand(hkdf_extract(VAULT_ID, ROOT_SECRET), OBJECT_INFO, 32)
    aad = synthetic_aad()
    nonce = aad[64:88]
    wrapped = crypto_aead_xchacha20poly1305_ietf_encrypt(ROOT_SECRET, aad, nonce, wrap_key)
    if len(raw) != 32 or len(wrap_key) != 32 or len(object_key) != 32 or len(wrapped) != 48:
        raise SystemExit("unexpected oracle length")
    rust_array("RAW_PWD_KEY", raw)
    rust_array("WRAP_KEY", wrap_key)
    rust_array("OBJECT_KEY", object_key)
    rust_array("WRAPPED_ROOT", wrapped)


if __name__ == "__main__":
    main()
