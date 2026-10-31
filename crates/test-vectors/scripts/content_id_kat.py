#!/usr/bin/env python3
"""Independent oracle for the keyed content id.

HKDF-SHA256 and HMAC-SHA256 are the RFC constructions on Python's hmac.
The root and vault id match the M2 synthetic constants. This script does
not call the Rust crate. The content id is not SHA-256(plaintext).
"""

from __future__ import annotations

import hashlib
import hmac

VAULT_ID = bytes([0x11]) * 16
ROOT_SECRET = bytes([0x42]) * 32
PLAINTEXT = b"synthetic-content"
INFO = b"eidoron/v0/content-id" + VAULT_ID


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
    content_key = hkdf_expand(hkdf_extract(VAULT_ID, ROOT_SECRET), INFO, 32)
    mac = hmac.new(content_key, PLAINTEXT, hashlib.sha256).digest()
    plain = hashlib.sha256(PLAINTEXT).digest()
    if mac == plain:
        raise SystemExit("keyed id collided with a plain hash")
    rust_array("CONTENT_ID_KEY", content_key)
    rust_array("CONTENT_ID", mac)
    rust_array("PLAIN_SHA256", plain)


if __name__ == "__main__":
    main()
