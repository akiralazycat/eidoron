#!/usr/bin/env python3
"""Independent oracle for one synthetic object AEAD.

Encrypts `kind || schema || payload` under the M2 ObjectKey with
PyNaCl (libsodium XChaCha20-Poly1305). The key bytes are the M2 oracle
output already recorded in src/key_schedule.rs. Do not replace this
output with bytes printed by the Rust crate.

Requires: python3 -m pip install 'PyNaCl'
"""

from __future__ import annotations

from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

# Copied from the M2 script output in src/key_schedule.rs (OBJECT_KEY).
OBJECT_KEY = bytes(
    [
        0x06, 0x86, 0x5B, 0xC2, 0xCF, 0x41, 0x91, 0xF3,
        0xAA, 0xEA, 0xF9, 0x6D, 0x64, 0xB3, 0x92, 0x51,
        0xBB, 0x32, 0x8F, 0x16, 0x00, 0x03, 0x3F, 0x49,
        0xB6, 0xF5, 0xB5, 0x36, 0xB6, 0xB1, 0x6B, 0xE4,
    ]
)
NONCE = bytes([0x66]) * 24
# kind 0x04 (file chunk), schema 0x00, payload ASCII "synthetic".
PLAINTEXT = bytes([0x04, 0x00]) + b"synthetic"
VAULT_ID = bytes([0x11]) * 16
OBJECT_ID = bytes([0x55]) * 32


def object_aad() -> bytes:
    """88-byte object prefix. Nonce is bytes 60..84. ciphertext_len includes the tag."""
    out = bytearray(88)
    out[0:8] = b"EIDOBJ\x00\x00"
    out[10:12] = (1).to_bytes(2, "big")
    out[12:28] = VAULT_ID
    out[28:60] = OBJECT_ID
    out[60:84] = NONCE
    out[84:88] = (len(PLAINTEXT) + 16).to_bytes(4, "big")
    return bytes(out)


def rust_array(name: str, data: bytes) -> None:
    body = ", ".join(f"0x{byte:02x}" for byte in data)
    print(f"pub const {name}: [u8; {len(data)}] = [{body}];")


def main() -> None:
    aad = object_aad()
    sealed = crypto_aead_xchacha20poly1305_ietf_encrypt(PLAINTEXT, aad, NONCE, OBJECT_KEY)
    if len(sealed) != len(PLAINTEXT) + 16:
        raise SystemExit("unexpected ciphertext length")
    rust_array("PLAINTEXT", PLAINTEXT)
    rust_array("NONCE", NONCE)
    rust_array("AAD", aad)
    rust_array("CIPHERTEXT_AND_TAG", sealed)


if __name__ == "__main__":
    main()
