#!/usr/bin/env python3
"""Independent fixtures for the genesis-commit predecessor check.

Encodes a few commit bodies with RFC 8949 preferred lengths. This is not a
CBOR library and it does not call the Rust crate. Expected labels come from
docs/09_ENVELOPE_FORMAT_V0.md: kind 0x01 and generation 0 must have a null
predecessor. Other generations and other kinds are outside that single check.
"""

from __future__ import annotations

ROOT_DIR = bytes([0x71]) * 32
COMMIT_ID = bytes([0x81]) * 16
PRIOR = bytes([0x91]) * 32


def encode_uint(value: int) -> bytes:
    if value < 0:
        raise SystemExit("unsigned only")
    if value < 24:
        return bytes([value])
    if value < 256:
        return bytes([0x18, value])
    if value < 65536:
        return bytes([0x19]) + value.to_bytes(2, "big")
    if value < 2**32:
        return bytes([0x1A]) + value.to_bytes(4, "big")
    if value < 2**64:
        return bytes([0x1B]) + value.to_bytes(8, "big")
    raise SystemExit("uint too wide")


def encode_uint_as_u64(value: int) -> bytes:
    """Deliberately non-minimal 8-byte unsigned integer."""
    return bytes([0x1B]) + value.to_bytes(8, "big")


def encode_bstr(data: bytes) -> bytes:
    if len(data) < 24:
        return bytes([0x40 + len(data)]) + data
    if len(data) < 256:
        return bytes([0x58, len(data)]) + data
    raise SystemExit("bstr too long for this script")


def encode_null() -> bytes:
    return bytes([0xF6])


def encode_map(pairs: list[tuple[int, bytes]]) -> bytes:
    body = b"".join(encode_uint(key) + value for key, value in pairs)
    if len(pairs) >= 24:
        raise SystemExit("map too large for this script")
    return bytes([0xA0 + len(pairs)]) + body


def commit_body(generation: bytes, prior: bytes) -> bytes:
    payload = encode_map(
        [
            (0, generation),
            (1, prior),
            (2, encode_bstr(ROOT_DIR)),
            (3, encode_bstr(COMMIT_ID)),
        ]
    )
    return bytes([0x01, 0x00]) + payload


def rust_array(name: str, data: bytes) -> None:
    body = ", ".join(f"0x{byte:02x}" for byte in data)
    print(f"pub const {name}: &[u8] = &[{body}];")


def main() -> None:
    # Spec: generation 0 requires prior_commit_id = null.
    rust_array("GENESIS_NULL", commit_body(encode_uint(0), encode_null()))
    print('pub const GENESIS_NULL_EXPECT: &str = "EmptyPredecessor";')
    # Spec: a present prior at generation 0 fails this check.
    rust_array("GENESIS_WITH_PRIOR", commit_body(encode_uint(0), encode_bstr(PRIOR)))
    print('pub const GENESIS_WITH_PRIOR_EXPECT: &str = "PredecessorNotEmpty";')
    # A zero-length byte string is not null.
    rust_array("GENESIS_EMPTY_BSTR", commit_body(encode_uint(0), encode_bstr(b"")))
    print('pub const GENESIS_EMPTY_BSTR_EXPECT: &str = "PredecessorNotEmpty";')
    # This check does not judge generation > 0.
    rust_array("LATER_WITH_PRIOR", commit_body(encode_uint(1), encode_bstr(PRIOR)))
    print('pub const LATER_WITH_PRIOR_EXPECT: &str = "NotGenesis";')
    # Non-minimal uint 0 is not preferred-length CBOR.
    rust_array("NONMINIMAL_ZERO", commit_body(encode_uint_as_u64(0), encode_null()))
    print('pub const NONMINIMAL_ZERO_EXPECT: &str = "Unreadable";')
    # Kind 0x02 is not a commit. The payload is not interpreted.
    rust_array("DIRECTORY_KIND", bytes([0x02, 0x00, 0x00]))
    print('pub const DIRECTORY_KIND_EXPECT: &str = "NotACommit";')


if __name__ == "__main__":
    main()
