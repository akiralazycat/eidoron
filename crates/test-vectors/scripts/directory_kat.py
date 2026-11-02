#!/usr/bin/env python3
"""Independent plaintext bodies for one directory, one file descriptor, and one chunk.

RFC 8949 preferred lengths only. This script does not call the Rust crate and
does not produce ciphertext. Re-run it to check the constants. Do not replace
those constants with bytes printed by the Rust tests.
"""

from __future__ import annotations

DIR_ID = bytes([0x11]) * 16
FILE_OBJECT = bytes([0x22]) * 32
FILE_ID = bytes([0x44]) * 16
CHUNK_OBJECT = bytes([0x55]) * 32
CHUNK_PAYLOAD = b"synthetic"


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


def encode_len(major: int, length: int) -> bytes:
    head = major << 5
    if length < 24:
        return bytes([head + length])
    if length < 256:
        return bytes([head + 24, length])
    if length < 65536:
        return bytes([head + 25]) + length.to_bytes(2, "big")
    raise SystemExit("length too wide for this script")


def encode_bstr(data: bytes) -> bytes:
    return encode_len(2, len(data)) + data


def encode_text(text: str) -> bytes:
    data = text.encode("utf-8")
    return encode_len(3, len(data)) + data


def encode_array(items: list[bytes]) -> bytes:
    return encode_len(4, len(items)) + b"".join(items)


def encode_map(pairs: list[tuple[int, bytes]]) -> bytes:
    body = b"".join(encode_uint(key) + value for key, value in pairs)
    return encode_len(5, len(pairs)) + body


def encode_null() -> bytes:
    return bytes([0xF6])


def directory_body() -> bytes:
    entry = encode_array(
        [
            encode_text("file.txt"),
            encode_uint(3),
            encode_bstr(FILE_OBJECT),
        ]
    )
    payload = encode_map(
        [
            (0, encode_bstr(DIR_ID)),
            (1, encode_null()),
            (2, encode_array([entry])),
        ]
    )
    return bytes([0x02, 0x00]) + payload


def file_descriptor_body() -> bytes:
    payload = encode_map(
        [
            (0, encode_bstr(FILE_ID)),
            (1, encode_bstr(DIR_ID)),
            (2, encode_uint(len(CHUNK_PAYLOAD))),
            (3, encode_array([encode_bstr(CHUNK_OBJECT)])),
        ]
    )
    return bytes([0x03, 0x00]) + payload


# Chunk schema 0x01. Header is 26 bytes: kind, schema, file id, ordinal, true length.
# Payload is padded to a power of two with a 4096-byte floor, capped at the
# plaintext budget. Schema 0x00 is the dropped unpadded layout.
CHUNK_HEADER = 26
MAX_CHUNK_PAYLOAD = 1_048_576 - CHUNK_HEADER
PAD_FLOOR = 4096


def padded_len(true_len: int) -> int:
    if true_len <= 0 or true_len > MAX_CHUNK_PAYLOAD:
        raise SystemExit("payload length is not a chunk")
    if true_len == MAX_CHUNK_PAYLOAD:
        return true_len
    padded = 1 << (true_len - 1).bit_length()
    if padded < PAD_FLOOR:
        padded = PAD_FLOOR
    if padded > MAX_CHUNK_PAYLOAD:
        padded = MAX_CHUNK_PAYLOAD
    return padded


def chunk_body() -> bytes:
    true_len = len(CHUNK_PAYLOAD)
    pad = padded_len(true_len)
    return (
        bytes([0x04, 0x01])
        + FILE_ID
        + (0).to_bytes(4, "big")
        + true_len.to_bytes(4, "big")
        + CHUNK_PAYLOAD
        + bytes(pad - true_len)
    )


def unpadded_v0_chunk() -> bytes:
    return bytes([0x04, 0x00]) + FILE_ID + (0).to_bytes(4, "big") + CHUNK_PAYLOAD


def rust_array(name: str, data: bytes) -> None:
    body = ", ".join(f"0x{byte:02x}" for byte in data)
    print(f"pub const {name}: &[u8] = &[{body}];")


def main() -> None:
    rust_array("DIRECTORY_FILE_TXT", directory_body())
    rust_array("FILE_DESCRIPTOR_SYNTHETIC", file_descriptor_body())
    rust_array("CHUNK_SYNTHETIC", chunk_body())
    rust_array("CHUNK_UNPADDED_V0", unpadded_v0_chunk())


if __name__ == "__main__":
    main()
