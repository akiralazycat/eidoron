# Metadata a sync folder shows

- Created: **2026-11-01**
- Status: **last-chunk padding is implemented; timestamps and chunk counts are still visible**
- Related: [envelope](09_ENVELOPE_FORMAT_V0.md), [storage](03_STORAGE_SYNC.md), [gc policy](15_GC_POLICY.md)

The product writes a directory the user's own sync tool copies. That tool sees every name, length, and timestamp in the folder. It does not see the passphrase or the unwrapped root. Last-chunk padding hides the exact remainder. It does not hide how many full chunks a file has, or when files were written.

## What the folder contains

| Item | What the provider sees | What it does not see |
|---|---|---|
| `vault.header` | Fixed name. Always 136 bytes. Magic `EIDORON\0`, suite, `vault_id`, KDF salt, Argon2id `m`/`t`/`lanes`, wrap nonce, and the wrapped root. The bytes do not change when a file is added, replaced, or unlinked. | The passphrase and the raw root. |
| Object files | One flat directory. Each name is 64 lowercase hex characters, the random 32-byte object id. | Plaintext file names, directory names, and content ids. Content ids are not filenames. |
| Object lengths | Envelope is an 88-byte prefix plus ciphertext and a 16-byte tag. A chunk header is 26 bytes (`kind`, schema `0x01`, `file_id`, ordinal, unpadded length). A full chunk's payload is 1,048,550 bytes and is not padded further. A shorter last chunk's payload is padded with zeros to a bucket before AEAD, so the file length is `88 + 26 + bucket + 16` = `130 + bucket`. | The exact unpadded length. Which hex files belong to the same user file, except by clustering writes that share a timestamp. |
| Commit, directory, and descriptor objects | Same hex names. Their lengths change with the number of directory entries and the number of chunk ids, not with the user's display name. | The names inside the directory. |
| Timestamps | Each successful put sets the file's modification time to the time of that write. | Nothing is done to round or freeze mtimes. |
| Layout | No per-directory subfolders. Conflict copies such as `notes (1)` and `name (conflicted copy)` stay under the names the sync tool chose. Leftover `.eidoron-tmp-` files are removed when a vault is created or opened, not on a later status read. | The encrypted tree shape as a path. |
| Writes | `write_file` adds a chunk object per piece, a descriptor, a new directory object, and a new commit. `replace_file` and `delete_entry` add new objects and leave the previous ones in place. The file count goes up. | Deletion of an old object. Two equal plaintexts do not produce equal chunk files: each object has its own id, key, and nonce. |

Tests pin the name rule and the bucket rule: `object_names_hide_plaintext_and_chunk_size_tracks_the_payload` and `last_chunk_padding_is_a_bucket_and_is_not_yielded`. A one-byte file and a 4096-byte file share one chunk length. A 4097-byte file uses the next bucket.

## Last-chunk buckets

Only the final chunk is padded, and only when its unpadded payload is shorter than 1,048,550 bytes. Full chunks stay at that maximum. The bucket is the next power of two, and at least 4096. If that power of two would exceed 1,048,550, the bucket is 1,048,550.

This is not [Padmé](https://lbarman.ch/blog/padme/). Padmé wastes less on sizes such as 4097 bytes (its step there is tens of bytes, not 4095). Powers of two are the scheme here because the boundaries are a short list, the code is a floor plus `next_power_of_two`, and a failed padding byte is easy to define. The cost is accepted: just above a power of two, almost a whole bucket is padding, and just above 512 KiB the pad can be about 512 KiB.

The unpadded length is a `u32` inside the chunk, covered by the chunk AEAD, and the file's total size is inside the descriptor AEAD. On read those two lengths must agree. Bytes after the unpadded length must be zero. A mismatch is `Unavailable`. Streaming returns only the unpadded prefix. Schema `0x00` chunks, which had no length field and no padding, are rejected. This tree has not shipped a reader for them.

| Unpadded payload | Bucket | Padding bytes |
|---:|---:|---:|
| 1 | 4096 | 4095 |
| 4096 | 4096 | 0 |
| 4097 | 8192 | 4095 |
| 8192 | 8192 | 0 |
| 524288 | 524288 | 0 |
| 524289 | 1048550 | 524261 |
| 1048550 (full chunk) | 1048550 | 0 |

On disk those buckets are `130 + bucket` bytes. Empty files still have zero chunk objects.

## What an observer can infer

- **That a vault exists**, and which KDF parameters it uses, from `vault.header`.
- **How many objects exist**, and that an edit happened, from new hex files and their mtimes. Replace and unlink both look like growth, not like a shrinking folder.
- **A size class, not an exact remainder.** A one-chunk file is one of the buckets above. A longer file is `N` full chunks plus one bucket. `N` is still visible if the writes share a timestamp. Dummy chunks that would hide `N` are not written.
- **Edit frequency**, from mtimes of new commits and directories.
- **Fan-out of a directory create**, roughly, because `append_directory` writes one object per subdirectory plus a root directory and a commit, in one burst.
- **Not plaintext equality.** Identical payloads under two names produce different chunk ciphertexts.
- **Not the user's names**, from object filenames. A sync tool's own conflict-copy name is the exception, and this app does not choose it.

## Decisions

| Idea | Decision | Why |
|---|---|---|
| Pad the last chunk to a power-of-two bucket with a 4096-byte floor | **Implemented** | Hides the exact remainder. Full chunks stay at the maximum so a large file is not padded twice. |
| Padmé-style smaller steps | Not used | Less waste at 4097 bytes, harder to audit. Revisit only if the 512 KiB top bucket is too costly. |
| Dummy chunks so every file has the same count | **Not implemented** | Owner decision. Chunk count remains a coarse size signal. |
| Round or freeze mtimes | **Not implemented** | Owner decision. Sync tools use mtimes. |
| Hide the header magic | Not implemented | The product is an identifiable archive. |
| Delete unreachable objects to shrink the folder | Not implemented | See [15_GC_POLICY.md](15_GC_POLICY.md). |
