# Metadata a sync folder shows

- Created: **2026-11-01**
- Status: **observation of the current local vault, not a claim that sizes or timestamps are hidden**
- Related: [envelope](09_ENVELOPE_FORMAT_V0.md), [storage](03_STORAGE_SYNC.md)

The product writes a directory the user's own sync tool copies. That tool sees every name, length, and timestamp in the folder. It does not see the passphrase or the unwrapped root. This note lists what is visible today and what a later change could hide. Padding is not implemented.

## What the folder contains

| Item | What the provider sees | What it does not see |
|---|---|---|
| `vault.header` | Fixed name. Always 136 bytes. Magic `EIDORON\0`, suite, `vault_id`, KDF salt, Argon2id `m`/`t`/`lanes`, wrap nonce, and the wrapped root. The bytes do not change when a file is added, replaced, or unlinked. | The passphrase and the raw root. |
| Object files | One flat directory. Each name is 64 lowercase hex characters, the random 32-byte object id. | Plaintext file names, directory names, and content ids. Content ids are not filenames. |
| Object lengths | Envelope is an 88-byte prefix plus ciphertext. A chunk's plaintext is 22 bytes of identity plus the file bytes, and the AEAD tag is 16 bytes. A chunk file is therefore `88 + 22 + payload + 16` bytes. The last chunk's length is the exact remainder. | Which hex files belong to the same user file, except by clustering writes that share a timestamp. |
| Commit, directory, and descriptor objects | Same hex names. Their lengths change with the number of directory entries and the number of chunk ids, not with the user's display name. | The names inside the directory. |
| Timestamps | Each successful put sets the file's modification time to the time of that write. | Nothing is done to round or freeze mtimes. |
| Layout | No per-directory subfolders. Conflict copies such as `notes (1)` and `name (conflicted copy)` stay under the names the sync tool chose. Leftover `.eidoron-tmp-` files are removed when a vault is created or opened, not on a later status read. | The encrypted tree shape as a path. |
| Writes | `write_file` adds a chunk object per piece, a descriptor, a new directory object, and a new commit. `replace_file` and `delete_entry` add new objects and leave the previous ones in place. The file count goes up. | Deletion of an old object. Two equal plaintexts do not produce equal chunk files: each object has its own id, key, and nonce. |

A test pins the name rule and the chunk-length rule: `object_names_hide_plaintext_and_chunk_size_tracks_the_payload`. Changing padding later has to change that test on purpose.

## What an observer can infer

- **That a vault exists**, and which KDF parameters it uses, from `vault.header`.
- **How many objects exist**, and that an edit happened, from new hex files and their mtimes. Replace and unlink both look like growth, not like a shrinking folder.
- **Approximate file size.** A one-chunk file's chunk object length minus 126 bytes is the plaintext length. A multi-chunk file is a set of full chunks (1,048,554 bytes of payload each) plus one shorter last chunk. The provider is not told which objects form the set, but objects written in one burst are a strong hint.
- **Edit frequency**, from mtimes of new commits and directories.
- **Fan-out of a directory create**, roughly, because `append_directory` writes one object per subdirectory plus a root directory and a commit, in one burst.
- **Not plaintext equality.** Identical payloads under two names produce different chunk ciphertexts.
- **Not the user's names**, from object filenames. A sync tool's own conflict-copy name is the exception, and this app does not choose it.

## Mitigations not implemented

| Idea | What it would hide | Cost |
|---|---|---|
| Pad every chunk payload to the 1,048,554-byte cap | Exact length of a short file | About 1 MiB of ciphertext per short file. Chunk count still leaks the size class "one chunk" versus "many". |
| Pad only the last chunk up to a power-of-two bucket | Exact remainder | Less waste. The bucket is still a size class. Full chunks stay obvious. |
| Add dummy chunks so every file has the same count | Chunk-count as a size signal | Large and easy to get wrong if dummies are distinguishable by size. |
| Keep the flat hex layout | Path names | Already the layout. Do not add a folder per directory; that would publish the tree. Bursts of new files still mark one edit. |
| Round or freeze mtimes | Edit times | Sync tools use mtimes. Changing them can cause extra uploads or missed updates. Leave them alone for v1. |
| Hide the header magic | "This is an Eidoron vault" | Breaks detection of the format. The product is an identifiable archive. Accept this leak. |

Recommendation: do not pad in the current milestone. If padding is added later, pad the last chunk to a documented size class, keep full chunks at the maximum, and update the length assertion in the vault test. Do not delete unreachable objects to tidy the folder. Do not rename conflict copies.
