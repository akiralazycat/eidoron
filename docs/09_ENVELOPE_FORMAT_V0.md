# Eidoron Vault Envelope v0 — candidate binary protocol

- Created / updated: 2026-10-31 JST
- Milestone: P1.3 (documentation only)
- Status: **candidate format amended by P1.5 internal review**; no implementation, executable vectors, independent audit or release approval
- Related: [ADR-0003](decisions/0003-envelope-and-key-hierarchy.md), [ADR-0002](decisions/0002-crypto-dependencies-ffi.md), [P1.1 security targets](08_SECURITY_TARGET.md)
- MUST / MUST NOT / SHOULD describe **future implementation requirements**, not validated existing behavior.

## 0. Boundaries and nonclaims

**Vault v0 only:** an openly identifiable encrypted archive containing encrypted immutable objects and an untrusted mutable head pointer. A provider can identify the archive format, object count, sizes and modification timestamps. **Not a hidden volume. Not deniable.** Shadow/Specter cannot reuse v0's visible vault header as evidence of hidden-space deniability. The eventual hidden-space format needs its own independently reviewed construction.

The following fixed layout is specific enough for a prototype and test fixtures; it MUST NOT be treated as frozen for user data until P1.4 tests, P1.5 design review and a version/compatibility decision.

Basic conventions:
- Byte offsets are zero-based; end offsets in tables are exclusive.
- Integers are unsigned **big-endian**; all text in envelope constants is ASCII.
- Every public fixed-length field must have its exact length; append/trailing bytes are rejected.
- Random IDs and nonces come from an OS CSPRNG; no seedable RNG in production.
- AEAD = **XChaCha20-Poly1305**, 32-byte key, 24-byte nonce, 16-byte tag appended to ciphertext. AAD is supplied *exactly* as specified; the complete ciphertext and tag must authenticate before plaintext is exposed.
- `||` denotes byte concatenation, `u32be(n)` an unsigned 4-byte big-endian integer, `ASCII(s)` the exact ASCII bytes.
- `HKDF` means HKDF-Extract/Expand with HMAC-SHA256 per RFC 5869, output length 32 bytes. Parameters below are **candidate v0 protocol constants**, not a proof of security.

## 1. Public vault header: `vault.header` (136 bytes)

One header per baseline Vault; do not allow a set of arbitrary passphrase slots or visible alternate namespace flags.

| Byte range | Field | Size | Value / interpretation |
|---|---|---:|---|
| 0..8 | magic | 8 | ASCII `EIDORON` + `00` hex |
| 8..10 | major | 2 | `0x0000` for candidate v0 |
| 10..12 | minor | 2 | `0x0000` |
| 12..14 | suite | 2 | `0x0001` = Argon2id(0x13) + HKDF-SHA256 + XChaCha20-Poly1305 |
| 14..16 | flags | 2 | `0x0000`; unknown nonzero flags MUST be rejected |
| 16..32 | vault_id | 16 | random, immutable within vault lifetime |
| 32..48 | kdf_salt | 16 | random salt for this passphrase wrapper |
| 48..52 | argon2_version | 4 | `0x00000013` (Argon2 v=19) |
| 52..56 | m_cost_kib | 4 | memory cost (KiB), bounded before derivation |
| 56..60 | t_cost | 4 | iteration count, bounded before derivation |
| 60..64 | lanes | 4 | degree of parallelism, bounded before derivation |
| 64..88 | wrap_nonce | 24 | fresh random nonce for root-secret wrap |
| 88..136 | wrapped_root | 48 | AEAD ciphertext (32-byte root secret + 16-byte tag) |

Exactly 136 bytes; any future extension MUST use a new recognized format version, not silently append optional fields. Path `vault.header` is a provider mapping convention for baseline storage, **not an authenticated secret path**.

### Root creation and unlock

1. Generate `vault_id` (16 bytes), `kdf_salt` (16), `RootSecret` (32 random bytes), `wrap_nonce` (24).
2. Encode passphrase into **exact UTF-8 bytes as entered**, with no automatic Unicode normalization, trimming or case folding. Client input methods must not silently transform it. Encoding must use valid Unicode scalar values; reject over 1024 UTF-8 bytes. No empty passphrases. Enforce a separate strength policy before shipping; not specified by this byte format.
3. `RawPwdKey = Argon2id(passphrase_utf8, kdf_salt, m_cost_kib, t_cost, lanes, output_len=32, version=0x13)`.
4. `WrapPRK = HKDF-Extract(salt=vault_id, IKM=RawPwdKey)`.
5. `WrapKey = HKDF-Expand(WrapPRK, info=ASCII("eidoron/v0/password-wrap") || vault_id, L=32)`.
6. `wrapped_root = XChaCha20Poly1305.Encrypt(WrapKey, wrap_nonce, RootSecret, AAD=header[0..88])`; store ciphertext followed by tag.
7. On unlock: first reject malformed/unsupported header or out-of-range KDF parameters, then recompute and AEAD-decrypt. Wrong password, changed header fields, bad tag and corrupted root wrapper all produce a **generic unavailable-to-unlock result**, without unverified plaintext.

No persisted PHC string/password verifier, root-secret hash or additional password oracle. The header is public and recognizably an encrypted Vault; offline guessing remains possible against a user-chosen password. A strong passphrase and meaningful KDF cost matter.

**Candidate parameter profile:** create with Argon2id `m=65536 KiB, t=3, lanes=4`, the RFC 9106 memory-constrained reference option; enforce reader input bounds `65536 ≤ m ≤ 262144 KiB`, `1 ≤ t ≤ 10`, `1 ≤ lanes ≤ 4`, and `m ≥ 8 × lanes`. A client that cannot safely allocate resources MUST refuse unlock with a supported-resource error (not downgrade KDF or silently substitute weaker parameters). **Creation profile and bounds require mobile device measurements and P1.5 review before locking v0.** No other Argon2 variants or versions accepted.

## 2. Root key schedule: independent encrypted objects

`RootSecret` is random, 32 bytes, portable with valid passphrase or separately approved recovery. It stays stable across *passphrase rewrap* and changes only with a coordinated full **root rotation**, which requires all data and trusted pointers to be migrated; see §7.

For each object, independently derive its AEAD key:

- `VaultPRK = HKDF-Extract(salt=vault_id, IKM=RootSecret)`
- `ObjectKey(object_id) = HKDF-Expand(VaultPRK, info=ASCII("eidoron/v0/object-aead") || object_id, L=32)`

Every `object_id` MUST be freshly generated as 32 random bytes and MUST NOT be recycled for a different plaintext object, even after deletion or an interrupted write. This design selects **derived per-object keys**, not random per-file keys with a wrapping table. It makes passphrase-only changes header-only but root rotation an expensive re-encryption operation. Sharing/per-file delegation is NOT provided in v0.

The encrypted object's inner schema kind is not an independent secret key domain; an authenticated reader MUST verify the requested kind, parent and ordinal from trusted manifest references and decrypted body fields. The same key SHALL NOT be used for any other purpose; secret log/checkpoint signing is a future separate domain-specific key if required.

## 3. Immutable object envelope: one `objects/<opaque-id>` per object

Provider path is a lower-case hex encoding of the **32-byte object_id** (64 characters); path equality with header ID MUST be checked. Provider-side prefix/hierarchy can change by adapter without changing object bytes, but no secret filename or logical parent may be embedded in provider object names.

| Byte range | Field | Size | Value |
|---|---|---:|---|
| 0..8 | magic | 8 | ASCII `EIDOBJ` + `0000` hex (two zero bytes) |
| 8..10 | major | 2 | `0x0000` |
| 10..12 | suite | 2 | `0x0001` |
| 12..28 | vault_id | 16 | matches verified header |
| 28..60 | object_id | 32 | random; must match expected ID/path |
| 60..84 | nonce | 24 | random AEAD nonce, never deliberately reused |
| 84..88 | ciphertext_len | 4 | length including 16-byte authentication tag |
| 88..end | encrypted_body || tag | `ciphertext_len` | no trailing data |

`AAD = envelope[0..88]` (exact 88 bytes) and `Key = ObjectKey(object_id)`; plaintext is exactly `kind:u8 || body_schema:u8 || payload`. `body_schema = 0x00` in this candidate. The object type is encrypted; unverified bytes cannot be parsed as object content.

`2 ≤ plaintext_len ≤ 1,048,576` bytes; `18 ≤ ciphertext_len ≤ 1,048,592`. Every encrypted body has the kind+schema prefix; the parser MUST reject a 1-byte body. Hard cap before allocation; integer overflow, surplus bytes, mismatched declared sizes or malformed prefix rejected. No compression in v0, avoiding decompression-bomb handling and variable compression-state ambiguity.

Each object is **immutable**: modification creates a new random ID, freshly derived object key and fresh random nonce; never overwrite an object at an existing ID. A storage retry may resend the *already sealed* ciphertext bytes of a previously prepared immutable object. It MUST NOT ask the cipher to encrypt new plaintext under the same ID and nonce.

**Decision (2026-10-31, owner, recorded while PR #11 was open):** the cipher MUST draw a fresh 24-byte OS CSPRNG nonce on every seal, including when the plaintext bytes match an earlier seal. Identical plaintexts therefore yield different ciphertexts. Returning a previous nonce and ciphertext for a repeated plaintext reveals plaintext equality and is forbidden. The cipher MUST NOT compare or decrypt a previous ciphertext in order to accept or reject a new seal. Idempotency, if required, belongs to the storage layer and is keyed by `object_id` together with a **keyed** content hash, as decided below. It is not decided by ciphertext equality.

**Decision (2026-10-31, owner):** a content hash used for storage idempotency MUST be keyed, or the hash MUST be stored only as ciphertext. Acceptable keyed constructions include HMAC-SHA256, keyed BLAKE2, or a key produced by HKDF from vault secrets. A plain hash of the plaintext (for example SHA-256 of the file bytes, with no key) MUST NOT be stored and MUST NOT be used as a storage key or deduplication id. Equal plain hashes would show the storage provider that two objects have the same plaintext.

### Authenticated inner object kinds

- `0x01`: **commit root**: deterministic CBOR payload.
- `0x02`: **directory**: deterministic CBOR payload.
- `0x03`: **file descriptor**: deterministic CBOR payload.
- `0x04`: **file chunk**: `file_id:16 || ordinal:u32be || file_bytes`.
- **Implementation limit (2026-10-31, M5.22):** `check_chunk_identity` compares one decrypted chunk's 16-byte `file_id` and big-endian `ordinal` with the caller's expectation. A mismatch of either field is the same error. Payload bytes are not compared, and no object store is scanned. Kind other than `0x04` is not a chunk. A short body or a schema other than `0x00` is unreadable.

On read, `kind` and `body_schema` MUST match the expected reference type. File-chunk `file_id` and `ordinal` MUST match the authenticated descriptor. A directory entry MUST match the child's authenticated logical ID and parent reference; no unauthenticated traversal into a caller-selected ciphertext object.

Chunk payload bounds: total plaintext ≤ 1 MiB, hence `file_bytes ≤ 1,048,554` (1,048,576 - 2 prefix -16 file ID - 4 ordinal). A file descriptor MUST NOT refer to more than 8192 chunks. Empty files have zero chunks.

## 4. Authenticated CBOR payload schemas

Use **RFC 8949 core deterministic encoding** for commit roots, directories and file descriptors: preferred-length integer/text/byte/map encodings; all definite lengths; keys sorted bytewise by their deterministic encoded form. For this protocol, limit schemas to integer map keys, unsigned integer values, UTF-8 strings, byte strings, arrays and null. Reject floats, tags, negative integers, indefinite lengths, duplicate/unknown map keys, nonminimal encodings, out-of-order keys and trailing bytes. Canonical encoding is validated by a strict decoder; never parse then silently normalize attacker bytes.

The following maps are *complete* v0 proposals (integer keys appear in ascending order). All byte strings have exact lengths.

### Commit root — kind 0x01

`{ 0: generation:uint64, 1: prior_commit_id:bstr(32)|null, 2: root_directory_object_id:bstr(32), 3: commit_id:bstr(16) }`

- `generation=0` must have `prior_commit_id=null`; `generation>0` must have a predecessor ID.
- **Implementation limit (2026-10-31, M5):** the code check reads a decrypted body only far enough to apply the generation-0 rule. Kind `0x01`, schema `0x00`, generation 0, and a null predecessor is `EmptyPredecessor`. Generation 0 with any byte string, including an empty one, is rejected. Kind other than `0x01` is not a commit. Generation other than 0 is reported and not judged. Keys 2 and 3, non-commit payloads, and a general CBOR decoder are not implemented. Non-minimal integer encodings of the fields that are read are rejected.
- `commit_id` is a freshly random 16-byte **logical change identifier** (distinct from 32-byte object ID).
- The untrusted HEAD's expected generation and root object ID MUST match these decrypted fields.
- When previous root is locally available, check declared prior ID and generation chain; malicious provider can withhold older objects and cause availability failure. A valid *older entire chain* cannot be detected without trusted freshness state.

### Directory — kind 0x02

`{ 0: dir_id:bstr(16), 1: parent_dir_id:bstr(16)|null, 2: entries:array }`

- Each entry is exactly `[name:text, child_kind:uint, child_object_id:bstr(32)]`; `child_kind=2` (directory) or `3` (file).
- Names MUST be Unicode NFC, 1..255 UTF-8 bytes, forbid U+0000, slash, `.` and `..`; MUST be unique within a directory by identical UTF-8 bytes. No locale-dependent case folding in v0.
- **Implementation limit (2026-10-31, M5.21):** `check_directory_name` rejects an empty name, a name longer than 255 UTF-8 bytes, a name containing `/` or U+0000, and the whole names `.` and `..`. It does not trim, and it does not check NFC. `file.txt`, `.hidden`, and `...` are accepted. Uniqueness, sort order, and depth are not checked.
- Entries MUST be sorted by unsigned lexicographic order of the **UTF-8 name bytes**; max 4096 entries. Root directory has `parent_dir_id=null`; nonroot has an authenticated parent logical ID matching the referring directory.
- The same directory logical ID referenced from two different logical parents or a directory cycle is invalid. Directory depth ≤ 64.

### File descriptor — kind 0x03

`{ 0: file_id:bstr(16), 1: parent_dir_id:bstr(16), 2: size_bytes:uint64, 3: chunks:array }`

- `chunks` is an ordered array of object IDs `bstr(32)`; max 8192. Index is the chunk ordinal starting at 0.
- The authenticated full file size MUST equal the sum of fully verified chunk `file_bytes` lengths. Do not export a partially verified file as complete.
- The file's logical ID, parent and every chunk must be verified against its authenticated directory/descriptor path. Duplicate chunk IDs in the same descriptor MUST be rejected.
- A file descriptor, directory or chunk cannot be substituted by changing an untrusted server path alone; the enclosing authenticated references determine expectations.

### Payload limits / authenticated graph invariants

- CBOR payload (plus 2-byte prefix) ≤ 1 MiB per object; strings, arrays and arithmetic must be bounded **before allocation**.
- A single verified commit root is the traversal trust anchor *after decrypting it and checking the selected HEAD identity*; no arbitrary orphan object should appear as a valid user file.
- Validate graph/cycles, IDs and generation consistency before exporting; when streaming, authenticate **each chunk before exposing that chunk**, and do not claim entire-file verification until all expected chunks pass. A streamed preview MAY show verified chunks, clearly not claim global file integrity until completion.
- A directory move updates relevant encrypted parent/child records and a new commit; references remain authenticated via the new commit graph.

## 5. Mutable untrusted HEAD pointer (66 bytes)

The provider stores exactly one `vault.head` pointer for the current committed root. Its bytes are *not themselves secret or a freshness anchor*, and its update must use a proven conditional write / atomic transaction model in P3.

| Byte range | Field | Size | Value |
|---|---|---:|---|
| 0..8 | magic | 8 | ASCII `EIDHEAD` + hex `00` |
| 8..10 | major | 2 | `0x0000` |
| 10..26 | vault_id | 16 | matches authenticated root/header |
| 26..34 | generation | 8 | unsigned big-endian |
| 34..66 | commit_root_object_id | 32 | provider object ID for encrypted root |

Read sequence: parse HEAD under strict bounds → find object by `commit_root_object_id` → derive ObjectKey and fully authenticate object → require kind 0x01, `generation` and expected vault ID match → validate object graph. A replaced HEAD pointing to an older *valid* root is not detected by AEAD alone. A local trusted record of last-seen generation/object ID can flag suspected rollback, but recovery on a new device without such a record MUST show **freshness unknown**, not 'current'. The provider may suppress HEAD entirely.

Write proposal: stage all immutable objects and verify successful remote persistence → publish HEAD with conditional write / compare-and-swap against the previously observed version → on CAS failure preserve both edits, fetch/verify competing roots and resolve or produce conflict revisions. P3 MUST define exact provider consistency semantics and visibility/durability; this v0 document does **not** claim that all providers have safe CAS.

## 6. Validation order and error taxonomy

1. Bound maximum raw input sizes and metadata before parsing. The header must be exactly 136 bytes, HEAD exactly 66; object envelope must be ≥ 106 bytes for 2-byte body + tag and ≤ 1,048,680 bytes.
2. Validate public magic, supported version/suite/flags, IDs and Argon2 resource bounds. Reject unknown critical format variants, not guess.
3. Run passphrase KDF only after resource limits; generic wrong-password/corrupt-wrapper error for unauthenticated root.
4. Read authenticated HEAD-selected object using expected vault/object ID, decrypt and validate canonical encoding/expected kind.
5. On traversal authenticate **each referenced object** and cross-check semantic parent, file ID, chunk ordinal, file size, generation and cycles.
6. Return only verified plaintext and honest freshness state; redact secrets and raw passwords from all logs and FFI error messages.

Typed internal errors: `UnsupportedFormat`, `InputTooLarge`, `InvalidEncoding`, `ResourcePolicyUnavailable`, `UnlockUnavailable`, `IntegrityFailure`, `MissingObject`, `FreshnessUnknown`, `SuspectedRollback`, `ConcurrentConflict`, `RemoteUnavailable`, `RecoveryRequired`. UI can coalesce unauthenticated errors where appropriate but MUST NOT hide meaningful user-recovery statuses.

**P1.5 clarified bounds:** complete envelope length is **106..1,048,680 bytes** inclusive. Test both endpoints and reject surplus bytes. See [P1.5 review](11_SECURITY_DESIGN_REVIEW.md).

## 7. Password changes, root rotation, restore, migrations

### Non-revoking password-wrapper replacement — future protocol, disabled in local prototype and cloud

1. Only after authenticated unlock, generate a new salt and wrapping nonce and choose reviewed KDF parameters.
2. Derive new wrapping key, encrypt the **same RootSecret** under a new header, AAD bound to new prefix.
3. Atomically replace header subject to provider update rules; maintain a client-local recovery journal until acknowledged. Never expose inconsistent new header with irrecoverable root.
4. A provider's retained **old header snapshot** can still permit the old password to decrypt unchanged object history. Therefore password-wrapper replacement does **NOT** revoke old access: a holder of an old header and passphrase can decrypt **future objects** using the unchanged RootSecret, not just old objects. Do not call this password revocation. Remote rewrap is disabled until a transactional design has been reviewed; local-only test fixtures may exercise in-memory rewrap.

### Full root rotation (future, non-v0 automatic feature)

To revoke previously exposed RootSecret or old-password access to *future writes*, a new root, new object IDs and ciphertexts, renewed manifest and a separately reviewed atomic migration/recovery process are needed. **Historical data already accessed, copied or version-retained by the provider cannot be retroactively protected.** Never claim secure deletion or guaranteed revocation. If rotation implementation is absent, MUST report unsupported rather than silently rewrap.

### Recovery / backups

v0 candidate is **passphrase-only**: lost passphrase may mean irreversible loss of access. No recovery credential, universal bypass or second password slot is defined. Any future opted-in recovery must have a distinct security design independent of device-only Keychain/Keystore wrapping and never store plaintext root material with the provider. When a valid old snapshot is restored without trusted checkpoint, display **freshness unknown**. No automatic repair by ignoring tags or replay gaps.

### Format migration

This is a **v0 candidate**, no guaranteed forward compatibility. Unknown major/suite MUST fail closed; only migration code that understands both versions can write successor format. Any migration touching encrypted key schedule/object AAD requires new vetted vectors, backup, crash recovery and security review; no silent downgrade.

## 8. Threat/leakage scope and what stays unresolved

- Vault v0 exposes a recognizable header, object count, sizes, upper bound on plaintext chunk lengths, upload cadence, mutable HEAD and API access history. No meaningful deniability claim.
- A cloud provider able to read versions can replay older valid signed-in user snapshots and observe password rewrap/root rotation events. AEAD cannot guarantee freshness.
- Provider-visible ciphertext length leaks information; no padding/cover traffic or ORAM protocol in v0. Such features require P6/P7 independent proofs.
- Availability cannot be cryptographically guaranteed against a malicious provider.
- Keys and decrypted data on an unlocked compromised device (T5), coercion (T6) are outside protected claims.
- Public HEAD metadata alone does not prove its authenticity or freshness. CAS/commit guarantees remain P3 work.
- Nonce and object ID randomness must be checked against actual mobile OS CSPRNG and implementation failures.
- If directory metadata reaches 1 MiB/4096 entries, client must refuse update or perform future reviewed sharding; no unreviewed truncation.

## 9. Deterministic synthetic vector contract (tests NOT yet generated)

Future fixture layout under `test-vectors/v0/` (not created by this milestone):
- `spec.json`: algorithm IDs, exact public header bytes, object header bytes, HEAD bytes, expected plaintext and errors, checksum for fixtures.
- `cases/passphrase_*.json`: explicit raw UTF-8 passphrases including non-ASCII and visually similar Unicode, and declared Argon2 parameters/salts.
- `cases/wrapped_root.json`: fixed **synthetic** RootSecret, salt, ID and nonce; exact Argon2/HKDF outputs and encrypted wrapped root.
- `cases/objects.json`: root/directory/file/chunk plaintext, CBOR encoding, derived ObjectKeys, nonce, AAD and final ciphertext.
- `cases/corruptions.json`: changed magic, version, lengths, suite, flags, KDF DoS, nonce/tag, object ID/path, expected child type, chunk ordinal, missing object, generation mismatch, duplicate or noncanonical CBOR keys, graph cycle, rollback without checkpoint and with checkpoint.
- `cases/rotation.json`: password rewrap preserves RootSecret + valid object ciphertext; old-header snapshot still works with old password (document limitation).
- `README.md`: fixture generation reproducible commands, platform cross-check, provenance and safety caveats.

Tests MUST assert **exact bytes**, not just encrypt/decrypt round-trip (two implementations can share a bug). Use published primitive KAT plus independent implementation to cross-check. Synthetic fixture passphrases/keys MUST NOT be copied into real product credentials. P1.4 must enumerate every SEC-001–013 mapping and fuzz cases; P2 must run on Rust, Swift/iOS and Kotlin/Android before release.

## 10. Acceptance record and remaining gates

- [x] Candidate header/object/HEAD exact offsets, lengths, IDs and endianness documented.
- [x] Candidate password KDF, HKDF key schedule, AEAD AAD and nonce uniqueness semantics documented.
- [x] Canonical CBOR payload schema, authenticated reference/parent/chunk model and parser resource limits documented.
- [x] Password rewrap vs full root rotation, rollback and recovery limits distinguished.
- [x] Synthetic vector fixture contract defined; Shadow/Specter explicitly excluded.
- [ ] Independent protocol review and full threat-game assurance: **not performed**.
- [ ] Executable test vectors, cross-platform fixture checks, parser fuzz, actual binary implementation: **not performed**.
- [ ] Cloud HEAD CAS/atomicity and recovery protocol: **P3 not designed/verified**.
- [ ] Parameter/performance validation on mobile: **not performed**.

**Next:** P1.4 enumerate adversarial test cases for this exact format; P1.5 review and resolve any security-critical open points before P2 implementation.

## 11. References

- RFC 9106 Argon2id (mobile reference candidate): https://www.rfc-editor.org/rfc/rfc9106
- RFC 5869 HKDF: https://www.rfc-editor.org/rfc/rfc5869
- RFC 8949 §4.2 core deterministic CBOR and duplicate keys: https://www.rfc-editor.org/rfc/rfc8949
- RustCrypto XChaCha20Poly1305: https://docs.rs/chacha20poly1305/latest/chacha20poly1305/

## 12. P1.5 internal security-review amendment — controlling scope and rules (2026-10-31)

The following review decisions **take precedence** if earlier v0 prose is ambiguous; a future format revision must explicitly incorporate them and produce new exact-byte fixtures:

1. **Local synthetic prototype only** in early P2; remote writes, multiwriter sync, cloud password rewrap, root rotation, recovery slots and real confidential data are not enabled. No production security promise.
2. Public HEAD is an untrusted root selector, not proof of freshness. A separately trusted *local* checkpoint `(vault_id, generation, commit_root_object_id)` can detect old generations and same-generation forks; verify authenticated ancestry for larger remote generations. Without a trusted checkpoint, report `FreshnessUnknown`. Even a matching checkpoint does not prove no newer provider-withheld writes.
3. Object encryption's AAD covers the **public envelope**, while generation and logical parent/path are verified through the *authenticated commit-root graph*. A file chunk is not individually bound to one fixed generation; reuse between versions is possible.
4. Bound actual encoded object size **and** logical directory/chunk count/depth together. The headline maximum entry count does not override the 1-MiB object limit; reject rather than truncate.
5. Import enforces filename NFC via an explicit accept/reject path. Password bytes remain byte-exact. OS export MUST check target-path conflicts under case folding and normalization, and never silently overwrite.
6. RFC 8949 §4.2.1 **bytewise encoded-key** core deterministic CBOR applies, not the RFC 7049 legacy length-first variant.
7. Only a provider-specific verified compare-and-swap/transaction model in P3 can enable cloud HEAD publication and competing-writer support. A standalone HEAD MAC does **not** solve replay of a valid prior MAC and HEAD together.
8. Local lock and password rewrap never imply forensic erasure or historical/future credential revocation.

See [P1.5 security design review](11_SECURITY_DESIGN_REVIEW.md) and [ADR-0004](decisions/0004-security-review-scope-and-safety.md). These decisions are **not** implementation, passing test results or an independent security audit. The older P1.4-oriented checklist above is retained as historical design-stage context; the next task is P2.1 synthetic local-only scaffolding.
