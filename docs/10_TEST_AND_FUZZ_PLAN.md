# P1.4 — Eidoron Vault v0 adversarial tests, vectors and fuzz plan

- Created / updated: **2026-10-31 JST**
- Status: **Test-design milestone only. No executable tests, fuzz campaigns, fixtures or cryptographic implementation have run.**
- Scope: **Vault v0** (no Shadow/Specter assurance)
- Source protocol: [09_ENVELOPE_FORMAT_V0.md](09_ENVELOPE_FORMAT_V0.md) and [ADR-0003](decisions/0003-envelope-and-key-hierarchy.md)
- Security requirements: [08_SECURITY_TARGET.md](08_SECURITY_TARGET.md), SEC-001–013, DEN-001–005 and CLAIM-001
- Next: P1.5 security design review and issue disposition, **then** P2 implementation if approved
- Document language: future MUST / expected assertions, not passing results.

## 0. Purpose and acceptance standard

P1.3 established a *candidate* RustCrypto Argon2id/HKDF/XChaCha20 Vault format with 136-byte public header, 88-byte object envelope, 66-byte untrusted HEAD selector, and deterministic CBOR objects. P1.4 turns every exposed byte boundary, authenticated relation, password event and synchronization state into a falsifiable contract.

The test architecture MUST independently detect that (a) two incompatible implementations do not merely agree on the same bug, (b) invalid ciphertext never reaches a viewer/exporter, (c) a malicious cloud may replay a previously authenticated root, (d) concurrency cannot silently discard committed edits, and (e) evidence for Vault encryption is **not** evidence for Shadow deniability.

The following table is a **test specification**, not a test report. Any security-relevant unexpected success, crash, out-of-bounds resource allocation or silent data loss is a blocker.

## 1. Test harness responsibilities and proposed layout

Create in P2 **only after P1.5 approves the format**:

- `test-vectors/v0/spec.json` — format revision, synthetic test key/salt/nonce values, reference digest and expected errors; never genuine passwords.
- `test-vectors/v0/positive/` — exact-byte header, HEAD, wrapped RootSecret, object envelopes, canonical root/directory/file CBOR, chunks and multi-file graph; companion metadata manifest with expected plain/cipher hex.
- `test-vectors/v0/negative/` — each rejection input with expected class and input size.
- `test-vectors/v0/state/` — deterministic provider fault/transaction event sequences, model checkpoint and expected sync state.
- `crates/format/tests/` — strict byte/layout regression and negative decoding.
- `crates/crypto/tests/` — primitive known-answer tests, key schedule, authenticated failure.
- `crates/vault/tests/` — graph/reference and traversal/export integrity.
- `crates/provider-local/tests/` — fake provider with CAS and failure injection; no real credentials.
- `fuzz/fuzz_targets/` — format/header, CBOR, graph, chunk, state-machine and FFI-boundary fuzz entries.

The synthetic fixture generator MUST take explicitly injected fixed randomness **only in test builds**. No deterministic RNG injection is reachable from production APIs. Independent expected bytes should be calculated using a separate vetted crypto implementation or reference vectors, not copied from the code under test. Store fixture provenance and digests.

### Tool candidates (not yet installed)

- `cargo test --workspace --locked` for unit, integration and exact-vector tests.
- `cargo fuzz run <target>` with `cargo-fuzz`/libFuzzer for malformed data, boundary and stateful fuzzing.
- `proptest` for property/state-machine generation and shrinking.
- `cargo audit`, `cargo deny check` and a manual dependency review per ADR-0002.
- Platform harnesses: generated UniFFI bindings, Swift/XCTest iOS device tests and Kotlin/JUnit/instrumented Android tests.

These are future commands; **they cannot yet run on the current docs-only repository**. GitHub Actions is OPTIONAL, not a prerequisite; reports can be captured with developer/work cloud execution, pinned commit, toolchain, platform and reproducible artifacts.

## 2. Exact-byte happy-path golden vectors

| ID | Vector | Required assertion |
|---|---|---|
| VEC-001 | Deterministic synthetic `vault.header` | Exactly **136 bytes**; magic `EIDORON 00`; strict u16/u32 offsets; exact `header[0..88]` AAD; wrapped RootSecret 48 bytes |
| VEC-002 | Argon2id raw output and HKDF | Expected 32-byte RawPwdKey, WrapPRK, WrapKey and ObjectKey for known synthetic bytes; fixed purpose strings and vault_id |
| VEC-003 | Empty Vault bootstrap | HEAD **66 bytes**; verified commit kind 1, empty root dir kind 2, valid ID/path chain and genesis generation 0 |
| VEC-004 | One-file small archive | Directory→file→chunk references and exact `kind || schema || payload` authentication; verified export bytes match synthetic input |
| VEC-005 | Multi-chunk file and subdirectories | Ordinals 0..N-1, logical file/parent identity, verified byte count, canonical deterministic CBOR maps and sorted directory names |
| VEC-006 | Empty file and boundaries | Zero chunks for empty file; 1-byte chunk, maximum allowed chunk, 4096 directory entries, depth 64, 8192 chunk IDs each tested against memory/size limit |
| VEC-007 | Rewrap with a new password | Same RootSecret and unchanged immutable content; new salt and wrapping nonce; old descriptor retained by attacker may still unlock Root with old password |
| VEC-008 | Independent iOS/Android/Rust reading | Exactly equal decrypted bytes and metadata from fixed golden vectors; equivalence for non-ASCII UTF-8 and defined normalization |
| VEC-009 | Root rotation prototype contract (future) | New vault_id/Root/object IDs/new ciphertext; old snapshots still decryptable with old material, cannot claim retrospective revocation |
| VEC-010 | Version compatibility rejection | Unknown major/suite and nonzero flags fail closed; no silent re-interpretation or fallback |

Golden vectors require **exact byte comparisons and reference cross-checks**, not just round-trip tests. VEC-006 may reveal inherent `1 MiB` encrypted-index limits; boundary acceptance depends on *both* entry-count cap and actual encoded object size. The generator MUST NOT assume every maximum is simultaneously possible.

## 3. Malformed public envelope and KDF resource matrix

Each case must be tested with prefix truncation, full truncation, trailing bytes and mutation of every public header field, plus fuzzed arbitrary-length input.

| ID | Attack / input | Expected outcome |
|---|---|---|
| PAR-001 | Header lengths 0,1,87,88,135,136,137; incorrect magic | Only 136-byte valid format accepted; reject before KDF |
| PAR-002 | Header major/minor/suite/flags/Argon2 version unknown | `UnsupportedFormat` or `InvalidEncoding`; no fallback |
| PAR-003 | Argon2 `m_cost_kib` = 0, <65536, >262144, UINT32_MAX; time = 0, 11, UINT32_MAX; lanes = 0 or 5 | Reject **before Argon2 memory allocation**; no silently weaker KDF |
| PAR-004 | Header wrong vault_id/salt/wrap nonce/AAD or wrapped-root tag flipped | Generic `UnlockUnavailable`, no Root/partial plaintext exposed |
| PAR-005 | Object prefixes 0,87,88,105,106, maximum 1,048,680, max+1, extremely large claimed lengths | Exact size and plaintext>=2 enforced; no excessive allocation or panic |
| PAR-006 | Wrong object magic, suite, version, oid/path mismatch, vault ID mismatch, nonce/AAD/tag corruption | Reject or `IntegrityFailure`; never return plaintext |
| PAR-007 | Object body with wrong kind/schema, extra bytes or wrong expected child type | Authenticated but **semantically invalid**; reject before export |
| PAR-008 | HEAD length !=66, wrong magic/version/vault ID, malformed or stale valid selector | Invalid HEAD rejected; stale valid selector marked freshness-unknown or suspected rollback depending checkpoint |
| PAR-009 | Zero/duplicate object IDs, repeated nonce under same object key, reencrypt different content under same object ID | Writer refuses reuse; immutable create-if-absent enforced |
| PAR-010 | Memory errors, invalid UTF-8/NUL/malformed Unicode password, >1024 bytes | Bounded error; no crash, no implicit trimming/normalization |

**Important P1.3 nuance:** §3 states `1 ≤ plaintext_len` and then the stricter `plaintext_len≥2`; §6 explicitly declares minimum object size **106** and max **1,048,680** bytes. The P1.4 tests MUST enforce the stricter bounds and flag the contradictory wording for cleanup before version freeze.

Exhaustive byte-field mutation must separate *early parser errors* from cryptographic failures. Failure of integrity checks MUST NOT be converted to a successful empty file, alternate key lookup or best-effort decrypted preview.

## 4. Canonical CBOR, graph and semantic reference matrix

| ID | Malformation / malicious substitution | Expected outcome |
|---|---|---|
| CBOR-001 | Nonminimal integer/length, indefinite string/map/array | Rejected, not normalized silently |
| CBOR-002 | Duplicate/out-of-order map keys, wrong key types, unknown fields, tags, floats, negative integers | Rejected; no schema fallback |
| CBOR-003 | Missing required key, wrong `bstr(16/32)` length, overflow/huge array count | Rejected with bounded allocation |
| CBOR-004 | Unsorted directory UTF-8 names, duplicate exact names, empty/oversized names, slash/NUL/dot/dot-dot | Rejected |
| CBOR-005 | Different Unicode NFC/NFD spellings, visually similar passphrases vs filenames | Password bytes are exact; directory NFC enforcement checked; cross-platform normalization collisions reported, never overwritten |
| GRAPH-001 | Directory child object ID replaced by unrelated object of valid AEAD key | Authenticated but wrong logical parent/ID/kind; reject |
| GRAPH-002 | Directory cycle, duplicate logical directory ID referenced from two parents, orphan/corrupt parent | Reject; depth cap 64 |
| GRAPH-003 | File descriptor parent mismatch, file ID mismatch, duplicate chunk OID, wrong ordinal | Reject even if all affected chunks authenticate |
| GRAPH-004 | Declared total file size differs from verified chunk lengths | Reject file completion/export |
| GRAPH-005 | More than 4096 directory entries, 8192 chunk IDs or 1-MiB CBOR object | Reject before oversized read/alloc; never truncate |
| GRAPH-006 | Commit generation different from HEAD; genesis prior_commit present; later prior missing; corrupted lineage | Reject or report unresolved lineage with documented failure |
| GRAPH-007 | One verified chunk followed by tampered next chunk during streaming preview | Only verified bytes can be surfaced; no fully-verified/export-success state |
| GRAPH-008 | Orphan object injected into provider list but not referenced by authenticated commit | Never surface as a normal file |
| GRAPH-009 | Chunk object swapped between vaults, files or ordinals | Reject through vault ID / authenticated file ID / ordinal / graph checks |

RFC 8949 §4.2 **core deterministic encoding**, not older length-first CBOR variants, is the adopted target. A byte-for-byte canonical **re-encode and compare** is a useful independent validator, but the decoder must still cap input size and reject duplicate keys before map construction erases evidence.

## 5. Rollback, concurrency and crash-fault matrix

Create a deterministic fake cloud that can choose any named fault at each operation boundary: local import, immutable object PUT, remote read-after-write, HEAD GET, conditional HEAD write, local checkpoint save, key rewrap and restore. Log the complete sequence and replay via fixture seed.

| ID | Scenario | Required state / counterexample to avoid |
|---|---|---|
| SYNC-001 | Root/descriptor created, upload interrupted before publishing HEAD | Not remotely synced; recoverable local pending journal; no dangling remote root treated as success |
| SYNC-002 | Some objects uploaded but final commit unavailable | No published root referring to missing content |
| SYNC-003 | HEAD compare-and-swap fails due to second device | Preserve both edits/conflict; never last-writer-wins loss |
| SYNC-004 | Network disconnect after CAS succeeds but before client acknowledgment | Query remote and reconcile idempotently; no duplicate rewrite under old OID |
| SYNC-005 | Two offline devices edit same file and reconnect in reverse order | Resolve or preserve both revisions; never silently overwrite either acknowledged edit |
| SYNC-006 | Quota full, revoked OAuth, object missing, partial upload, rate limit or timeout | Accurate `RemoteUnavailable` / local-pending; no false success |
| SYNC-007 | Provider deletes or replaces object while preserving old valid commit/root | Integrity or missing-object failure where detectable; availability cannot be guaranteed |
| SYNC-008 | Provider returns older **valid** HEAD and prior encrypted objects, client has trusted newer checkpoint | `SuspectedRollback`, not `Synced` |
| SYNC-009 | Same old valid archive on new device **without** checkpoint | `FreshnessUnknown`, not falsely guaranteed current |
| SYNC-010 | Provider supplies different valid old header after passphrase rewrap | Old password can still unlock old Root: documented limitation, not a false revocation claim |
| SYNC-011 | Device locked, app killed, resumed, OS backup restored, Keychain/Keystore material invalid | No false biometric recovery or plaintext persistence; user chooses portable passphrase/recovery |
| SYNC-012 | GC near concurrent revisions, app offline and stale device comes online | No deletion of content still reachable under valid retained concurrent revision |
| SYNC-013 | Provider lacks guaranteed conditional update and consistency | Feature disabled or explicit unsupported adapter, never pretend safe CAS |

A fake provider can exercise these contracts without spending money on cloud services. Real provider integration verification is a later P3 gate. **Provider denial of service is not preventable cryptographically.**

## 6. SEC and CLAIM requirement coverage

| Security target ID | Planned evidence | Explicit nonclaim |
|---|---|---|
| SEC-001 | VEC-004, provider trace inspection with synthetic known marker | Hiding total storage volume or timing |
| SEC-002 | VEC-001/002, published primitive KAT, PAR-004/009 | A formal security proof |
| SEC-003 | Chosen equal-leakage plaintext comparison + cryptography analysis | Ciphertext-size indistinguishability |
| SEC-004 | PAR-004/006/007, GRAPH-007 | Detecting all server outages |
| SEC-005 | GRAPH-001/003/009, PAR-006 | Hiding object graph traffic |
| SEC-006 | CBOR-001..005, GRAPH-002, PAR-002/005 | Any unsupported schema auto-fix |
| SEC-007 | SYNC-008 plus checkpoint state | Detection without trusted checkpoint |
| SEC-008 | SYNC-009 | New-device freshness certification |
| SEC-009 | SYNC-001/002/004 | Guaranteed network availability |
| SEC-010 | SYNC-003/005/012 | Automatic perfect merge of all conflicts |
| SEC-011 | SYNC-006/013, PAR-003 | Universal cloud adapter support |
| SEC-012 | SYNC-011, mobile app snapshots/log/privacy inspection | Forensic erasure on compromised OS |
| SEC-013 | VEC-007/009/010, SYNC-010/011, malformed backup | Historical cloud deletion / revocation |
| CLAIM-001 | Copy review per target T0–T6 with evidence link and owner | Vault confidentiality **does not** prove Shadow/Specter deniability |

DEN-001–DEN-005 are **research-only P6/P7 gates**. They require W0/W1 indistinguishability games, snapshot and request traces, public-password disclosure tests and allocation non-corruption. **No result is implied or counted by passing the Vault test suite.**

## 7. Fuzzing targets and required invariants

| Target | Input model | Primary invariant |
|---|---|---|
| `fuzz_header_preparse` | Arbitrary bytes including 136-byte boundary / KDF fields | Never allocate Argon2 memory for malformed or over-cap parameters; no panics, OOM or hangs |
| `fuzz_object_envelope` | Arbitrary public envelope + ciphertext/tag + expected path OID | No unauthenticated plaintext, no overlong read, no tag bypass |
| `fuzz_cbor_schema` | Arbitrary canonical and noncanonical CBOR with kind selector | Reject all invalid encodings; no duplicate-key collapse, infinite recursion or panic |
| `fuzz_graph_traversal` | Generated authentic synthetic object graph incl adversarial cycles/aliases | Bounded traversal; no escaped orphan/unchecked chunk or unbounded recursion |
| `fuzz_session_state` | Stateful init/unlock/import/write/lock/reconnect/rewrap sequence | No use-after-lock or false synced state |
| `fuzz_provider_failures` | Operation sequence, injected timeout/quota/CAS/missing-object | No acknowledged commit loss or unsafe deletion under declared model |
| `fuzz_ffi_boundary` | Bounded malformed UTF-8, file ranges, cancellation, rapidly closed handles | No panic over FFI, leaked secret logs or returned unverified bytes |

Fuzz one parsing layer at a time to avoid each case invoking costly Argon2id. Resource parameters must be prevalidated; cryptographic verification fuzzing should use fixed synthetic keys plus separately authenticated/unauthenticated test inputs. Sanitizers/coverage may be used where target/toolchain supports them. **Never bypass authentication in a production code path to make fuzzing easier.**

Track for each target: executable name, rustc/tool version, architecture, seed/corpus digest, runtime, executed inputs, coverage, crash/hang count, minimized reproducer and Git commit. Retain regression tests for every resolved bug.

Suggested initial budgets (to refine with P2 resources): at least 60 minutes per parser/CBOR target, 30 minutes per state/FFI target, plus a longer overnight campaign when suitable compute exists. These are planning targets, **not executed durations**. No expectation that the user operates a PC.

## 8. Property-based and interoperability tests

Properties:
1. Encode(decode(valid bytes)) reproduces **exact** input for strict v0 canonical objects.
2. Decrypt(encrypt(message, nonce, context)) yields message only under the correct key/context; mutation yields no user-visible unverified bytes.
3. Authenticated directory traversal returns exactly the referenced reachable files, no more.
4. Any commit acknowledged synced has complete retrievable immutable dependencies **subject to stated provider durability**.
5. Interleaving edits from two devices either merges nonconflicting edits correctly or preserves explicit conflicts.
6. Lock invalidates all live handles and forbids verified operations on closed sessions.
7. No parser size/iteration field bypasses the hard cap on allocations/CPU from remotely controlled bytes.
8. Password rewrap is logically reversible with new password while old historical credentials remain a **known** risk, not concealed by UI.

Run fixed fixtures on host Rust, native iOS and native Android builds. On-device tests must include Keychain/Keystore invalidation, app backgrounding, file export collisions, memory/battery measurements for Argon2id profile, and released UniFFI artifacts. FFI bindings are not covered by Rust-only unit tests.

## 9. Review blockers surfaced by the current P1.3 candidate

These are **explicit design-review questions**, not verified exploits. P1.5 MUST resolve with a source change/ADR or written risk acceptance before P2 code.

| Blocker | Observation | Required P1.5 disposition |
|---|---|---|
| **BLK-01** | v0 object §3 says plaintext min `1` then §6 effectively enforces min `2` (kind+schema) | Harmonize to ≥2 across spec and vector contract |
| **BLK-02** | Unauthenticated public HEAD, even with AEAD-authenticated commit, can select another **valid historical** root; provider-visible generation not signed | Specify exact checkpoint trust/freshness state and distinguish replay vs integrity; decide whether HEAD needs independent MAC; update ADR if changed |
| **BLK-03** | v0 immutable-object protocol requires true conditional HEAD updates; many consumer-cloud APIs do not promise the same semantics | Gate initial provider; define fallback/no-multiwriter policy rather than generic CAS claims |
| **BLK-04** | Root stays stable through password rewrap, and retained old header enables old-password access even to later objects | Password-change UX and historical-version threat response must be explicit |
| **BLK-05** | Directory names require NFC but passphrases preserve exact UTF-8 bytes; OS filename normalization/export collisions differ | Cross-platform invariant and conflict UX require explicit tests |
| **BLK-06** | 1 MiB per-object cap, 8192 chunks/file and 4096 directory entries have complex combined limits; large archive migration undefined | Verify impossible combinations, error codes and a safe future extension path |
| **BLK-07** | Atomic descriptor rotation vs simultaneous edit/HEAD publication may race, and device recovery checkpoints are unspecified | Define owner/transaction and rollback behavior or prohibit concurrent rewrap |
| **BLK-08** | No design for reversible recovery credential or lost-device restore trust anchor | Decide whether v0 is passphrase-only; document irreversible loss and restore freshness |
| **BLK-09** | Exact crate versions, Rust MSRV, FFI packaging and secret-copy semantics not yet checked on mobile | Require version pin, dependency/security review and empirical platform test gate |
| **BLK-10** | A visible vault header is not a plausible-deniability primitive | Explicitly forbid Vault/Shadow claim conflation in app and marketing |

No blocker is *resolved* by the mere existence of this test plan. Prioritize BLK-02/03/04/07 because they can lead to false freshness or data-loss expectations; BLK-01 is a straightforward normative inconsistency.

## 10. Future reproducibility commands (NOT RUN)

After P1.5 and code scaffolding, provide a manual runbook with commands conceptually equivalent to:

```sh
cargo test --workspace --locked
cargo test --workspace --locked --test vectors
cargo fuzz run fuzz_header_preparse -- -max_total_time=3600
cargo fuzz run fuzz_object_envelope -- -max_total_time=3600
cargo fuzz run fuzz_cbor_schema -- -max_total_time=3600
cargo fuzz run fuzz_provider_failures -- -max_total_time=1800
cargo audit
cargo deny check
```

Some targets/crates are not yet named or installed and commands will need verification against the actual workspace. `cargo fuzz` requires a suitable toolchain and uses libFuzzer; it is not universally available on every device. Save actual complete commands, tool versions and output evidence in the future work's PR and handoff ledger. No mandatory GitHub Actions.

## 11. P1.4 document-only exit and next handoff

- [x] Positive exact-byte fixture catalog covers descriptor/HEAD/object/schema and password events.
- [x] Negative byte fields, cryptography-authentication failures, canonical CBOR and object-graph cases enumerated.
- [x] Sync crash/replay/CAS/offline/concurrent state model with expected outcomes listed.
- [x] SEC-001–013 and CLAIM-001 mapped; DEN research kept strictly separate.
- [x] Fuzz targets, invariants, future reproducibility commands and mobile interoperability specified.
- [x] Known P1.3 ambiguities / risks recorded as **unresolved** P1.5 review blockers.
- [ ] Fixture bytes, executable tests, fuzz campaigns, platform verification, external security review: **NOT STARTED**.

**P1.5 NEXT:** independently review the v0 protocol against this document, decide each BLK-01..10, amend P1.3/ADRs with Git-traceable changes, and issue a review disposition. No deployment of a cryptographic product or security claim before gates.

## 12. References

- [Eidoron v0 envelope candidate](09_ENVELOPE_FORMAT_V0.md)
- [Eidoron security target](08_SECURITY_TARGET.md)
- RFC 8949 deterministic CBOR: https://www.rfc-editor.org/rfc/rfc8949
- Rust Fuzz Book / cargo-fuzz: https://rust-fuzz.github.io/book/cargo-fuzz.html
- proptest: https://docs.rs/proptest/latest/proptest/
- Argon2id RFC 9106: https://www.rfc-editor.org/rfc/rfc9106
