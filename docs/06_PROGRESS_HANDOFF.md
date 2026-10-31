# Progress, Decisions and AI Handoff

- Created: **2026-10-31 JST**
- Last updated: **2026-10-31 JST**
- Current baseline: **M6.23 temporary directory store passes; crash safety is not claimed**
- Implementation status: **opaque hex files; 36 unit tests pass; NO CLOUD, NO CRASH-SAFETY CLAIM**
- Foundation branch: `docs/foundation-master-plan-20261031` (merged)
- Foundation PR: https://github.com/akiralazycat/eidoron/pull/1 — merged into main on 2026-10-31 JST
- Foundation merge commit: `7835fd40e5608f5525db9dcb625b30ddff395e7e`
- P1.1 security-target PR: https://github.com/akiralazycat/eidoron/pull/2 — merged on 2026-10-31 JST
- P1.1 merge commit: `7a4a7d7fb9668d8d9fb6d98b2fc8d36e09aff374`
- P1.2 dependency/FFI PR: https://github.com/akiralazycat/eidoron/pull/3 — merged on 2026-10-31 JST
- P1.2 merge commit: `7dd3ba458838b50df24b9d3b9623ab8350e9cb0d`
- P1.3 envelope-format PR: https://github.com/akiralazycat/eidoron/pull/4 — merged on 2026-10-31 JST
- P1.3 merge commit: `fc1aad284349b25bde58888fcbe317b437b4a094`
- P1.4 test/fuzz-plan PR: https://github.com/akiralazycat/eidoron/pull/5 — merged on 2026-10-31 JST
- P1.4 merge commit: `db7613737073231c812fed22b18559eedabd3534`
- P1.5 internal security-review PR: https://github.com/akiralazycat/eidoron/pull/6 — merged on 2026-10-31 JST
- P1.5 merge commit: `bc125274e84535574301adb04919a9851a1f1387`
- P2.1 scaffold PR: https://github.com/akiralazycat/eidoron/pull/7 — merged 2026-10-31 JST; build was unverified at merge
- P2.1 merge commit: `88eca61d21b36008e72ebcbc56e63bf52e5531b9`
- P2.1-V compiler verification: recorded 2026-10-31 on rustc 1.99.1; see the P2.1-V session log below and `docs/PLAN.md`

## Current phase board

| ID | Work item | State | Evidence / notes |
|---|---|---|---|
| P0.1 | Inspect initial repository and license | DONE | 2026-10-31: main contained README + MIT license |
| P0.2 | Master plan and product boundary | DONE | docs/00_MASTER_PLAN.md |
| P0.3 | Threat model and nonclaims | DONE | docs/01_THREAT_MODEL.md |
| P0.4 | Candidate cryptography and protocol boundary | DONE (draft only) | docs/02_CRYPTO_ARCHITECTURE.md |
| P0.5 | Storage/sync research agenda | DONE (planning only) | docs/03_STORAGE_SYNC.md |
| P0.6 | Native UX vision | DONE (planning only) | docs/04_PRODUCT_UX.md |
| P0.7 | Roadmap and handoff process | DONE | docs/05_IMPLEMENTATION_ROADMAP.md + this file |
| P1.1 | Formalize adversaries/claims into normative spec | DONE (docs only) | 2026-10-31; `docs/08_SECURITY_TARGET.md`; C01–C08, SEC-001–013, DEN-001–005; no tests executed |
| P1.2 | Library/FFI/device secure storage ADR | DONE (docs only) | 2026-10-31; ADR-0002 candidates and risks recorded; **no versions pinned, build or audit** |
| P1.3 | Binary envelope v0 candidate and ADR-0003 | DONE (docs only) | 2026-10-31; `docs/09_ENVELOPE_FORMAT_V0.md`, ADR-0003; security review/interop vectors pending |
| P1.4 | Security-oriented test/fuzz plan | DONE (docs only) | 2026-10-31; `docs/10_TEST_AND_FUZZ_PLAN.md`; planned VEC/PAR/CBOR/GRAPH/SYNC and fuzz targets; **not run** |
| P1.5 | Internal security design review and scope | DONE (docs only) | 2026-10-31; `docs/11_SECURITY_DESIGN_REVIEW.md`, ADR-0004. Not an external audit; release gate BLOCKED |
| P2.1 | Synthetic local-only Rust workspace | DONE (scaffold verified, no crypto) | rustc 1.99.1 fmt/test/clippy recorded in `docs/12_P2_IMPLEMENTATION.md` |
| P2.1-V | Verify lockfile, fmt, test, clippy on actual Rust | DONE | 2026-10-31: rustc 1.99.1 (`58cf8f9c3`, 2026-10-13). fmt check, 10 unit tests, clippy `-D warnings`, Cargo-generated path-only lockfile. Next tasks in `docs/PLAN.md` |
| P2.2 | Known-answer crypto vectors and suite evaluation | PARTIAL | M1–M5 and M6.23 done 2026-10-31. M6.24 cloud and later stay deferred. See `docs/PLAN.md` |
| P2 | Rust Vault implementation | NOT STARTED | Do not claim ready |
| P3 | Safe cloud sync | NOT STARTED | Do not claim ready |
| P4/P5 | iOS / Android native clients | NOT STARTED | Do not claim ready |
| P6 | Shadow-deniability experiments | NOT STARTED | No security claim |
| P7 | Snapshot/trace-resistance research | NOT STARTED | No security claim |

## Decision ledger

| Date | ID | Decision | Reason / follow-up |
|---|---|---|---|
| 2026-10-31 | ADR-0001 | Rust core, native Swift/Kotlin clients, local-first baseline | One reviewed crypto boundary; platform UX remains native |
| 2026-10-31 | ADR-0001 | Vault is a deliverable; Shadow/Specter are gated research | Prevent false security claims |
| 2026-10-31 | OPEN-01 | XChaCha20-Poly1305 + Argon2id + HKDF are candidates | Benchmark/review/format tests before freezing |
| 2026-10-31 | OPEN-02 | First cloud adapter undecided | Evaluate provider constraints empirically |
| 2026-10-31 | OPEN-03 | Safe hidden allocation without disclosure unresolved | Core P6 research blocker |
| 2026-10-31 | OPEN-04 | Hidden-key onboarding/recovery/biometrics unresolved | May reveal hidden existence |
| 2026-10-31 | P1.1 | Formal prospective security target and falsification map authored | Not yet reviewed or verified |
| 2026-10-31 | ADR-0002 | RustCrypto + UniFFI preferred; device wrapper keys remain platform-native | Alternatives and FFI risks documented; pending P1.3 specification and on-device verification |
| 2026-10-31 | OPEN-05 | Exact pinned crate releases and Rust MSRV/FFI build packaging | To confirm when implementation begins, after P1 review |
| 2026-10-31 | OPEN-06 | Password encoding, raw KDF-to-root hierarchy, secure recovery and rollback | v0 candidate specified in P1.3; recovery credential design and P3 trusted freshness remain OPEN |
| 2026-10-31 | ADR-0003 | Candidate Vault header+object+HEAD protocol, independent random root wrapped by passphrase | Enables cheap password rewrap; still exposes old snapshots and Vault existence |
| 2026-10-31 | OPEN-07 | P1.3 parameter ceilings and parser/metadata schema need security review | Resolve through P1.4 tests + P1.5 assessment |
| 2026-10-31 | OPEN-08 | Conditional HEAD publication, rollback and root-rotation migration need implementation-level protocol | P3; no cross-provider atomicity promise |
| 2026-10-31 | P1.4 | Security test/fuzz design documented | `docs/10_TEST_AND_FUZZ_PLAN.md`, BLK-01..10; no code/test run |
| 2026-10-31 | OPEN-09 | HEAD freshness, conditional commit, historical descriptor risks and parser limits need P1.5 dispositions | See P1.5 review; remote/performance evidence still OPEN |
| 2026-10-31 | ADR-0004 | Only synthetic local P2 prototype conditionally allowed | BLK-01..10 dispositions, trusted checkpoint, non-revoking rewrap, cloud disabled |
| 2026-10-31 | OPEN-10 | Provider-specific CAS, durable cloud password update, remote freshness | P3 blocker; not part of P2 local prototype |
| 2026-10-31 | OPEN-11 | Independent cryptography/code review and executed primitive/fuzz/mobile tests | Release and security claims not authorized |
| 2026-10-31 | P2.1 | Rust 1.99.1 + edition 2024, five path-only crates, fail-closed stubs | Source authored; `Cargo.lock` was hand-seeded pending Cargo regeneration |
| 2026-10-31 | OPEN-12 | Rust toolchain unavailable in the P2.1 authoring container | Resolved for the 2026-10-31 verification run, which had rustc 1.99.1. Other machines still need the pinned toolchain |
| 2026-10-31 | P2.1-V | Execute the fmt/test/clippy gate and replace the hand-written lockfile | rustfmt was the failing check; compiler accepted the sources. Regenerated path-only `Cargo.lock`. 10 unit tests pass. Cryptography still absent |
| 2026-10-31 | P2.2-M1 | Pin RustCrypto and check three published vectors | `argon2` 0.6.0, `hkdf` 0.13.0, `sha2` 0.11.1, `chacha20poly1305` 0.11.0, `zeroize` 1.9.1. Expected bytes transcribed from RFC 9106 §5.3, RFC 5869 A.1 and draft-irtf-cfrg-xchacha-03 A.3.1. Vault encrypt API unchanged |
| 2026-10-31 | P2.2-M2 | Derive RawPwdKey, WrapKey and ObjectKey for one synthetic vector | Expected bytes from `crates/test-vectors/scripts/key_schedule_kat.py` (argon2-cffi 25.1.0, Python hmac HKDF, PyNaCl 1.6.2). Wrong passphrase, flipped AAD and flipped tag share `Unavailable`. `encrypt_authenticated` unchanged |
| 2026-10-31 | M4 | Seal object bodies with XChaCha20-Poly1305 under ObjectKey | Expected ciphertext from `crates/test-vectors/scripts/object_aead_kat.py` (PyNaCl 1.6.2). Every release seal draws a fresh 24-byte nonce from `getrandom` 0.4.3. Fixed nonce is `cfg(test)` only. Wrong key, AAD/ciphertext/tag flips and truncation share `Unavailable`. Crypto does not return a previous ciphertext for a repeated plaintext |
| 2026-10-31 | M4-nonce | Fresh OS nonce on every object seal | Owner decision on PR #11: identical plaintext must not reuse or echo the previous nonce/ciphertext, because that reveals plaintext equality. Idempotency is a storage concern |
| 2026-10-31 | M5-hash | Storage idempotency hash must be keyed or encrypted | Owner decision: HMAC, keyed BLAKE, or an HKDF-derived vault key. A plain hash of plaintext must not be stored or used as an id |
| 2026-10-31 | M5.20 | Genesis commit predecessor check | Decrypted body only. Kind 0x01, generation 0, null prior. No general CBOR decoder. Fixtures from `scripts/genesis_commit_kat.py` |
| 2026-10-31 | M5.21 | Directory name rejection without NFC | Empty, longer than 255 UTF-8 bytes, `/`, U+0000, and the whole names `.` and `..`. `file.txt` and non-NFC text are accepted. NFC/NFD coexistence is an open question in `docs/PLAN.md` |
| 2026-10-31 | M5.22 | Chunk file_id and ordinal check | One decrypted chunk compared with the caller. No store scan. Either mismatch is `Mismatch`. Payload bytes are ignored |
| 2026-10-31 | M6.23 | Temporary directory of opaque objects | Lowercase hex file names. Identical opaque bytes retry. Different bytes rejected. Not a plaintext hash. Crash safety not tested |
| 2026-10-31 | M6.24 | Cloud, HEAD CAS, remote rewrap, biometrics, Shadow password | Deferred until a provider is chosen and its conditional writes are recorded |

## Immediate next task — blocked on owner choices

**Do not start** cloud sync, conditional HEAD publication, remote password rewrap, biometrics, or a second Shadow password. Those need a chosen provider and a record of its conditional writes (PLAN item 24, ADR-0004).
- Open questions: whether NFC and NFD directory names may coexist, and which keyed hash (HMAC-SHA256, keyed BLAKE, or HKDF) storage idempotency will use.
- Explicit scope restrictions: no cloud, real user data, native secrets, Shadow/Specter, production security claims; no mandatory GitHub Actions or user's PC.

## Session log — 2026-10-31 M6.23 temporary directory

- Started from main at `1b87dd9` (PR #14 merged).
- `TempDirStore` writes opaque bytes into a caller-chosen directory. The file name is 64 lowercase hex characters of the 32-byte id, so a byte of `0x2f` or `0x00` does not create another path component.
- An identical byte string at the same id returns `IdenticalRetry` and leaves the file unchanged. A different byte string returns `ExistingObjectDiffers`. The comparison is of the opaque bytes already stored, not a hash of plaintext.
- A directory sitting on the object's path returns `Io`. The error text does not include the path or the payload.
- Crash safety and atomic replacement were not tested and are not claimed. Item 24 was not started.
- `cargo fmt --all -- --check`, `cargo test --workspace --locked --offline` (36 unit tests) and `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` exited 0 on rustc 1.99.1.

## Session log — 2026-10-31 M5.22 chunk identity

- Started from main at `aa6051f` (PR #13 merged).
- `eidoron_vault::check_chunk_identity` reads one decrypted body `kind || schema || file_id:16 || ordinal:u32be || file_bytes` and compares `file_id` and `ordinal` with the caller. It does not read a store and does not compare `file_bytes`.
- A differing `file_id`, a differing ordinal, or both return the same `Mismatch`. Kind other than `0x04` is `NotAChunk`. A short body or schema other than `0x00` is `Unreadable`. Ordinal bytes are big-endian: `01 00 00 00` is not ordinal 1.
- Recorded an open question in `docs/PLAN.md`: directory names are not Unicode-normalized, so NFC and NFD spellings of the same visual name can both be stored. The decision is deferred.
- `import_encrypted` and `status()` remain `NotImplemented`.
- `cargo fmt --all -- --check`, `cargo test --workspace --locked --offline` (32 unit tests) and `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` exited 0 on rustc 1.99.1.

## Session log — 2026-10-31 M5.21 directory names

- Started from main at `05019e1` (PR #12 merged).
- `eidoron_vault::check_directory_name` takes a `&str` and does not parse CBOR. Empty names, names longer than 255 UTF-8 bytes, names containing `/` or U+0000, and the whole names `.` and `..` are rejected. The error text does not include the name.
- `file.txt`, `.hidden`, `...`, a trailing-space `..`, ASCII backslash, and both NFC `é` and NFD `e` + combining acute are accepted. Length is counted in UTF-8 bytes, so 253 `a` bytes plus `é` is 255 and accepted, and 254 `a` bytes plus `é` is rejected.
- `import_encrypted` and `status()` remain `NotImplemented`.
- `cargo fmt --all -- --check`, `cargo test --workspace --locked --offline` (28 unit tests) and `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` exited 0 on rustc 1.99.1.

## Session log — 2026-10-31 M5 genesis predecessor

- Started from main at `baa9c71` (PR #11 merged).
- `eidoron_vault::check_genesis_predecessor` reads a decrypted `kind || schema || payload` only through CBOR map keys 0 and 1.
- Kind `0x01`, schema `0x00`, generation 0, and null prior returns `EmptyPredecessor`. Generation 0 with a byte string, including a zero-length one, returns `PredecessorNotEmpty`. Other kinds return `NotACommit`. Other generations return `NotGenesis` and are not judged. Non-minimal integers in the fields that are read return `Unreadable`.
- Fixture bytes and expected labels were produced by `crates/test-vectors/scripts/genesis_commit_kat.py` from RFC 8949 preferred-length rules, then stored in `crates/test-vectors/src/commit_genesis.rs`.
- Owner decision: a storage idempotency hash must be keyed (HMAC, keyed BLAKE, or HKDF from vault secrets) or stored encrypted. A plain hash of plaintext is forbidden. Recorded in `docs/09_ENVELOPE_FORMAT_V0.md` and `docs/PLAN.md`.
- `import_encrypted` and `status()` remain `NotImplemented`. No CBOR decoder crate was added.
- `cargo fmt --all -- --check`, `cargo test --workspace --locked --offline` (25 unit tests) and `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` exited 0 on rustc 1.99.1.

## Session log — 2026-10-31 M4 object AEAD

- Started from main at `66af934` (PR #10 merged).
- `encrypt_authenticated` seals `kind || schema || payload` under `ObjectKey` with XChaCha20-Poly1305. Plaintext length must be 2..=1,048,576 before AEAD. Ciphertext length must be 18..=1,048,592.
- The release path fills a 24-byte nonce with `getrandom` 0.4.3 (`getrandom::fill`). `seal_object_with_nonce` is `#[cfg(test)]` and is absent from the library that dependents link.
- Owner decision, same day: every `encrypt_authenticated` call draws a fresh 24-byte OS nonce. Repeating a plaintext produces a different nonce and ciphertext, and both open to that plaintext. The cipher does not compare a previous ciphertext. `CryptoError::Conflict` was removed. Idempotency stays with storage, keyed by object id and content hash. See the decision note in `docs/09_ENVELOPE_FORMAT_V0.md`.
- Wrong key, flipped AAD, flipped ciphertext, flipped tag, and truncation all return `Unavailable` with display `unavailable`. The plaintext buffer is wiped when authentication fails.
- Expected ciphertext is in `crates/test-vectors/src/object_aead.rs`, printed by `scripts/object_aead_kat.py` (PyNaCl 1.6.2) from the M2 `OBJECT_KEY` bytes. Plaintext is kind `0x04`, schema `0x00`, payload `synthetic`. Nonce is 24 bytes of `0x66`.
- `status()` remains `NotImplemented`. Key `Drop` still zeroizes and is documented as best-effort.
- `cargo fmt --all -- --check`, `cargo test --workspace --locked --offline` and `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` exited 0 on rustc 1.99.1. After the fresh-nonce decision, the suite is 23 unit tests.

## Session log — 2026-10-31 P2.2 M2 key schedule

- Started from main after PR #8 and PR #9 merged.
- Added `derive_raw_pwd_key`, `derive_wrap_key` and `derive_object_key` per `docs/09_ENVELOPE_FORMAT_V0.md`. `ObjectKey` uses a fixed synthetic `RootSecret`, not the passphrase. Key `Debug` output is `TypeName(redacted)`.
- `seal_root` / `open_root` wrap that root. Wrong passphrase, a one-bit AAD flip and a one-bit tag flip all return `CryptoError::Unavailable` with display text `unavailable`.
- Expected `RawPwdKey`, `WrapKey`, `ObjectKey` and wrapped-root bytes are in `crates/test-vectors/src/key_schedule.rs`. They were produced by `crates/test-vectors/scripts/key_schedule_kat.py` before the Rust schedule test was written. Oracle: argon2-cffi 25.1.0, HMAC-SHA256 HKDF in the script, PyNaCl 1.6.2.
- Argon2id parameters for the vector are the candidate profile `m=65536 KiB, t=3, lanes=4`. Empty passphrases, passphrases over 1024 bytes, and out-of-range parameters return `UnsupportedParameters` before Argon2 runs.
- `encrypt_authenticated` still returns `NotImplemented`. `status()` is unchanged.
- `cargo fmt --all -- --check`, `cargo test --workspace --locked --offline` (20 unit tests) and `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` exited 0 on rustc 1.99.1.

## Session log — 2026-10-31 P2.2 M1 published vectors

- PR #8 was still open, so this work is branched from `cursor/verify-p2-1-compiler-814d`.
- Pinned exact crates in `[workspace.dependencies]`: argon2 0.6.0 (MSRV 1.85), hkdf 0.13.0, sha2 0.11.1 (MSRV 1.88), chacha20poly1305 0.11.0, zeroize 1.9.1. No UniFFI, no secrecy.
- `cargo generate-lockfile` pulled those crates and their transitive registry dependencies (including `aead` 0.6.1, `hmac` 0.13.0, `blake2` 0.11.0, `password-hash` 0.6.1, `getrandom` 0.4.3).
- Known-answer tests in `crates/crypto/src/published_kat.rs`:
  - RFC 9106 §5.3 Argon2id, including the published secret and associated data. 32-byte tag matched.
  - RFC 5869 A.1 HKDF-SHA-256 test case 1. PRK (32) and OKM (42) matched.
  - draft-irtf-cfrg-xchacha-03 A.3.1. Ciphertext and 16-byte tag matched; decrypt with the same AAD returned the published plaintext.
- `encrypt_authenticated` still returns `NotImplemented`. `status()` is unchanged.
- Public parser rejection tests in `eidoron-test-vectors` cover header lengths 0/135/136/137 and magic, version/suite/flags/KDF id, Argon2 bound rows, object lengths including the 1,048,680 maximum, and HEAD lengths 65/66/67.
- `cargo fmt --all -- --check`, `cargo test --workspace --locked --offline` (17 unit tests) and `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` exited 0 on rustc 1.99.1.

## Session log — 2026-10-31 P2.1-V compiler verification

- Read README, master plan, roadmap, P2 ledger and the five crate sources. P2.1-V was the unblocked next unit.
- rustc 1.99.1 (`58cf8f9c3`, commit date 2026-10-13) was already active via `rust-toolchain.toml`.
- `cargo test --workspace --locked --offline` passed (10 unit tests) and clippy `-D warnings` passed **before** source edits. The compiler was not rejecting the scaffold.
- `cargo fmt --all -- --check` failed. Applied rustfmt (import order in `eidoron-test-vectors`, `assert_eq!` wrapping in `eidoron-provider-local` and `eidoron-vault`).
- Deleted the hand-annotated `Cargo.lock` and regenerated it with `cargo generate-lockfile --offline`. Package graph unchanged: five path crates, no external crates, lockfile version 4. Cargo's standard header replaced the manual bootstrap comments.
- Re-ran fmt check, locked offline tests and clippy; all exit 0. Recorded in `docs/12_P2_IMPLEMENTATION.md`. Next tasks: `docs/PLAN.md`.
- No cryptographic behavior added. Passing tests still mean the fail-closed stubs and public shape checks behave as written.

## Session log — 2026-10-31 P2.1 scaffold

- Read latest main, P1.5 review and ADR-0004 before creating `feat/p2-1-rust-workspace-20261031`.
- Created Rust 1.99.1 / edition 2024 workspace with five path-only crates and source-level unit tests.
- Public envelope inspection returns only `Untrusted*` types; malformed lengths/magic and KDF resource budget are checked without invoking crypto.
- `eidoron-crypto` and vault import **return NotImplemented**. `MemoryStore` only persists in process RAM and rejects conflicting overwrite of an opaque ID.
- Added `docs/12_P2_IMPLEMENTATION.md` with module boundaries, verification commands, nonclaims and next owner task.
- Only **static source/tree-level** checks are feasible. **No cargo/rustc tests executed; hand-composed Cargo.lock needs regeneration**.
- Branch: `feat/p2-1-rust-workspace-20261031`; PR #7 merged to main (squash) despite build verification pending; P2.1-V remains blocked until Rust toolchain available.

## Session log — 2026-10-31 P1.1

- Re-read main and baseline docs; chose a bounded **documentation-only** milestone.
- Added `docs/08_SECURITY_TARGET.md` covering T0–T6, C01–C08, W0/W1 observable games, SEC/DEN tests, failure semantics, release claim gates.
- Updated README, master plan, threat model and roadmap cross-references.
- **No executable tests, encrypted storage engine or security audit performed.**
- Branch: `docs/p1-1-security-target-20261031`; PR #2 merged to main (squash), 2026-10-31 JST.
- Next: P1.2 ADR-0002; do not mistake test contracts for passing tests.

## Session log — 2026-10-31 P1.2

- Re-read current main docs and official RustCrypto, UniFFI, Apple and Android platform documentation.
- Added `docs/decisions/0002-crypto-dependencies-ffi.md` with candidate libraries, explicit Rust/native boundary, OS wrapper key constraints, upgrade/audit policy and P1.3 open questions.
- Updated crypto architecture, roadmap, README and progress references.
- **Documentation only**: no code, dependency manifest, `Cargo.lock`, platform build, cryptographic runtime test or independent audit.
- Branch: `docs/p1-2-crypto-dependencies-ffi-20261031`; PR #3 merged to main (squash), 2026-10-31 JST.
- Next: P1.3 envelope-format specification + ADR-0003.

## Session log — 2026-10-31 P1.3

- Re-read latest main documentation and checked RFC 9106 (Argon2id), RFC 5869 (HKDF), RFC 8949 (deterministic CBOR) and RustCrypto XChaCha20Poly1305 references.
- Added `docs/09_ENVELOPE_FORMAT_V0.md` with fixed candidate binary layouts and `docs/decisions/0003-envelope-and-key-hierarchy.md`.
- Resolved prior **Vault v0** key-choice ambiguity to a random RootSecret, password-derived wrapper and per-object HKDF key schedule. Shadow allocation and deniability still unresolved.
- Updated README, crypto overview, roadmap, research references and dated progress/hand-off.
- **No implementation, compiled tests, security audit or production-format freeze.**
- Branch: `docs/p1-3-envelope-format-v0-20261031`; PR #4 merged into main (squash), 2026-10-31 JST.
- Next: P1.4 test/fuzz plan, then P1.5 review before P2.

## Session log — 2026-10-31 P1.4

- Detected that P1.3 had already merged (PR #4); avoided overwriting it with a competing format proposal.
- Read current `docs/09_ENVELOPE_FORMAT_V0.md` and ADR-0003, authored P1.4 **documentation-only** `docs/10_TEST_AND_FUZZ_PLAN.md`.
- Enumerated exact positive/negative byte vectors, property/fuzz tests, malicious-provider failure state model, SEC and CLAIM coverage, and 10 pending P1.5 blockers.
- No crates installed, files encrypted, actual vectors created, test suites executed or security guarantees verified.
- Branch: `docs/p1-4-test-fuzz-plan-20261031`; PR #5 merged to main (squash), 2026-10-31 JST.
- Next: P1.5 security design review, decide BLK-01..10, keep progress updated.

## Handoff recipe (another AI, mobile or desktop)

1. Read this page first, then `README.md`, `docs/00_MASTER_PLAN.md`, `docs/01_THREAT_MODEL.md`, and ADRs.
2. Check main branch, open PRs and newest commits; do not trust stale status labels.
3. Take first TODO not blocked by dependencies; preserve scope.
4. Before implementing, write purpose, acceptance, risk and files to change in PR/issue.
5. On completion, update this table, date and decision ledger **in the same commit/PR** as changes; link test commands and relevant commit/PR.
6. If the plan changes, edit current plan but preserve traceability with a new ADR and Git history; never silently mark skipped tasks as done.
7. Keep no actual secrets/credential dumps in public repo; use synthetic fixtures.
8. GitHub Actions is optional, **not a prerequisite**. Prioritize workflows operable from GitHub's mobile/web interface.

## Session log

### 2026-10-31 — Foundation authored
- Verified the newly initialized public repository and its MIT license.
- Created initial architectural, security, UX, research, roadmap and handoff documentation.
- No executable cryptographic code, cloud infrastructure, secret credentials or automated tests introduced.
- PR #1 was reviewed for scope and merged to main (squash); 10 documentation/README files changed.
- Next: P1.1 Security Target; see above.
