# Progress, Decisions and AI Handoff

- Created: **2026-10-31 JST**
- Last updated: **2026-10-31 JST**
- Current baseline: **P2.2 M2 synthetic key schedule passes; vault object encryption API still NotImplemented**
- Implementation status: **RawPwdKey, WrapKey and ObjectKey derived; 20 unit tests pass; NO VAULT OBJECT ENCRYPTION**
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
| P2.2 | Known-answer crypto vectors and suite evaluation | PARTIAL | M1 and M2 done 2026-10-31. **NEXT** is M4 object AEAD. `encrypt_authenticated` remains `NotImplemented`. See `docs/PLAN.md` |
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

## Immediate next task (M4) — object AEAD

**Goal:** encrypt one object body as `kind || schema || payload`, with the length limits in `docs/PLAN.md` item 15. Keep a test-supplied nonce separate from the OS CSPRNG nonce.
- `encrypt_authenticated` stays `NotImplemented` until that object path has known-answer and failure tests.
- Explicit scope restrictions: no cloud, real user data, native secrets, Shadow/Specter, production security claims; no mandatory GitHub Actions or user's PC.

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
