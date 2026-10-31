# Implementation Roadmap and Release Gates

- Created / updated: 2026-10-31 JST
- Status: v0.1 sequencing; dates are recording dates, NOT delivery promises.
- Status reference: [Progress ledger](06_PROGRESS_HANDOFF.md)

## Phase map

| Phase | Goal | Dependencies | Exit criteria |
|---|---|---|---|
| P0 Foundation | Stable plan, ADR, research and handoff | initial repo | Docs and decision record committed |
| P1 Security Protocol | Threat model, format sketch and crypto library choice | P0 | Reviewable normative protocol; attack tests specified |
| P2 Vault Core | Rust encrypted objects, index, local provider | P1 | Known-answer, fuzz, crash and integrity tests pass |
| P3 Safe Sync | Remote adapter and cross-device reconciliation | P2 | Offline/conflict/replay/power-cut matrix passes |
| P4 iOS Experience | SwiftUI vault, viewer, import and local lock | P2/P3 | On-device privacy/performance checks pass |
| P5 Android & Recovery | Kotlin/Compose, interoperability and migration | P3/P4 | Same test vectors, restore and migration validated |
| P6 Shadow Research | Password-defined views, allocation invariants | P1/P2 + research | Non-corruption and specific threat-model evaluation |
| P7 Specter Research | Snapshot/trace resistance, ORAM candidates | P6 | Observable-trace study, cost model, external review |
| Release Gate | Scope-controlled shipping | P2–P5 and audits | Accurate security claims; Shadow/Specter excluded unless independently ready |

P6/P7 are parallel research and MUST NOT hold up an honest, useful Vault release. Zero guaranteed delivery timeline.

## P1 — exact work packages

- P1.1: **DONE (documentation only, 2026-10-31)** — T0–T6 observer definitions, prospective security claims C01–C08, falsification matrix SEC/DEN, research games and failure semantics in [08_SECURITY_TARGET.md](08_SECURITY_TARGET.md). Not peer-reviewed, implemented or certified.
- P1.2: **DONE (documentation only, 2026-10-31)** — ADR-0002 records RustCrypto candidate dependencies, UniFFI binding preference, OS device-key wrappers, secure-secret-handling/FFI risks, review and dependency policy. No crates integrated or security audit executed.
- P1.3: **DONE (documentation only, 2026-10-31)** — [Vault Envelope v0 candidate](09_ENVELOPE_FORMAT_V0.md) and [ADR-0003](decisions/0003-envelope-and-key-hierarchy.md): exact public binary offsets, protected CBOR metadata, random-root + password wrapper, per-object HKDF keys, AAD, HEAD, rewrap/rotation limitations and synthetic fixture contract. Not implemented or reviewed.
- P1.4: **DONE (documentation only, 2026-10-31)** — [Adversarial tests and fuzz plan](10_TEST_AND_FUZZ_PLAN.md): VEC/PAR/CBOR/GRAPH/SYNC matrix, SEC-001–013 and CLAIM-001 coverage, proposed fuzz/property cases, synthetic fixture and platform validation criteria. **Nothing executed; BLK-01..10 remain open.**
- P1.5: **DONE (internal documentation review only, 2026-10-31)** — [review and BLK-01..10 dispositions](11_SECURITY_DESIGN_REVIEW.md), [ADR-0004](decisions/0004-security-review-scope-and-safety.md). Synthetic offline/local-only P2 prototype conditionally permitted. **Independent audit/cloud/release gates NOT passed**.
Exit for synthetic P2 prototype: review must define a narrow local-only boundary, verified no-release/nonclaim policy and unresolved risks; **real-data, cloud and production security use remain prohibited until independent reviews and tests**.

## P2 — exact work packages

- P2.1: **DONE as a verified synthetic scaffold (2026-10-31)** — five dependency-free Rust crates, pinned `rust-toolchain.toml` (1.99.1), Cargo-generated path-only `Cargo.lock`, untrusted public format inspector, memory-only store, fail-closed crypto/vault stubs. `cargo fmt --check`, `cargo test` (10 unit tests) and `cargo clippy -D warnings` executed on rustc 1.99.1. Cryptography is still absent. See [P2 implementation ledger](12_P2_IMPLEMENTATION.md) and [development plan](PLAN.md).
- P2.2: deterministic versioned test vectors and direct primitive interoperability tests.
- P2.3: stream/chunk AEAD implementation, length limits, strict error model and zeroization attempts.
- P2.4: encrypted tree/index with object↔parent↔generation authenticated bindings.
- P2.5: local provider, atomic persistence, safe imports and verified exports.
- P2.6: property/fuzz/mutation tests, recovery and benchmarking.
Exit: cannot return unauthenticated plaintext; corruption detectable; recovery tested with no cloud.

## P3 — exact work packages

- P3.1: provider abstraction with explicit capability detection.
- P3.2: first remote provider evaluation (S3-compatible vs WebDAV vs consumer cloud constraints).
- P3.3: optimistic immutable commit protocol, resumable uploads, conflict revisions.
- P3.4: local trusted checkpoints / rollback notice; document partial protection.
- P3.5: offline→online, concurrent devices, expired credential, kill/restart, rate-limit and quota tests.
Exit: never silently lose a user's successfully committed data.

## P4–P5 — native & user readiness

- Native SwiftUI/Kotlin implementation with shared crypto core and platform-specific secure storage.
- Privacy-safe previews, app-switcher redaction, import/share/export tests, accessibility.
- Interop vectors across iOS/Android/Rust; lost-device recovery without provider plaintext.
- Support matrix, deterministic manual runbooks; optional CI later, not GitHub Actions-dependent.

## P6–P7 — research gates (no marketing claims)

- P6.1: compare independent namespace vs shared-pool model; reject naive hidden folder as deniable.
- P6.2: prove or experimentally falsify public-only-write safety and capacity accounting.
- P6.3: trace generator, snapshot adversary and multi-device crash tests.
- P7.1: investigate published deniable-storage / write-only ORAM schemes; estimate cloud request cost.
- P7.2: privacy/availability/performance tradeoff and mobile scheduling feasibility.
- P7.3: independent technical review and revised threat claims; default disabled if unresolved.

## P1.1 security specification evidence (2026-10-31)

- Source: [08_SECURITY_TARGET.md](08_SECURITY_TARGET.md), with explicit asset/observer/assumption/falsifier mapping and nonclaims.
- Gate passed: *document authoring only*. No runtime test or independent peer review was performed.
- Remaining P1 design and review work (P1.2–P1.5) must pass before implementing P2.

## P1.2 dependency and platform-design evidence (2026-10-31)

- Source: [ADR-0002](decisions/0002-crypto-dependencies-ffi.md).
- Recorded candidate crates and alternative evaluation, FFI contracts, Apple Keychain/Secure Enclave and Android Keystore/StrongBox separation, key lifecycle, dependency/release audit gates.
- **Gate passed: document/decision capture only.** No installed dependencies, builds, platform benchmarks or audits. Do not begin P2 until P1.3–P1.5 are reviewed.

## P1.3 binary format design evidence (2026-10-31)

- Sources: [Vault Envelope v0](09_ENVELOPE_FORMAT_V0.md) and [ADR-0003](decisions/0003-envelope-and-key-hierarchy.md).
- Recorded complete **candidate** byte offsets/sizes/endianness; public vs secret fields, key wrapping, deterministic metadata, authenticated references, nonce handling, rollback limitations and resource limits.
- **Gate passed: documentation only.** No executable vectors, parser, AEAD implementation, external review, mobile benchmarks or production compatibility guarantee. P1.4/P1.5 remain mandatory before P2.

## P1.4 adversarial test-design evidence (2026-10-31)

- Source: [10_TEST_AND_FUZZ_PLAN.md](10_TEST_AND_FUZZ_PLAN.md).
- Exact-byte test vector contract, malicious cloud rollback/CAS conditions, canonical CBOR rejection, Argon2 resource guardrails, secret-handling/FFI and real-device verification plans recorded.
- **No fixtures, compiled tests, actual fuzzing or independent audit.** P1.5 must resolve blockers before any cryptographic P2 code.

## P1.5 internal review record (2026-10-31)

- [Review document](11_SECURITY_DESIGN_REVIEW.md) and [ADR-0004](decisions/0004-security-review-scope-and-safety.md) cover BLK-01..10 and five additional findings, with explicit nonclaims and release gates.
- Candidate P1.3 format now records corrected ≥2-byte plaintext, trusted local checkpoint semantics, nonrevoking password rewrap, passphrase-only recovery boundary, graph-level generation binding and local-only single-writer prototype restriction.
- **Documentation-only evidence**: no executed tests, code audit, provider CAS, independent security reviewer or mobile validation. P2.1 local-only synthetic work is conditionally allowed; release readiness remains none.

## P2.1 verification checkpoint (2026-10-31)

- [Implementation record](12_P2_IMPLEMENTATION.md) documents the code scaffold, the executed fmt/test/clippy results, and the still-absent cryptography.
- No external Rust crates are installed. RustCrypto and UniFFI remain design candidates, not dependencies.
- **Execution status:** on rustc 1.99.1 (`58cf8f9c3`, 2026-10-13), `cargo fmt --all -- --check`, `cargo test --workspace --locked --offline` (10 passed) and `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` exited 0 after rustfmt and a Cargo-generated lockfile. Next work is [PLAN.md](PLAN.md) M1.

## QA matrix (minimum)

Platforms: Rust local harness → iOS real devices → Android real devices → cloud sandbox.
Adversarial inputs: malformed byte streams, huge advertised lengths, malicious provider substitutions.
Faults: network cut, app kill, disk full, device clock change, conflicting edits, lost passphrase, rollback.
Performance: cold unlock p50/p95, local encryption throughput, delta upload bytes, idle network/battery, quota.
Privacy: key/log/clipboard/preview/external viewers, app switcher, diagnostics, backup restore.

No dates or percentages should be invented. Progress records say not started / in progress / blocked / done and link proof (commit, test, ADR).

## Workflow

1. Read README → master plan → threat model → current handoff → relevant ADR.
2. Take ONE bounded task on a dedicated feature branch off main; record intended acceptance criteria in PR/issue.
3. Implement/test; no real secrets in repo; no mandatory GitHub Actions.
4. Update progress ledger **in the same branch/PR** after each completed task, including plan drift and verification evidence.
5. Merge after review; carry blockers and next task into handoff; retain Git history for replaced plans.
6. If format/security architecture changes, create a new ADR rather than quietly rewriting original assumptions.
