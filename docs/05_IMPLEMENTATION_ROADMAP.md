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

- P1.1: Freeze adversary taxonomy T0–T6; fill observation/leakage matrix with normative MUST/SHOULD statements.
- P1.2: ADR for crypto libraries, dependency audit policy, Rust FFI and mobile key storage.
- P1.3: Versioned on-disk envelope spec: canonical encoding, key hierarchy, authenticated fields, nonce discipline, limits and parse errors.
- P1.4: Threat-oriented test plan for file corruption, swap, truncation, replay, metadata substitution, KDF denial-of-service.
- P1.5: External/internal design review checklist and explicit release/claim policy.
Exit: no unresolved decision that impacts encryption safety. Only then begin coding P2.

## P2 — exact work packages

- P2.1: Rust workspace skeleton (`crates/crypto`, `format`, `vault`, `provider-local`, `test-vectors`).
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
