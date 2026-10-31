# Progress, Decisions and AI Handoff

- Created: **2026-10-31 JST**
- Last updated: **2026-10-31 JST**
- Current baseline: **P1 Security Protocol / P1.1–P1.4 documentation authored**
- Implementation status: **no code written**
- Foundation branch: `docs/foundation-master-plan-20261031` (merged)
- Foundation PR: https://github.com/akiralazycat/eidoron/pull/1 — merged into main on 2026-10-31 JST
- Foundation merge commit: `7835fd40e5608f5525db9dcb625b30ddff395e7e`
- P1.1 security-target PR: https://github.com/akiralazycat/eidoron/pull/2 — merged on 2026-10-31 JST
- P1.1 merge commit: `7a4a7d7fb9668d8d9fb6d98b2fc8d36e09aff374`
- P1.2 dependency/FFI PR: https://github.com/akiralazycat/eidoron/pull/3 — merged on 2026-10-31 JST
- P1.2 merge commit: `7dd3ba458838b50df24b9d3b9623ab8350e9cb0d`
- P1.3 envelope-format PR: https://github.com/akiralazycat/eidoron/pull/4 — merged on 2026-10-31 JST
- P1.3 merge commit: `fc1aad284349b25bde58888fcbe317b437b4a094`

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
| P1.5 | Security design review / release gate | TODO | **NEXT** — address BLK-01..10 before P2 |
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
| 2026-10-31 | OPEN-09 | HEAD freshness, conditional commit, historical descriptor risks and parser limits need P1.5 dispositions | Critical security/UX design gate |

## Immediate next task (P1.5)

**Goal:** review the actual Vault v0 protocol, tests and user claims against real security threats, with an explicit approve / revise / block disposition.
- Inputs: `docs/09_ENVELOPE_FORMAT_V0.md`, `docs/10_TEST_AND_FUZZ_PLAN.md`, ADR-0003, `docs/08_SECURITY_TARGET.md` and ADR-0002.
- Deliverable: `docs/11_SECURITY_DESIGN_REVIEW.md` with each BLK-01..10 disposition, approved threat model, architectural changes, unresolved P3/provider assumptions, evidence and sign-off limits. Amend candidate spec/ADR in a new Git commit if needed.
- Exit: **no unresolved security-critical ambiguity** in candidate Vault v0. Test execution and mobile validation remain P2 gates; this is NOT permission to claim audited security or Shadow deniability.
- Then plan P2 scoped core implementation, recording test/tool versions. No mandatory GitHub Actions.

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
- Branch: `docs/p1-4-test-fuzz-plan-20261031`; verify merge state in GitHub history.
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
