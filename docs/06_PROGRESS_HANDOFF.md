# Progress, Decisions and AI Handoff

- Created: **2026-10-31 JST**
- Last updated: **2026-10-31 JST**
- Current baseline: **P1 Security Protocol / P1.1 security target authored**
- Implementation status: **no code written**
- Foundation branch: `docs/foundation-master-plan-20261031` (merged)
- Foundation PR: https://github.com/akiralazycat/eidoron/pull/1 — merged into main on 2026-10-31 JST
- Foundation merge commit: `7835fd40e5608f5525db9dcb625b30ddff395e7e`
- P1.1 security-target PR: https://github.com/akiralazycat/eidoron/pull/2 — merged on 2026-10-31 JST
- P1.1 merge commit: `7a4a7d7fb9668d8d9fb6d98b2fc8d36e09aff374`

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
| P1.2 | Library/FFI/device secure storage ADR | TODO | **NEXT** — ADR-0002; must precede code |
| P1.3 | Binary envelope v0 spec | TODO | Must precede code |
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
| 2026-10-31 | P1.1 | Formal prospective security target and falsification map authored | Security claims not yet reviewed or verified; next ADR-0002 |

## Immediate next task (P1.2)

**Goal:** choose candidate Rust cryptographic dependencies, platform FFI boundary and device key lifecycle safely.
- Inputs: `docs/08_SECURITY_TARGET.md`, `docs/02_CRYPTO_ARCHITECTURE.md` and roadmap P1.
- Deliverable: `docs/decisions/0002-crypto-dependencies-ffi.md` with library comparison, maintenance and supply-chain policy, secret handling, benchmark parameters, and audit/trust boundary.
- Exit: actionable library/FFI choice with documented risks; **no crypto implementation until P1.3 envelope is reviewed and overall P1 gate is satisfied**.
- Then P1.3: normative versioned envelope, nonce strategy, authenticated context and test vectors specification.

## Session log — 2026-10-31 P1.1

- Re-read main and baseline docs; chose a bounded **documentation-only** milestone.
- Added `docs/08_SECURITY_TARGET.md` covering T0–T6, C01–C08, W0/W1 observable games, SEC/DEN tests, failure semantics, release claim gates.
- Updated README, master plan, threat model and roadmap cross-references.
- **No executable tests, encrypted storage engine or security audit performed.**
- Branch: `docs/p1-1-security-target-20261031`; PR #2 merged to main (squash), 2026-10-31 JST.
- Next: P1.2 ADR-0002; do not mistake test contracts for passing tests.

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
