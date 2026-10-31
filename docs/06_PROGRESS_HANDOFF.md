# Progress, Decisions and AI Handoff

- Created: **2026-10-31 JST**
- Last updated: **2026-10-31 JST**
- Current baseline: **P0 Foundation / completed**
- Implementation status: **no code written**
- Working branch for this milestone: `docs/foundation-master-plan-20261031`
- Merge status: pending at document authoring time; Git/PR is the final source of truth.

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
| P1.1 | Formalize adversaries/claims into normative spec | TODO | **NEXT** |
| P1.2 | Library/FFI/device secure storage ADR | TODO | Must precede code |
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

## Immediate next task (P1.1)

**Goal:** convert threat model v0.1 to a protocol-facing security target.
- Inputs: `docs/01_THREAT_MODEL.md`, `docs/03_STORAGE_SYNC.md` and research references.
- Deliverable: `docs/08_SECURITY_TARGET.md` (create) with actor assets, observer traces, claims/out-of-scope, precise T0/T1 properties, optional T2–T4 experimental games, failure semantics, and tests that would falsify the claims.
- Exit: each security property maps to an observable test and a documented assumption; maintain explicit nonclaims.
- Then P1.2: choose Rust cryptographic libraries and safe FFI requirements via ADR-0002.
- No implementing encrypted formats before P1.3 is reviewed.

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
- Next: P1.1 Security Target; see above.
