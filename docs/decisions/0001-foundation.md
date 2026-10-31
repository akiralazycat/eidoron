# ADR-0001 — Local-first native clients and gated deniable-storage research

- Date: 2026-10-31 JST
- Status: **Accepted for planning**, revisable with new ADR
- Authors: Eidoron planning session
- Affects: all phases

## Context

The product needs cloud-compatible file encryption with mobile-native convenience, while preserving a long-term research path toward hidden password-defined spaces. Existing encrypted vaults do not necessarily protect file size, timestamp or provider-side history. Naively creating a second encrypted folder does not establish plausible deniability. Shipping ambiguous claims would expose users to unacceptable risk.

## Decision

1. First ship an independently useful **Vault** with authenticated encryption and truthful metadata/security disclosures.
2. Pursue **Shadow** and **Specter** only behind research and review gates; no security claim based solely on UI, encryption or padding.
3. Prefer a **Rust portable core** with **SwiftUI iOS** and **Kotlin/Compose Android** native clients; FFI choice to be decided in ADR-0002.
4. Use vetted primitive candidates: **Argon2id**, **HKDF-SHA256**, **XChaCha20-Poly1305**, subject to protocol design and review; do not finalize now.
5. Prioritize **cloud-agnostic local-first** storage interfaces, initial local provider, then ONE measured cloud adapter.
6. Keep docs/roadmap/progress/ADRs up to date in Git, with task completion evidence and no mandated GitHub Actions.
7. Prefer mobile-operable workflows; avoid requiring local desktop machines for ordinary changes.

## Consequences

- Initial progress may look slower, but hidden-volume safety is treated as a scientific claim rather than a demo feature.
- Native UI builds are two platform tasks, but reuse crypto logic.
- Cloud integration is phased and provider-specific constraints are explicit.
- Public repo must contain no secrets, sensitive samples or operational keys.
- An independent security review is a release gate, not a marketing afterthought.

## Rejected at this stage

- 'One password = one magical safe hidden space' as a complete protocol.
- Reinventing block ciphers, using custom cryptography, or hand-rolling an ORAM.
- Promising trace invisibility or guaranteed deletion.
- Server-side plaintext processing as default.
- A mandatory CI/GitHub Actions infrastructure before testing locally or in a suitable environment.

## Follow-up

ADR-0002: crypto dependency selection, FFI and secure key lifecycle.
ADR-0003: encrypted binary envelope and rollback strategy.
ADR-0004: provider consistency model and conflict policy.
ADR-0005+: researched deniability construction and audited claims if evidence supports it.
