# ADR-0004 — Security review dispositions and local-prototype scope

- Date: 2026-10-31 JST
- Status: **Accepted as a conditional internal design decision; no production security approval**
- Extends: [ADR-0003](0003-envelope-and-key-hierarchy.md)
- Review: [P1.5 security design review](../11_SECURITY_DESIGN_REVIEW.md)
- Candidate wire protocol: [09_ENVELOPE_FORMAT_V0.md](../09_ENVELOPE_FORMAT_V0.md)

## Context

P1.4 identified 10 unresolved questions in the Vault v0 protocol. Continuing to build a cloud product without limiting HEAD replay, concurrent commits, password rewrap and recovery would risk false safety guarantees and data loss. The current project is **docs-only**, so there is no implementation to audit.

## Decision

1. **Split design readiness from product readiness.** Proceed to a *synthetic, offline, local-only Rust prototype* under nonproduction warnings; do not enable cloud, multiwriter, actual sensitive data or user security promises.
2. Fix v0 plaintext minimum at 2 bytes (kind + schema). Total object envelope limit remains 106..1,048,680 bytes; strict parser rejects short/surplus bytes.
3. Treat HEAD as *untrusted selector*, not a certificate. Use a **trusted client-local high-water checkpoint** of (vault_id, authenticated generation, authenticated commit object ID) where available; same-generation forks and rollback must be flagged. A never-before-seen device without checkpoint has **FreshnessUnknown**. No HEAD MAC substitutes for rollback trust.
4. **No generic cloud CAS claim.** P3 must test selected provider's exact atomicity/durability/consistency semantics, plus conflict preservation. Until then, remote sync/multi-device writes are unsupported.
5. **Password rewrap is non-revoking.** Old password + historical header + same RootSecret can decrypt all subsequent objects encrypted under that root. Do not label rewrap "password revocation". For local prototype only test it using synthetic/in-memory fixtures; no remote rewrap transaction feature. Full root rotation requires separate ADR, backup and journal.
6. **Passphrase-only portable access** in candidate v0. No secondary recovery slot or universal bypass credential. Lost passphrase may cause irrevocable data loss. Device biometric convenience keys are deferred to native integration.
7. Enforce both per-object byte ceilings and logical count/depth caps. Normalize filenames to NFC according to a documented reject/accept rule; password bytes remain unchanged. Exports MUST detect collisions with casefold and normalization differences and not overwrite.
8. Make graph-level, not per-chunk, generation/path authentication claims. Every verified file traversal starts from the authenticated commit root and checks parent, ID, chunk order and size.
9. Rust dependency and FFI releases require pinned versions, independent vector references, platform builds, code audit and real-device lifecycle testing; none are achieved here.
10. Vault's recognizable header and provider-visible metadata do not offer Shadow/Specter deniability. Hidden storage remains a separate research protocol and release gate.

## Rejected / deferred

- Adding a standalone MAC to HEAD as a supposed replay cure: a provider can replay old valid MAC and HEAD together.
- A generic fallback 'last writer wins' when provider lacks CAS.
- Implying password-only header rewrap revokes old credentials against stored histories.
- Shipping a hidden-mode UI and treating concealment of menu items as cryptographic deniability.
- Keychain/Keystore as the sole recovery route.
- Binding a file chunk to a fixed generation (would prevent legitimate reuse across versions); verify generation via authenticated commit graph instead.

## Consequences

- Full cloud feature delivery is deferred until P3 with provider evidence.
- Local-only Rust prototype can advance, validate primitives and synthetic objects while clearly labeled unsafe for real-world secret storage.
- Future wire-format or key changes MUST use another ADR and regenerate exact reference fixtures.
- P1.5 is an **internal review** only; independent security audit remains a release prerequisite.
