# Research Sources, Evidence and Open Questions

- Created / updated: 2026-10-31 JST
- Purpose: grounding and evaluation; links are sources, not proof of Eidoron's security.

## Reference specifications and implementation docs

- RFC 9106 Argon2: https://www.rfc-editor.org/rfc/rfc9106
  - Mobile parameter selection requires benchmark; RFC describes 64 MiB/t=3/p=4 as its memory-constrained recommendation.
- RFC 5869 HKDF: https://www.rfc-editor.org/rfc/rfc5869
- libsodium XChaCha20-Poly1305: https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305
- libsodium secretstream: https://doc.libsodium.org/secret-key_cryptography/secretstream
- Cryptomator security architecture: https://docs.cryptomator.org/security/architecture/
- Cryptomator explicit security target / metadata leakage: https://docs.cryptomator.org/security/security-target/

- NIST SP 800-38D, Appendix D: authenticated decryption alone does not prevent replay; a trusted freshness mechanism is separate: https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf

## Deniable storage background

- DataLair (PoPETs 2017), multi-snapshot adversary and write-only ORAM: https://crysp.petsymposium.org/popets/2017/popets-2017-0035.php
- DataLair arXiv abstract: https://arxiv.org/abs/1706.10276
- Search subsequent peer-reviewed work on deniable cloud storage, multi-client ORAM, and traffic analysis before adopting a construction. No source implies a drop-in secure cloud implementation.

## Distinguish scientific claims

1. **Encryption**: confidentiality/integrity of chunks against T0/T1 can be tested through specified cryptography.
2. **Hiding names/structure**: encrypted index protects names but not necessarily total bytes/updates.
3. **Deniability**: a formal observational game; never inferred just because storage looks random.
4. **Unlinkability/traffic secrecy**: separate network-level goal.
5. **Forensic protection**: device and OS boundary; not promised.

## Open evaluation questions

- Can a cloud object store expose enough history to distinguish even padded Shadow writes?
- How does a public-key-only client avoid hidden data corruption while maintaining an ordinary-only explanation?
- Is fixed-size pooling practical for growing media without anomalous storage expansions?
- Does object version retention defeat garbage collection or cover traffic?
- Can two offline devices modify one hidden namespace without a trusted allocation ledger?
- How large is the mobile latency/battery tradeoff of Argon2id and ORAM?
- How can onboarding, biometric integration and backup avoid making hidden-space existence visible?

## P1.1 security target

The normative proposed claim IDs, falsification test IDs and W0/W1 games are in [08_SECURITY_TARGET.md](08_SECURITY_TARGET.md). This is **planning evidence only** and must not be cited as passing security tests.

## Required evidence deliverables

- Written adversary model and clear nonclaims.
- Normative envelope design, cross-language test vectors, fuzz harness.
- Deterministic local fault injection and provider trace collection.
- Pre-registered comparator workloads and independent evaluators.
- Security audit with fixed findings and reproducible release tag.
