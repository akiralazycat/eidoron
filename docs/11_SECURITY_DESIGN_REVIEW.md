# P1.5 — Eidoron Vault v0 internal security design review

- Review performed: **2026-10-31 JST**
- Reviewer: **AI-assisted internal specification review (NOT an independent professional cryptographic audit)**
- Artifacts reviewed: [security target](08_SECURITY_TARGET.md), [envelope candidate](09_ENVELOPE_FORMAT_V0.md), [test plan](10_TEST_AND_FUZZ_PLAN.md), [ADR-0002](decisions/0002-crypto-dependencies-ffi.md), [ADR-0003](decisions/0003-envelope-and-key-hierarchy.md)
- Change decision: [ADR-0004](decisions/0004-security-review-scope-and-safety.md)
- **Disposition: CONDITIONALLY READY FOR AN ISOLATED, SYNTHETIC, LOCAL-ONLY RUST PROTOTYPE. NOT READY FOR CLOUD, PRODUCTION, REAL DATA, SHADOW, OR SECURITY MARKETING CLAIMS.**
- P1.5 status: **internal document review recorded; independent implementation/protocol security review not completed**.

## 1. What was reviewed / what was not

Performed: read P1.1–P1.4 documentation, analyzed byte-level invariants, historical replay, key rotation, resource limits, directory-reference consistency, CSPRNG assumptions, recovery, and cloud transaction model; reviewed normative references (RFC 9106, 5869, 8949). Checked that header is 136 bytes, object prefix 88 bytes, HEAD 66 bytes, and envelope min/max 106 / 1,048,680 bytes.

**Not performed:** cryptographic proof, manual/automated code audit (no code exists), executable KAT, fuzz campaign, formal verification, iOS/Android toolchain tests, provider CAS trials, threat simulations, independent third-party sign-off. Any claim of "audited secure storage" is **unauthorized**.

## 2. Decision: sharply scoped next implementation

Allowed next (conditional prototype only):
- P2.1 Rust workspace and pure local deterministic test harness; synthetic data only; no user registration, cloud keys or personal archives.
- P2.2 independently sourced primitive KAT and exact-byte fixture generation; detect spec disagreements first.
- P2.3–P2.6 local encryption/verified graph and fault-injection code **only for experimental evaluation**, subject to reviewed errata and fail-closed invariants. Run under explicit "DO NOT USE FOR REAL DATA" warning.
- Strict parser, authenticated contents, best-effort memory lifecycle and *local* persistence proof of concept. Local provider cannot claim universal power-loss-safe atomic rename until platform durability behavior is verified.

Not allowed until later gates:
- Remote multi-device sync, optimistic/cloud HEAD CAS, cloud password changes or destructive GC; P3 requires evidence for a specific provider's exact semantics.
- Device biometrics, secret mode, Shadow/Specter deniability, Dead Drop: these have independent security/UX requirements.
- A user-facing stable file-format promise, production release, real confidential files, marketing claims, or the assertion that security design has an independent sign-off.

**Why:** A small local test harness can detect cryptographic design mistakes without prematurely promising freshness, safe cloud transactions or hidden-storage protection.

## 3. BLK-01..10 disposition matrix

| ID | Severity | Design decision / correction | Status after review | Blocking for |
|---|---|---|---|---|
| BLK-01 | Medium | Correct plaintext min to 2 bytes; header/object parser bounds 136 / 106..1,048,680; add exact boundary tests | **Resolved in v0 candidate wording; tests pending** | P2 verified parser until tests pass |
| BLK-02 | Critical | HEAD is untrusted; define local trusted checkpoint tuple and fork detection; no checkpoint = `FreshnessUnknown`. No standalone HEAD MAC claimed to solve freshness; provider could replay MAC with old head | **Specified; secure persistence and lineage tests pending** | sync/currentness claims; P3 |
| BLK-03 | Critical | No generic provider CAS. Start with local-only provider, disallow cloud & multiwriter until provider-specific conditional commit + consistency tested. CAS support is not inferred from ETag/listing | **Scoped out of local prototype; unresolved for P3** | cloud sync & release |
| BLK-04 | High | Password rewrap retains RootSecret. An old header + old password permits **future as well as historical object** decryption if root is unchanged. Rename as non-revoking rewrap; no 'revoke password' UX. Disable cloud rewrap; true revocation needs a separately-reviewed root-rotation protocol | **Risk documented; cloud feature blocked** | credential revocation UX/release |
| BLK-05 | Medium | UTF-8 passphrase bytes preserved exactly; filenames MUST be Unicode NFC before archive acceptance, and **file export must never overwrite** conflicting host path spelling/casefold; explicit collision result | **Rule specified; platform tests pending** | native import/export |
| BLK-06 | Medium | 1 MiB **actual encoded object** cap and graph count/depth caps apply together. A nominally permitted entry count may still exceed size bound; refuse explicitly, never truncate. No sharding advertised in v0 | **Rule clarified; boundary tests pending** | oversized graph handling |
| BLK-07 | Critical | No concurrent rewrap/multi-device mutation in baseline. P3 must supply transactional replace + recoverable local journal + rollback-checkpoint model; local prototype may *test* rewrap in memory/synthetic fixture only | **Remote operation deferred; no transactional guarantee** | password update, cloud writes |
| BLK-08 | High | v0 portable unlock uses passphrase only. No recovery bypass/secondary slot is accepted. Loss of passphrase can permanently lose access. Restore on an untrusted/new device is `FreshnessUnknown`. Device convenience key may supplement later, never replace password | **Scope resolved; recovery feature not shipped** | production onboarding/backup |
| BLK-09 | High | Library choices are candidates only. Exact pinned versions, Rust toolchain, UniFFI builds, BOM, `cargo audit`/deny, memory/KDF on-device benchmark required before production claim. No "security-certified" crate label | **Implementation gate open** | release/device integration |
| BLK-10 | Critical | Vault header is conspicuous and storage-size/timing data leak. Shadow/Specter remain *experimental* and have no inherited security claim from passing Vault tests | **Explicit nonclaim settled** | hidden-vault marketing/release |

**Meaning of "resolved":** the specification ambiguity or scope was settled. It does **not** mean the corresponding behavior has been implemented, experimentally verified or externally audited. BLK-02/03/07/09 retain **conditional implementation or release blockers**; none is silently waived.

## 4. Additional findings from design review

### FIND-11 — Generation and parent-reference scope must not be overstated (High)

The object AEAD AAD authenticates **public object header fields**, while decrypted file chunks authenticate file_id and ordinal; the *commit root and authenticated graph* carry logical generation and parent-link relationships. Do **not** assert that each immutable chunk's ciphertext individually cryptographically binds its current generation or path: chunks may be legitimately referenced in multiple versions, and a malicious provider can replay a full valid older graph. Verification MUST start from the selected authenticated commit and check the entire reference path. The trusted checkpoint is the only candidate freshness anchor. Test two valid forks with the same generation but distinct commit-root IDs.

Disposition: **spec clarification added**, graph/fork tests required.

### FIND-12 — Root checkpoint identity must remain protected and durable (High)

Proposed local checkpoint: `(vault_id, last_verified_generation, last_verified_commit_root_object_id)`, stored in an app-controlled integrity-protected local state, not in the same provider-controlled bucket alone.

Decision table (when trusted checkpoint exists):
- Remote generation below local trusted generation → `SuspectedRollback`.
- Equal generation but different commit root ID → `ConcurrentConflict` or suspicious fork; **never `Synced`**.
- Remote generation above local → examine authenticated prior_commit root chain to checkpoint; if chain missing/inconsistent → `FreshnessUnknown` / `ConflictNeedsResolution`, not verified latest.
- Equal generation and same root ID → matches **previously observed local state**, but provider could have newer withheld updates (cannot prove global latest).
- No trusted checkpoint / fresh device → `FreshnessUnknown` even if AEAD verifies ciphertext.
- Remote HEAD absent → `RemoteUnavailable`/missing remote, not proof of deletion or currentness.

Do not persist checkpoint based solely on untrusted HEAD; only *after* verifying root graph and recording the correct local transaction/commit state. A modified local checkpoint due to T5 compromise is out of scope. An independent witness/consistency checkpoint is optional future study, not implied by local record.

### FIND-13 — Provider identities, directory names, and Unicode (Medium)

All file/directory names are encrypted but file paths exported to the OS must be collision-resistant across case-insensitive/normalizing file systems. Import should reject or explicitly canonicalize non-NFC names (no silent name renaming); export collision must yield a recoverable user decision, never overwrite or leak to unattended logs. Keep passwords byte-exact and never run filename normalization over passphrases.

### FIND-14 — Complete-file release policy (Medium)

Chunk AEAD authentication prevents exposing *tampered chunk content*, but does not establish that a file's descriptor, full length and all expected chunks are complete. A viewer MAY stream **individually verified chunks** with an explicit partial status; a completed export MUST validate the entire descriptor and total length and then finish an atomic verified export. Failure after partial preview MUST not report full integrity or success. P2 harness must verify no partial export remains as a falsely complete destination file.

### FIND-15 — Compression, quotas, and cleartext leftovers (Medium)

v0 no compression, no deniability padding, no deductive size privacy. Chunk counts and timing leak. P2 tests should inspect temp files, FFI copies and diagnostic logging. The provider may retain previous versions or copied objects indefinitely.

## 5. Required protocol errata and evidence links

The candidate v0 spec gains the following reviewer notes, without rewriting ADR-0003 history:
- plaintext length MUST be at least **2**; parser rejects length 1;
- public HEAD is **not a MAC and is not freshness-proof**; trusted local checkpoint tuple and its limits must be represented;
- password rewrap retains root and does NOT revoke **future** object access for a holder of an old header/password;
- cloud rewrap, cloud commits and multiwriter mode are **unsupported for local-only initial prototype**;
- canonical CBOR is RFC 8949 §4.2.1 bytewise encoded-key ordering, not RFC 7049 legacy length-first;
- generation is authenticated through commit-root/graph consistency, not independently embedded in every chunk;
- conflicting export host paths cannot be overwritten silently.

See amended [P1.3 candidate](09_ENVELOPE_FORMAT_V0.md) and [ADR-0004](decisions/0004-security-review-scope-and-safety.md). These amendments are **proposals for implementation**, not passing test evidence.

## 6. Explicit gate decisions

| Gate | Decision at 2026-10-31 | Required evidence for promotion |
|---|---|---|
| **G0: Docs/review** | **Internal review recorded** | Updated spec, ADR, blocker dispositions, handoff |
| **G1: P2 local synthetic prototype** | **Conditionally authorized** | No real data, no remote provider, no public marketing, fail-closed parsers, tests as code is built |
| **G2: P2 crypto/integrity functionality verified** | **NOT PASSED** | Exact vector KAT, independent expected bytes, fuzz/property results, file/graph integrity and regression |
| **G3: P3 safe cloud sync** | **NOT PASSED** | Provider-specific conditional publication and consistency tests, concurrency/data-loss proof-of-concept, remote rollback/restore UX |
| **G4: Native/device integration** | **NOT PASSED** | Actual iOS/Android UniFFI/Keychain/Keystore builds and recovery tests |
| **G5: Production claim/release** | **NOT PASSED** | Independent security audit, remediation, review of marketed claims, documented support and threat limitations |
| **G6: Shadow/Specter deniability** | **NOT PASSED / RESEARCH ONLY** | Separate T2/T3/T4 protocol/model and peer-reviewed evidence before any claim |

P1.5 **is not external approval**. No source or reviewer in this session can assert Eidoron's actual cryptographic security; there is no running program.

## 7. Next implementation plan (P2.1, scoped)

1. Create `crates/` workspace skeleton with crypto/format/vault/provider-local/test-vectors and a synthetic local fixture provider.
2. Pin compatible RustCrypto/UniFFI crate versions and Rust toolchain; record dependency audit results. Prefer validating crypto+format before introducing native binding code.
3. Implement **parser skeletons** with strict bounds, no raw secret logging; add table-driven negatives from [P1.4](10_TEST_AND_FUZZ_PLAN.md).
4. Produce independently checked exact-byte synthetic golden vectors before claiming interoperability.
5. Mark each completed task and tested commit in `docs/06_PROGRESS_HANDOFF.md`; no mandatory GitHub Actions or personal PC.
6. If any inconsistency in the candidate wire format emerges, **STOP**, update spec with new ADR, regenerate fixtures and only then proceed.

No cloud credentials, public user archives or production encryption release in this phase.

## 8. Sign-off limitations and references

- Internal decision author: AI-assisted technical review, **not a certified auditor and not independent of the specification author**.
- Formal cryptographic proofs / code execution / professional penetration tests: **not performed**.
- RFC 8949 core deterministic CBOR: https://www.rfc-editor.org/rfc/rfc8949
- RFC 9106 Argon2id: https://www.rfc-editor.org/rfc/rfc9106
- RFC 5869 HKDF: https://www.rfc-editor.org/rfc/rfc5869
- Historical decisions are preserved in Git; all normative design changes appear in [ADR-0004](decisions/0004-security-review-scope-and-safety.md).
