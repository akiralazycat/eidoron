# Eidoron Security Target v0.1 — Normative Requirements and Falsification Plan

- Created: 2026-10-31 JST
- Updated: 2026-10-31 JST
- Work package: P1.1
- Status: **Specification baseline authored; NOT peer-reviewed, implemented, audited or proven**
- Related: [Threat Model](01_THREAT_MODEL.md) · [Crypto Architecture](02_CRYPTO_ARCHITECTURE.md) · [Storage/Sync](03_STORAGE_SYNC.md) · [Roadmap](05_IMPLEMENTATION_ROADMAP.md)
- Interpretation: **MUST / MUST NOT / SHOULD / MAY** are prospective design requirements, not statements that current software satisfies them.

## 0. Scope and interpretation

This target defines which claims may be made about **Vault** (candidate shipping product), which remain experimental for **Shadow** (password-defined hidden space), and which belong to **Specter** (multi-snapshot / provider-trace resistance).

A passing integration test is **evidence of behavior**, not a cryptographic security proof. Formal reductions, third-party review, independent reproducibility and examination of implementation assumptions are necessary for stronger claims. No hidden-space claim is authorized by this document.

This spec constrains later design choices; it does **not** select a final byte format, library, password-recovery design, key hierarchy or cloud adapter.

## 1. Assets, roles, observers and boundaries

### Assets

- **A1:** File plaintext and decrypted preview representations.
- **A2:** File names, hierarchical relationships, tags, encrypted search index, document annotations.
- **A3:** Root secrets, data encryption keys, passphrases, local recovery materials.
- **A4:** Logical file integrity, generation continuity, authoritative commit membership.
- **A5:** Whether a secret namespace exists and which operations use it (**research only**).
- **A6:** Client-local temporary data, caches, thumbnails and background snapshots.
- **A7:** Recovery availability and user-controlled export; remote availability is not assured.

### Roles

- **Owner:** authenticates locally and initiates read/write/export.
- **Client:** trusted app build plus Rust cryptographic engine, on a supported uncompromised OS.
- **Provider:** cloud transport, object storage, histories, quota and API metadata; never receives intentional plaintext/secret keys.
- **Attacker:** chosen by T0–T6; may hold some credentials, modify storage, observe histories and/or network telemetry.

### Observer classes (cumulative only when explicitly combined)

| Threat | Attacker observation / capability | Security posture |
|---|---|---|
| **T0** | One selected time: complete provider object bytes, visible names/IDs, sizes, count, directory and generic format, without passwords | Vault confidentiality/integrity goals with explicitly acknowledged metadata leakage |
| **T1** | T0 plus replace, truncate, delete, replay, swap, reorder or selectively withhold provider objects and commits | Reject unauthorized modifications when detectable; availability and unconditional freshness impossible |
| **T2** | Ordered snapshots and historical object revisions, timestamps, creation/deletion, size/usage and observed provider retention | **Shadow/Specter research only**; Vault does not promise hidden activity |
| **T3** | T2 plus API method, object ID, client sessions, timing, request bytes, IP/device/account linkage and error patterns | **Specter research only**; no anonymity promise |
| **T4** | Access to *ordinary* password, ordinary namespace, applicable backups and all ordinary-access behavior; may be combined with T0–T3 | **Shadow/Specter research only**; ordinary-key disclosure can expose public data |
| **T5** | Compromised or unlocked client, memory capture, compromised app binary/OS, filesystem forensics | Out of scope for strong confidentiality/deniability, even after best-effort cleanup |
| **T6** | Compelled disclosure, physical coercion, adversarial observation of human behavior | No guaranteed protection or safe deniability under coercion |

The provider may always refuse service, delete data, record access and retain versions. It can learn account identity and billing information. Transport security, OS protections and provider behavior are **assumptions to enumerate**, not universal guarantees.

### Observation transcript

For any experiment, define `Obs(T, run)` as a serialization of everything the declared adversary can see. The transcript MUST specify:
- initial provider state and setup time; vault creation and any reserve/padding allocation;
- all observable object bytes, IDs, sizes, history and deletion markers allowed by T;
- ordered API actions, timing and actor/device/account relationships when T3 applies;
- public password and decrypted public view when T4 applies;
- setup, capacity growth, key/format migration, garbage collection, recovery, sync conflicts, crash/restart, offline/resume;
- explicit exclusions (e.g. client RAM for T0–T4 if T5 not included).

A study that excludes setup, growth, idle periods or retries MUST label this narrower observer and cannot generalize to the full threat class.

## 2. Vault design claims: prospective normative requirements

**Claim C01 — Encryption boundary (T0).**
- MUST encrypt file plaintext **and** sensitive metadata locally before transmitting or persisting them in remote storage; provider-facing diagnostic logs MUST NOT contain them.
- MUST document public envelope metadata and all exposed file length/traffic information.
- Assumption: uncompromised client and vetted cryptographic primitive/library; password has sufficient entropy.
- Falsifier: synthetic secret bytes or sensitive file names show in a provider trace, crash log or ciphertext object in cleartext.

**C02 — Confidentiality under declared leakage (T0).**
- MUST use a reviewed authenticated encryption protocol with independently generated or safely derived keys and unique nonce usage under each key.
- MUST use a memory-hard passphrase KDF; parameter bounds must prevent memory/CPU denial of service on parse.
- MUST define a confidentiality experiment that compares equal-leakage chosen plaintext workloads. Ciphertext length or total size is **allowed leakage unless a separate concealment claim states otherwise**.
- Assumption: randomness and KDF entropy/parameters.
- Falsifier: nonce collision in tested lifecycle; deterministic encryption under a fixed key due to nonce misuse; successful non-password plaintext recovery in red-team experiment.

**C03 — Strict authentication and anti-mixup (T1).**
- MUST authenticate the bytes **before** returning plaintext to the caller or making it available to preview/export.
- MUST bind required context (format version, object identity, chunk ordinal, parent reference and logical generation) cryptographically, in protected metadata/AAD as appropriate.
- MUST reject wrong key, corrupted tag, truncated or swapped object, duplicate/ambiguous canonical encoding and inconsistent tree references.
- Assumption: trusted roots or authenticated parent references are available.
- Falsifier: mutated/spliced ciphertext returns apparently valid altered plaintext or silently accepted unrelated file bytes.

**C04 — Freshness and rollback honesty (T1).**
- MUST NOT claim that AEAD authentication alone proves freshness; an old, previously valid authenticated snapshot may be replayed.
- MUST detect rollback when a previously trusted, local/independent high-water mark exists and comparison is possible. If a new device has no trustworthy checkpoint, MUST report **freshness unknown**, not **current/verified**.
- MUST distinguish missing data / network errors from proven tampering where evidence permits.
- Falsifier: a previously trusted generation N is replaced by generation N−1, yet UI reports current/verified; uncheckable state is labeled safe.

**C05 — Crash-safe, conflict-safe persistence (T1 / accidents).**
- MUST NOT publish a new authoritative root before referenced content is durably available, under documented provider capability assumptions.
- MUST NOT silently replace an acknowledged committed edit on sync conflicts. Preserve divergent revisions or block with an explicit conflict state.
- MUST handle kill/offline/quota/failed upload as pending or recoverable, with no false 'synced' status.
- Falsifier: deterministic fault injection produces silent committed data loss or a root referencing never-committed chunks with no recovery path.

**C06 — Key lifecycle and locking (T0 / local-scope).**
- MUST store secrets with purpose separation, redact secrets in logs, avoid serialization/telemetry of keys, and implement best-effort session zeroization.
- MUST NOT advertise local lock as forensic erasure, cloud deletion, protection from an unlocked compromised OS, or destruction of copies already exported.
- SHOULD support native platform secure storage for appropriate **device wrapping** roles with documented portability/recovery tradeoffs.
- Falsifier: secrets appear in routine logs/backups due to app implementation; UI represents lock as guaranteed remote erase.

**C07 — Recovery and migrations (T1 / accidents).**
- MUST define and test how backup, restore, format upgrade and interrupted rotation behave before shipping.
- MUST warn when password/key loss makes ciphertext unrecoverable; provider can destroy availability.
- MUST NOT silently reinterpret corrupted or future-version objects.
- Falsifier: unsupported format is parsed under weaker rules; recoverable backup is accepted as current without required freshness distinction.

**C08 — Honest user-visible state and claims (T0–T6).**
- MUST clearly distinguish **local**, **upload queued**, **synced**, **conflict**, **integrity error**, **freshness unknown** and **recovery required** states.
- MUST label Shadow/Specter research and MUST NOT promise hidden-volume safety, traffic invisibility or protection under T5/T6 based on an attractive UI.
- Falsifier: shipping UI or marketing implies protection for an adversary not covered by evidence.

## 3. Experimental Shadow/Specter objectives — not shipping claims

### G-SHADOW-0: Ordinary-key consistency (T4 with stated snapshots)

Define two worlds with the **same public-facing workload** and public password:
- `W0`: public namespace only, including permitted background/cover operations.
- `W1`: identical public logical operations plus hidden operations constrained to an explicitly declared storage, timing and bandwidth budget.

The evaluator chooses secret activity consistent with a pre-registered workload policy. The challenger samples bit `b`, executes `Wb`, and discloses `Obs(T, Wb)` plus public credentials/view to adversary `D`. Report:

`Adv(D,T) = |Pr[D(Obs(T,W1))=1] - Pr[D(Obs(T,W0))=1]|`.

This is an *experimental distinguishing metric definition*, not a formal security proof. All randomness, fixture distributions, observation periods, construction assumptions and allowed public explanation must be recorded. A construction-level proof needs a rigorous game and reduction.

A meaningful study MUST explain how the W0 run generates operations indistinguishable from W1 without secret writes (such as cover activity), including storage expansion, retries and recovery. A visible hidden-only directory, new header, reserved marker or distinctive 'shadow password' metadata is an immediate design concern.

### G-SHADOW-1: Public-only write safety (T4, multiple devices)

An ordinary-key-only client MUST be able to perform all *supported* ordinary operations without corrupting live hidden bytes or hidden indexes under the stated capacity and concurrency model. It MUST NOT depend on learning hidden allocations through a visible marker or key oracle.

Test at least: near-full pool, public imports, deletions, reallocation, quota exhaustion, offline device, concurrent device, interrupted update, GC, migration and key rotation. The design MAY prohibit an operation with a general, equally plausible capacity/retry reason; it MUST NOT falsely claim an unimplemented strategy is safe.

**Current state: unresolved.** The shared cell pool idea is not a solution to this invariant.

### G-SPECTER-0: Multi-snapshot and full trace resistance (T2 / T3 plus T4)

Repeat the W0/W1 game with:
- T2: every provider snapshot, object ID lifecycle, previous versions, quota/growth and timestamps;
- T3: all provider requests, times, payload sizes, IP/client metadata and errors;
- T4: ordinary password/view simultaneously, not merely ciphertext.

The protocol MUST specify what it permits the attacker to observe and what is intentionally leaked. Success against T2 alone MUST NOT be marketed as protection against T3. Statistical classifiers and measured overhead are evidence; independent cryptographic review is required for a security claim.

### G-RESOURCE-0: Cost and availability

Measure for paired public-only and hidden workloads: API requests/edit, bytes/edit, idle bytes/day, cache, CPU/battery, p50/p95 operation latency, cloud version growth, storage overhead, number of clients and expected sync delay. Include actual offline/mobile suspension and account quotas. No security claim may assume permanent periodic traffic when the OS cannot schedule it.

### Experimental gating

- [ ] Security game reviewed by cryptography specialist.
- [ ] Protocol defines safe public-only writes without hidden-key knowledge.
- [ ] W0/W1 experiment harness, full logs and seedable synthetic workload fixtures are published.
- [ ] Snapshot and API-observation attacks run and results published with methodology.
- [ ] Recovery, capacity and multidevice cases tested on real provider(s).
- [ ] Independent review of implementation and revised claims.
- Until all relevant boxes pass, **no publicly supported deniability guarantee**.

## 4. Falsification-oriented test requirements

These IDs establish future test contracts, not executed tests.

| Test ID | Claims / threats | Adversarial input or fault | Required observed result |
|---|---|---|---|
| **SEC-001** | C01 / T0 | Import synthetic file containing a unique marker | Provider objects/logs do not contain marker or plaintext filenames |
| **SEC-002** | C02 / T0 | Known-answer KDF/AEAD vectors, fresh re-encryption | Correct vectors; no same key+nonce reuse; no accidental deterministic ciphertext |
| **SEC-003** | C02 / T0 | Distinct chosen plaintexts with equal declared leakage | Confidentiality experiment documented; test not mistaken for proof |
| **SEC-004** | C03 / T1 | Flip bit, change tag, truncate ciphertext | Auth failure; no unauthenticated plaintext returned |
| **SEC-005** | C03 / T1 | Swap chunk across file/generation/ordinal | Rejected or explicitly quarantined |
| **SEC-006** | C03 / T1 | Mutate index parent, duplicate fields, corrupt canonical encoding | Parse/auth failure; bounded resource use; no panic |
| **SEC-007** | C04 / T1 | Replay older valid snapshot with trusted newer checkpoint | Rollback warning; never label current |
| **SEC-008** | C04 / T1 | Restore old snapshot on fresh device with no trusted checkpoint | Freshness unknown; do not claim detection |
| **SEC-009** | C05 / T1 | Kill app between chunk upload and root commit | Recoverable pending operation; no false acknowledgement |
| **SEC-010** | C05 / T1 | Two offline devices edit same file | Explicit conflict revisions; no silent last-writer-wins |
| **SEC-011** | C05/C07 / T1 | Quota exhausted / network failure / expired token | Fail closed, safe retry; honest local/remote status |
| **SEC-012** | C06/C08 / local | Lock, background snapshot, diagnostic capture | No intentional secrets in logs/preview; no remote-delete claim |
| **SEC-013** | C07 / T1 | Broken backup, interrupted migration, unsupported version | Reject safely or documented recovery; no silent acceptance |
| **DEN-001** | G-SHADOW-0 / T0+T4 | Compare public-only vs public+hidden final state with public key | Register observables/attacker, report distinguishing advantage |
| **DEN-002** | G-SHADOW-1 / T4 | Public-only writes against occupied hidden space | No hidden corruption or unsupported success claim |
| **DEN-003** | G-SPECTER-0 / T2+T4 | Compare historical snapshots/versions across worlds | Report full transcript and classifier results; no 'proof' claim |
| **DEN-004** | G-SPECTER-0 / T3+T4 | Compare complete API traces/timing/account linkage | Report distinguishability and model limitations |
| **DEN-005** | G-RESOURCE-0 / T2/T3 | Idle, sleep, airplane mode, low battery, resize, 2+ devices | Report overhead and broken traffic assumptions |
| **CLAIM-001** | C08 / all | Security/marketing copy review | Every promise maps to claim, evidence and stated adversary |

Suggested fixtures must be **generated synthetically**, with no real passwords or personal data. Record seeds (for the *test harness*, never as production cryptographic entropy), supported platforms and replication instructions.

## 5. Failure semantics and UI contract (future implementation)

The implementation SHOULD use typed machine states distinct from untrusted error messages. UI SHOULD present understandable categories while avoiding side-channel-oracle responses for unauthenticated flows.

| Condition | Internal result | Allowed user message | Prohibited assertion |
|---|---|---|---|
| Wrong passphrase or unauthenticated root | `UnlockUnavailable` | Could not unlock archive | Whether alternate namespace exists |
| Authenticated root, invalid/tampered chunk | `IntegrityFailure` | File could not be verified | Successful decrypt / file safe |
| Unsupported or dangerous envelope | `UnsupportedFormat` | This archive format is not supported | 'Recovered' via permissive parser |
| No trusted freshness checkpoint | `FreshnessUnknown` | Latest version cannot be verified | No rollback occurred |
| Trusted checkpoint ahead of remote | `SuspectedRollback` | Stored version is older than trusted record | Guaranteed attribution to attacker |
| Interrupted upload before commit | `LocalPending` | Saved locally; not yet synced | Synced |
| Concurrent divergent authenticated roots | `ConflictNeedsResolution` | Conflicting revisions need review | One change safely superseded another |
| Remote deletion/rate-limit/quota outage | `RemoteUnavailable` | Remote storage unavailable | Data safely replicated |
| Local lock | `Locked` | Archive locked on this device | Forensically erased or cloud deleted |
| Hidden-mode experimental failure | `ResearchFailure` | Experimental feature unavailable | Hidden data is deniable or safe |

A generic unlock message must not hide distinguishable timing, access pattern, server queries or different caching behavior that reveals the secret branch. This is a future protocol test obligation, not achieved by uniform wording alone.

## 6. Claim-to-evidence register

| Potential user-facing statement | Minimum evidence before allowed | Status now |
|---|---|---|
| 'Files are encrypted on device before cloud upload' | C01/C02/C03 verified end-to-end + implementation review | **NOT ALLOWED YET** |
| 'Tampered file contents are rejected' | C03, SEC-004/005/006 and audit | **NOT ALLOWED YET** |
| 'Cloud provider cannot read plaintext' | Scoped C01/C02 with explicit endpoint and metadata limitations | **NOT ALLOWED YET** |
| 'Hidden space cannot be identified from one snapshot' | Reviewed formalized Shadow model + DEN-001 and independent assessment | **NOT ALLOWED YET** |
| 'Hidden activity is undetectable across cloud history' | Rigorous T2/T3 (and T4 when applicable) construction/proof + DEN-003/004 + independent assessment | **NOT ALLOWED YET** |
| 'Impossible to recover/delete/trace under coercion' | Not a supported product claim | **PROHIBITED** |

Users may see descriptive *research goals* with prominent non-guarantee language, never certified protection labels.

## 7. Acceptance for P1.1 (documentation only)

- [x] Asset/role/boundary inventory and T0–T6 observer definitions documented.
- [x] Proposed Vault requirements C01–C08 mapped to assumptions, falsifiers and test IDs.
- [x] Shadow/Specter experimental games define W0/W1, observable transcript and explicit threat combinations.
- [x] Failure semantics and honest UI messages specified.
- [x] Security claims separated from research claims and from verified implementation status.
- [x] Open questions / review dependencies preserved for P1.2–P1.5 and P6/P7.
- [ ] External review, executable tests, cryptographic proof, implementation: **NOT part of this completed documentation milestone**.

## 8. Open questions handed to P1.2 and later

1. Rust crypto crates/libraries, dependency/update/supply-chain policy, zeroizing memory boundaries.
2. Explicit binary envelope, nonce allocation, file-key wrapping and authenticated root generation model.
3. KDF parameters and minimum password policy after mobile benchmarks; Argon2id's RFC recommendations are candidates.
4. How independent fresh-device restore establishes truth without an external checkpoint.
5. How a public-key-only client safely writes without seeing hidden allocation; Shadow blocker.
6. Exactly which operations the selected cloud adapter exposes in version history/API telemetry.
7. Safe secret-key onboarding/recovery without an observable hidden-slot marker.

## 9. References

- RFC 9106 (Argon2id design/parameter recommendations): https://www.rfc-editor.org/rfc/rfc9106
- RFC 5869 (HKDF): https://www.rfc-editor.org/rfc/rfc5869
- NIST SP 800-38D Appendix D (authenticated encryption does not inherently preclude replay): https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
- DataLair: https://crysp.petsymposium.org/popets/2017/popets-2017-0035.php
- Project baseline: [ADR-0001](decisions/0001-foundation.md)

*This is a future-looking security requirements document, not a claim of current protection.*
