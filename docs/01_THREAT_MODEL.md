# Threat Model, Leakage and Claim Discipline

- Created / updated: 2026-10-31 JST
- Status: v0.1 **draft; not externally reviewed**
- Normative follow-on (P1.1): [08_SECURITY_TARGET.md](08_SECURITY_TARGET.md). For exact prospective MUST/SHOULD requirements, experiments, failure semantics and test IDs, refer to that document. Both are **unverified designs**, not implemented protection.

## 1. Assets and trust boundaries

Protected assets: file contents, filenames, directory graph, plaintext previews, encryption keys, file-integrity history and (aspirationally) the existence/use of a hidden namespace.

Trust: client OS, trusted crypto implementation, app distribution, entropy and device-local credential store **within defined limits**. Do not assume cloud provider, internet route, backup/snapshot infrastructure, or other logged-in devices are honest. If the device itself is compromised while unlocked, most guarantees fail.

Boundaries: user↔device↔Rust engine↔provider adapter↔remote storage. Also OS file providers, preview engines, app backups, logs, thumbnails, clipboard and telemetry.

## 2. Adversaries (distinct; never silently conflate)

| ID | Observer / capability | Target claim |
|---|---|---|
| T0 | Sees one offline ciphertext snapshot only | Confidentiality/integrity; metadata leakage recorded |
| T1 | Controls cloud storage, can alter/delete/reorder objects | Authenticated data, detect tampering; availability not guaranteed |
| T2 | Retains historical snapshots and object/version metadata | Study multi-snapshot deniability; NOT in Vault guarantee |
| T3 | Also sees request timing, object IDs, IP/device and traffic volume | Study trace resistance; cannot guarantee network anonymity |
| T4 | Gets the *ordinary* password and associated view | Research hidden-space non-disclosure and non-corruption |
| T5 | Has unlocked device, malware, memory dump or OS forensic acquisition | Out of scope for strong protection |
| T6 | Compels user to unlock or disclose credentials | No guarantee against coercion or compelled disclosure |

Threats can combine (especially T2+T3+T4). Define exactly which combinations each experiment tests.

## 3. Desired security properties

V1 Vault has candidate confidentiality, integrity, domain-separation, nonce-safety, best-effort key erasure, recovery, fail-closed and conflict-safety requirements. These are formalized as **prospective** C01–C08 in the security target; **none has been implemented, proven or tested yet**.

**Deniability requirement (RESEARCH, not delivered):** within a stated observation model, an observer cannot distinguish a run with hidden writes from a permitted run with only ordinary writes except negligible (or bounded and measured) advantage. Include *initialization, growth, repair, sync and offline resumption* in traces, not just the final bytes. Use appropriate indistinguishability experiments, not aesthetic inference.

If ordinary credentials are given to the adversary, the public-view explanation must remain consistent with the observed storage and updates. Consider false negatives and false positives under repeated observation.

## 4. Leakage inventory

| Surface | Vault | Shadow/Specter research |
|---|---|---|
| Cloud account and bucket/folder existence | May leak | Likely still leaks |
| Timing, source IP, API request count | Leaks | Requires separate traffic countermeasure |
| Total byte count and growth | Leaks unless padded | Fixed budget/cover operations investigated |
| Object counts/IDs and update chronology | Leaks to provider | Oblivious / fixed-pattern design investigated |
| Password attempts / UI behavior on seized device | May leak | Cannot assume hidden |
| Device caches, thumbnails, share sheets | Can leak | App hygiene helps, does not eliminate |
| Server-side version retention, logs, backups | Outside deletion control | Must enter observation model |
| Availability / remote deletion / rollback | Server can disrupt | Trusted checkpoints or independent witnesses needed |

Do not call an archive 'undetectable', 'trace-free' or 'forensic-proof'; avoid green check marks for untested properties.

## 5. Fundamental design conflict to solve

How can an ordinary-key-only client allocate space or rotate storage safely without overwriting hidden data while not learning, exposing or marking hidden allocations? A reserved partition is a clue; a global plaintext allocation map is a clue; a hidden-only metadata marker is a clue. This is a central unsolved *design and proof obligation* for Shadow.

Concurrently: independent offline devices, cloud object version histories, predictable access schedules and data growth can break plausible deniability even if current bytes look random.

## 6. Test matrix / exit criteria

Canonical future test IDs are SEC-001–013, DEN-001–005 and CLAIM-001 in [08_SECURITY_TARGET.md](08_SECURITY_TARGET.md). The examples below are proposed—not executed.

- T0: known-answer vectors, wrong-key rejection, ciphertext indistinguishability sanity checks, malformed-input fuzzing.
- T1: swap/truncate/replay/delete/duplicate objects; encrypted index and parent-child binding; no silent data corruption.
- T2: reproducible paired experiment (ordinary-only vs hidden activity), with a classifier observing all snapshots and provider metadata. Pre-register observations and comparison workloads.
- T3: same paired experiment including request traces and device/session correlations; test actual provider behavior.
- T4: expose ordinary password and public metadata; verify hidden non-corruption, public consistency and inability to trivially identify hidden pool locations.
- T5/T6: document failure modes and do not market coverage.
- Data recovery: backup restore, lost device, concurrent write, interrupted key rotation, wrong sync state.

A successful toy/demo run does not prove cryptographic deniability. Independent review and a precise model are necessary before shipping Shadow/Specter claims.

## 7. Responsible design

The tool supports legitimate privacy. No feature should falsely promise evidence destruction, evasion of legal process or safety under coercion. Preserve user agency, prevent lockout, and keep secure defaults understandable.
