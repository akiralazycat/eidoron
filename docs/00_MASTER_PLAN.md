# Eidoron — Master Plan

- Created: 2026-10-31 JST
- Last updated: 2026-10-31 JST
- Document status: baseline v0.1 (planning, subject to security review)
- Source of truth for completion: [06_PROGRESS_HANDOFF.md](06_PROGRESS_HANDOFF.md)
- Normative security target: [08_SECURITY_TARGET.md](08_SECURITY_TARGET.md) — requirements, **not verified claims**
- Change tracking: Git history; material changes require an ADR and roadmap/progress synchronization.

## 1. Mission

Build a polished, local-first, cross-platform encrypted archive for cloud storage. Pursue a second, research-driven capability: multiple password-defined views over a common encrypted pool, with defensible and independently evaluated *plausible deniability* against specifically defined observers.

We are NOT building a guaranteed 'undetectable' or 'forensic-proof' application. A hidden view, a disguised login, or encrypted random-looking data does not establish deniability.

## 2. Product pillars

1. **Eidoron Vault (ship candidate):** encrypted file vault, authenticated metadata, safe incremental sync, offline read/write, recovery and mobile viewer.
2. **Eidoron Shadow (research):** independent password-defined namespaces in one pool; no obvious hidden header; must prove non-corruption and disclosure properties before use.
3. **Eidoron Specter (advanced research):** snapshot/trace-resistant updates, potentially using write-only ORAM and cover operations; substantial overhead accepted only if measured and worthwhile.
4. **Archive experience:** restrained intelligence-file aesthetics (sealed/unsealed, dossier, drop, exposure radar). No decorative 'security score' that misrepresents guarantees.

These are stages, not simultaneously guaranteed paid tiers. Shadow and Specter MUST be disabled or labeled experimental until gates pass.

## 3. Audience and use cases

- Individuals protecting documents/photos in Dropbox, iCloud Drive, Google Drive or object stores.
- Journalists/researchers holding sensitive but lawful material.
- Advanced users who need a clear threat model and inspectable implementation.
- Mobile-primary users who may never own a desktop.

Avoid product claims that encourage users to rely on the software under physical coercion, malware, seizure or state-level surveillance beyond validated assumptions.

## 4. Scope

### Included for v1 candidate
- Client-side encryption/decryption; authenticated file chunks and metadata.
- Plain-language local threat-model setup and honest leakage report.
- Vault create/unlock/lock; import/export/view; recovery and backups.
- Incremental cloud sync via **one first-class adapter** (choose using prototype evidence), transport-agnostic Rust interface.
- Integrity and rollback awareness with clearly scoped guarantees.
- iOS native first, Android native second; Rust portable core.
- Optional macOS/Windows frontends later; no server or login required for local-first vault.
- Versioned format, migration and deterministic interoperability vectors.

### Excluded until research gates pass
- Advertising hidden-volume or multi-snapshot deniability.
- Automatic access from every cloud provider on day one.
- Self-destruction claims, guaranteed remote deletion or preventing screenshots/OS forensics.
- Unattested key extraction protections, zero forensic traces, undetectable activity, 'military-grade' labels.
- Custom cryptographic primitives or unreviewed file-format changes.

## 5. Proposed logical architecture

Native UI (Swift / Kotlin)
→ thin native FFI bindings and device secure storage adapters
→ Rust workspace: core-crypto / format / vault / metadata / sync / provider-api / leakage-lab
→ providers: local file, one initial cloud adapter, later S3-compatible/WebDAV/File Provider where actually supported.

Independence boundaries:
- `crypto`: no network or UI dependencies.
- `format`: canonical serialization, versioning, domain-separated AAD.
- `vault`: authenticated virtual file tree, chunk CRUD, capability policy.
- `sync`: immutable objects or generation-aware commits, retries, reconciliation.
- `research`: hidden-space allocation/ORAM simulations completely separated from production-ready Vault.

Server stores ciphertext, generic object IDs and necessary transport metadata; provider still observes network access, timing and quota/volume. No product-hosted backend required for baseline.

## 6. Product invariants

- Wrong password and corrupted ciphertext never return unverified plaintext.
- Nonce never repeats with the same AEAD key; immutable chunks or new random nonce on each re-encryption.
- Encrypted metadata binds object identity, logical version, content type and parent relationships; swapping/replay is detectable to the extent supported by trusted state.
- Cross-device convergence must never silently discard edits.
- A local lock never claims to erase OS/cloud copies.
- Non-secret metadata exposure is documented explicitly.
- All sensitive work is testable offline before cloud integration.
- A public Git repository NEVER contains secrets, real vault exports, personal keys or real sensitive fixtures.

## 7. Release policy

Gate A: security specification reviewed and stable.
Gate B: crypto/format KAT, property tests, fuzzing and cross-platform test vectors pass.
Gate C: sync power-loss and conflict tests, rollback handling and recovery tested.
Gate D: native privacy review + external assessment for relevant attack surface.
Gate E: public claims exactly match demonstrated capabilities.
Shadow and Specter have *additional* mandatory, separate scientific evaluation gates; failing a gate means do not ship that promise.

## 8. Risks and decision priorities

Highest: strong deniability may be incompatible with cheap transparent cloud sync, unbounded growth, offline writes and simultaneous devices. Treat as an open research question, not an engineering detail.
Next: provider metadata/history and device forensic artifacts; cloud version retention and account logs; mobile background execution limits.
Then: safe, usable recovery and human error; memory, battery and storage costs.

Work from risk reduction to code volume. Revisit architecture after empirical measurements. See roadmap and ADR.
