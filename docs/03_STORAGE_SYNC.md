# Storage, Synchronization and Deniability Research

- Created / updated: 2026-10-31 JST
- Status: alternatives and research plan, not a working design

## 1. Baseline Vault storage

Local-first encrypted content-addressed or random-ID object store; encrypted file tree, chunks and generation commits. File-by-file sync instead of one monolithic disk image, with reliable interruption recovery. Remote storage must never receive plaintext file contents or user passphrases.

Interfaces:
- BlobStore: put/get/list/delete with strict length limits, pagination and conditional writes if supported.
- CommitStore: opaque generation root, version comparison, integrity checks and conflict retry.
- LocalCache: encryption at rest, explicit eviction and provenance.
- ProviderCapability: whether versioning/ETag/atomic rename/listing/locking is available.

The shipping storage target is the local sync folder only. The user runs Google Drive, Dropbox, or another folder sync outside the app. The app reads and writes that directory and does not call a vendor API. S3-compatible conditional writes remain an optional later backend described in [13_S3_CONDITIONAL_HEAD.md](13_S3_CONDITIONAL_HEAD.md). Do not promise that the sync tool's conflict copies are a merge.

## 2. Sync protocol invariants

1. Write encrypted immutable chunks before publishing a new root/commit pointer.
2. Verify locally and remotely observed object generation where possible.
3. Use optimistic version check and explicit merge/conflict UI; no last-writer-wins data loss.
4. Retry idempotently after app kill, offline switch, cancellation and partial uploads.
5. Detect unexpected prior-generation replay where local trusted checkpoint is available.
6. Encrypt names, notes and directory relationships; avoid leaking names in logs and blob keys.
7. Garbage collection must not erase chunks still referenced by another device/commit. Provider retains historical versions beyond app control.

Conflict policy: either provable non-conflicting merge or create user-visible conflicting revisions; never choose arbitrarily for secret content. Maintain encrypted recovery points with documented retention.

## 3. Shadow alternative hypotheses (research)

A: independent encrypted namespace files in the same folder — easy but exposes separate object counts/update history; **NOT deniable**.
B: common padded random-looking cell pool, private password-derived locator/index and hidden slots — promising prototype but does NOT solve multi-snapshot visibility, safe public-only writes or capacity/expansion.
C: write-only ORAM or related deniable-storage construction — evaluate published constructions with full remote snapshot + API trace semantics; cost in requests/bandwidth/latency likely significant.

**Critical unresolved invariant:** ordinary-only clients must be able to write safely without hidden allocation knowledge AND without disclosing hidden allocations. Naive hidden indexes, reserved blocks, padding and ORAM alone do not establish this.

## 4. Research experiment

For each candidate:
1. Fix attacker observations: final objects, successive snapshots, API operation metadata, credentials held, endpoint timing.
2. Generate paired workloads: baseline public-only, public+hidden with matched public operations and storage budget.
3. Include initialization, resize, key change, backup, merge, crash recovery, GC, multi-device and offline phases.
4. Collect provider-visible traces from a local cloud emulator; later repeat on a real provider with its version retention enabled.
5. Measure a blinded attacker's ability to classify traces; compare with pre-registered null/control experiments.
6. Formally review assumptions and seek external cryptography review. **Classifier scores alone are not a security proof**.

## 5. Cover traffic and mobile constraints

A fixed-rate traffic schedule may hide activity only within the modeled observation window. It consumes data/battery, requires continuing cover operations even when secret data is not used, and mobile OS background execution is not guaranteed. Model sleep/offline/dead battery as adversarially visible events; never claim universal indistinguishability.

A paid cloud's request billing and version history can defeat naive cover writes. Quantify overhead in requests per file edit, bytes/day idle, battery/day, time to unlock, and chance of corruption at each phase.

## 6. Data loss and disaster recovery

Design backup and restore *before* user trials. Lost phone, ordinary passphrase available but hidden credentials lost, malicious remote rollback, duplicate-device restore, interrupted key rotation, quota exhaustion, and hidden sector overwrite must all have explicit outcomes. If a safe outcome cannot be demonstrated, Shadow is not release-ready.
