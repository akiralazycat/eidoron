# ADR-0002 — Rust cryptography dependencies, mobile FFI and device key lifecycle

- Decision date: **2026-10-31 JST**
- Status: **Accepted as a design baseline; implementation and security review pending**
- Scope: **P1.2 only — documentation / dependency decision; no code committed**
- Supersedes: none; extends [ADR-0001](0001-foundation.md)
- Normative security targets: [08_SECURITY_TARGET.md](../08_SECURITY_TARGET.md)
- Next: P1.3 format specification; P1.4 adversarial test details; P1.5 security review

## 1. Decision summary

Use **RustCrypto-family pure-Rust primitives** as the preferred implementation of the *Vault* cryptographic core, with **Mozilla UniFFI** as the first candidate for generating the iOS Swift and Android Kotlin bindings. Keep native platform key storage behind explicit adapters; do **not** assume Secure Enclave or Android StrongBox runs XChaCha20-Poly1305 natively.

Selected **candidates**, subject to version pinning, API proof-of-concept, reviews and benchmarks:

| Purpose | Preferred crate / mechanism | Decision rationale | Conditions / caveats |
|---|---|---|---|
| File and index AEAD | RustCrypto `chacha20poly1305` (`XChaCha20Poly1305`) | Extended 192-bit nonce and vetted ecosystem | Need protocol-level uniqueness, generation binding, length constraints; historical audit is not a project audit |
| Password-to-raw-key derivation | RustCrypto `argon2` (Argon2id) | Memory-hard KDF with explicit parameters | Use raw output API for key material, NOT a persisted password verifier; benchmark / enforce resource upper bounds |
| Context-separated subkeys | RustCrypto `hkdf` + `sha2` (HKDF-SHA256) | Standard, explicit domain separation | Versioned `info`, purpose and context defined in P1.3 |
| Secret values | `secrecy` and `zeroize` | Explicit access and best-effort memory clearing | No promise all copies, GC buffers, registers, app-swap, snapshots or runtime bridges are wiped |
| OS randomness | `getrandom` / OS CSPRNG and compatible `rand_core` interfaces | Entropy supplied by OS | Fail closed; pin chosen APIs/versions; never seed production RNG with test fixtures |
| Swift and Kotlin FFI | Mozilla `uniffi` | Widely used generated native bindings | Generated bindings may copy passphrases/plaintext; FFI panic/error, lifecycle, packaging tests essential |
| Apple device key wrapper | Keychain, optionally Secure Enclave-generated P-256 private key | Device access control and nonexportable key usage | No raw arbitrary imported XChaCha20 key in Secure Enclave |
| Android device key wrapper | Android Keystore AES-GCM or suitable asymmetric wrapping, StrongBox when available | Nonexportable device-bound key operation and auth policy | Actual hardware backing must be queried; StrongBox optional; not identical to Rust vault encryption |

These are **not pinned dependency versions**, implementation results or user-facing security guarantees. At P2 start, pin exact compatible releases and associated checksums in `Cargo.lock`, record source links and audit findings; never put a fictitious version in a manifest.

## 2. Alternatives considered

### Primitive implementation: RustCrypto vs libsodium FFI vs custom algorithms

**RustCrypto (preferred):** fewer external native library distributions; portable Rust core; reasonably inspectable ecosystem and straightforward use from one Rust boundary. Risks include semver/API churn, multiple cryptographic crate dependencies, compiler/platform behavior and Rust dependency advisories. The `chacha20poly1305` project's published audit history does NOT audit Eidoron's use of it, current dependency graph or our storage protocol.

**libsodium FFI (fallback to investigate):** mature cross-language C implementation, useful reference/KAT and `secretstream_xchacha20poly1305` for sequential stream designs; disadvantage is dual native build/packaging, ABI and cross-platform binary supply chain. Do not combine two independently versioned streaming formats without explicit format negotiation. A single RustCrypto/XChaCha implementation is sufficient to plan P1.3.

**Handwritten cipher / password KDF / ORAM:** rejected. The project's novelty belongs in the system protocol, and deniability is a separate, reviewed research track.

**AES-256-GCM-SIV:** viable future alternative for specific nonce-misuse models, but not chosen here. Adding competing suites increases format compatibility and test surface. FIPS compliance is **not claimed**.

### Bindings: UniFFI vs handwritten C ABI

**UniFFI (preferred):** generates Swift/Kotlin APIs from a shared Rust interface and avoids manually maintaining two language projections. Limitation: generated bindings do not themselves compile/distribute a working XCFramework or Android AAR; cross-compilation/signing/packaging are separate engineering work. Version changes can change generated APIs.

**Manual C ABI/cbindgen (fallback):** more explicit ABI and minimal generator dependency; higher risk around ownership, cancellation, allocator compatibility, UTF-8, exceptions and arrays. Use only if UniFFI cannot satisfy a measured requirement, and record a follow-up ADR.

**Direct platform-native crypto for every file:** rejected as default because algorithms, file format and interoperability could drift across platforms. Device key operations remain native.

## 3. Key architecture and lifecycle boundaries

### A. Long-lived vault / file keys

1. A human passphrase is collected in the trusted **native** interface, then temporarily handed into Rust for Argon2id. This crossing entails unavoidable managed-memory/FFI copies; record and minimize them. Do not claim zero-copy secrets across Swift/Kotlin/JVM/Rust.
2. Argon2id produces purpose-bounded raw key material from passphrase, salt, *explicitly versioned KDF parameters*. HKDF derives distinct wrapping, metadata, and other required keys after P1.3 specifies exact derivation/context. The eventual protocol MUST specify raw-password UTF-8 handling, normalization policy and length caps.
3. A vault data-encryption key (or hierarchy of file keys) MUST have a reviewed creation, wrap, rotate and recovery path. Choice of random per-file keys vs derived per-file keys is deferred to P1.3.
4. Never persist plaintext master keys, a reusable passphrase-equivalent key, sensitive names or a vault plaintext index in cloud, analytics, crash logs or default OS backup.
5. During unlock, retain session keys in Rust as non-cloneable, non-debuggable secret types; attempts to clear owned memory on lock/drop are **best effort**. No on-disk decrypted preview cache unless a specifically reviewed design permits it.
6. Password reset is impossible without a valid recovery mechanism; never pretend local biometric credentials replace the independent passphrase/recovery path.

### B. Apple Keychain / Secure Enclave

- Use **Keychain** to protect the optional **device-scoped convenience-unlock wrapping material** with access control; candidate accessibility `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` for foreground-only access. If passcode-required semantics are necessary, evaluate `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`; verify device/user recovery implications.
- Biometric prompt controls access to device-held wrapping material only; it does **not** authenticate remote storage and cannot magically make ciphertext deniable.
- Secure Enclave can provide nonexportable hardware-generated **P-256** private key operations (e.g., agreement to derive device-side wrapping material), **not** arbitrary raw import of an existing symmetric XChaCha20 content key; do not confuse Keychain and Secure Enclave.
- Treat uninstall, restore to different device, biometric enrollment changes, passcode reset and access-control invalidation as explicit failures requiring password/recovery, not data loss or 'invalid ciphertext' errors.
- The iOS application must not persist a secret realm marker in Keychain that would itself disclose the existence of Shadow. For Vault, prefer to ship **password unlock first**, defer convenience biometrics until privacy review.

### C. Android Keystore / StrongBox

- Use **Android Keystore** generated, nonexportable device key for an **optional** device-only wrapper (e.g., AES-GCM) around separate vault-unlock material; do not equate it with XChaCha file encryption.
- Query device/key security level (TEE vs StrongBox); hardware backing and StrongBox are not universal and not guaranteed for every algorithm/operation.
- Restrict permitted operations and authentication using platform APIs; model key invalidation due to lock-screen removal/reset or biometric changes, with documented fallback to passphrase recovery.
- Prevent automatic Android backup of app-owned wrapping material and decrypted temporary files except as explicitly reviewed; do not assume app/data restore also restores Keystore material.
- Shadow/hidden vault **must not** opportunistically create detectable second realm aliases, biometrics labels, notifications, tokens or backup artifacts until the T4 deniability protocol has been reviewed.

### D. Sessions, recovery and crash effects

- The base product uses passphrase as its standard portable unlock path; optional platform biometrics may only supplement it.
- A keychain/keystore credential can be lost during reinstall, migration or hardware replacement; preservation requires **separate, explicit** recovery (to be specified in P1.3/P3).
- App lock discards reachable Rust session handles and attempts zeroization; purge UI previews and revoke in-app references. It cannot guarantee removal of all historical OS copies, memory dumps, exported files or cloud versions.
- The key hierarchy must allow restoration after device loss from valid user recovery material without leaving an observable universal-bypass key for hidden spaces.

## 4. FFI and Rust interface design contract

**UniFFI should expose capability-oriented calls, not raw cryptographic gadgets.** A native app requests high-level verified operations; Rust owns cryptography, authenticated indexing and sensitive session state.

Suggested *design-level* API shapes (illustrative, NOT implementation):
- `unlock(passphrase, archive_locator) -> SessionHandle | UnlockUnavailable`
- `read_verified(session, file_id, bounded_range) -> VerifiedBytes`
- `import_and_encrypt(session, input_stream_or_bounded_chunks) -> PendingCommit`
- `seal_and_lock(session) -> LockResult`
- `get_sync_state(session) -> LocalPending | Synced | Conflict | ...`

Boundary rules:
1. No `get_master_key()`, exported `SessionKey`, logging of passphrase or arbitrary unchecked decrypt API across FFI.
2. Secret keys remain private Rust types; handles have epoch/generation, expiration and explicit close. Enforce access authorization per call.
3. Inbound file bytes and passwords are untrusted: strict maximum lengths, allocation guards, explicit UTF-8 policy, error redaction.
4. Native and Rust errors are typed; no panics crossing FFI; catch at a well-defined boundary where practical without hiding critical corruption errors.
5. Evaluate async cancellation, unexpected client death, backpressure and concurrency of session calls. No exposed half-verified plaintext.
6. Do not return plaintext from a chunk before AEAD authentication. Limit buffer size and temporary file retention; FFI copies may occur.
7. Verify bindings compile against **real Swift/iOS and Kotlin/Android** toolchains, including arm64 and release profiles. On-device tests required, not only host unit tests.
8. Generated binaries, Swift package/XCFramework, Android AAR/JNI libraries and signature/build provenance require their **own release procedure**; UniFFI is a code generator, not a universal build system.

## 5. Dependency integrity and release supply chain

### Policy (before shipping)
- `Cargo.lock` committed for application/workspace reproducibility. Use exact releases/feature sets, pinned Rust toolchain and supported target list; record MSRV and reproducible build commands.
- Run **cargo audit** (RustSec Advisory DB), **cargo deny check advisories bans licenses sources**, dependency tree inspections, and check unmaintained/yanked crates. Do not auto-ignore alerts without dated written risk acceptance.
- Generate an SBOM for release artifacts (Cargo/native deps). Review licenses for MIT open-source distribution and any future app packaging.
- Prefer minimal dependency graph and no untrusted Git dependencies; justify `unsafe`, `build.rs`, C toolchains and transitive native code.
- Freeze and review any crypto dependency upgrade or feature change; keep protocol/format stable, add KAT/regression vectors and multi-platform round-trip checks.
- Use documented vulnerability handling path and security contact before publicly inviting vulnerability reports. Do not put test passwords/keys, signing credentials or private app bundles in public repo.
- **No GitHub Actions required**: provide locally runnable and optionally hosted commands/checklists. If independent build infrastructure is used, results must attach to commits/releases.

### Verification artifacts (future)
`Cargo.lock`, dependency graph, advisory report dated at release, license/source policy output, cryptographic known-answer tests, fuzz outputs, mobile key invalidation/recovery observations, binary provenance, external audit and reproducible cross-device test vectors.

Never label a crate 'safe' merely because it is popular or has an old audit. Current state has **no implemented dependencies to audit**.

## 6. Parameter choices and unresolved security questions

| Topic | Candidate or criterion | Status / next owner |
|---|---|---|
| Argon2id | Start benchmark with RFC 9106's memory-constrained profile: 64 MiB, t=3, p=4; evaluate performance/memory contention on representative devices | Candidate only; P1.3 chooses encoded bounds, P2 measures p50/p95 and memory |
| KDF salt | Random ≥128 bits, versioned public metadata where permitted | P1.3: format / namespace discovery / Shadow leakage impact |
| XChaCha nonce | 192-bit fresh OS-random value per encryption under a key; never force reuse on retry | P1.3: nonce envelope, failure policy, authenticated binding |
| Chunk sizes | Compare 256 KiB and 1 MiB, measure memory, bandwidth, streaming UI | P1.3/P2: not fixed |
| Domain separation | Explicit versioned context strings and key-purpose IDs; authenticate logical references | P1.3: exact binary vectors |
| Password text | Explicit UTF-8 normalization, input length and fallback for user error | P1.3 |
| Key backup | Portable, user-controlled recovery without hardware-key dependency | P1.3/P3 |
| Confidentiality after unlocked device seizure | Not promised | T5 excluded |
| Hidden multi-password unlock | No design accepted from this ADR | P6 blocked by T2–T4 and collision-free allocation obligations |

An Argon2id raw-key derivation needs a *raw* KDF API; a stored PHC password-verifier string is not a vault encryption key. Whether the vault root wraps random master key material or directly derives a hierarchy must be justified in P1.3, especially when changing passwords.

## 7. Acceptance and review record (P1.2 documentation milestone)

- [x] Preferred and fallback primitive/binding approaches documented.
- [x] Rust/native trust boundaries, device wrapper vs content key responsibilities documented.
- [x] iOS Keychain/Secure Enclave and Android Keystore/StrongBox limitations documented.
- [x] Key creation, unlock, locking, lost device and recovery requirements identified.
- [x] Secret-copying, error/FFI failures and native packaging risks documented.
- [x] Dependency auditing/locking/security-response policy documented.
- [x] Explicit next design work and benchmark criteria assigned.
- [ ] Crate/API source code integrated — **not done**.
- [ ] Versions pinned and advisory reports generated — **not done**.
- [ ] On-device performance/FFI tests — **not done**.
- [ ] Protocol/implementation security audit — **not done**.
- [ ] P1.3 envelope, P1.4 tests, P1.5 review — **not done**.

Completing this ADR means the **design decision is recorded**, not that an implementation is certified or secure.

## 8. References consulted (2026-10-31)

- RustCrypto XChaCha20-Poly1305: https://docs.rs/chacha20poly1305/latest/chacha20poly1305/
- RustCrypto Argon2: https://docs.rs/argon2/latest/argon2/
- RustCrypto HKDF: https://docs.rs/hkdf/latest/hkdf/
- RustCrypto secrecy: https://docs.rs/secrecy/latest/secrecy/
- RustCrypto zeroize: https://docs.rs/zeroize/latest/zeroize/
- UniFFI user guide: https://mozilla.github.io/uniffi-rs/
- UniFFI Swift bindings: https://mozilla.github.io/uniffi-rs/latest/bindings.html
- Apple Secure Enclave key protection: https://developer.apple.com/documentation/Security/protecting-keys-with-the-secure-enclave
- Apple ThisDeviceOnly keychain: https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly
- Android Keystore: https://developer.android.com/privacy-and-security/keystore
- Android authentication invalidation: https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder
- cargo-deny: https://github.com/EmbarkStudios/cargo-deny
- RustSec advisories: https://rustsec.org/
- RFC 9106 (Argon2): https://www.rfc-editor.org/rfc/rfc9106
- RFC 5869 (HKDF): https://www.rfc-editor.org/rfc/rfc5869
