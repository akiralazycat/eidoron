# Eidoron

**Encrypted by default. Concealed only when proven.**

Eidoron は、端末側で暗号化してからクラウドへ同期する、プライベートなファイル保管・閲覧エンジンの構想です。長期研究テーマとして、単一の暗号化ストレージを異なる鍵で開いたときに異なるファイル空間を提供する **deniable storage（存在の否認可能性を目指すストレージ）** を研究します。

> **安全性に関する重要な注意**: 2026-10-31 現在、これは設計段階です。暗号化、隠しボリューム、クラウド上での否認可能性は未実装・未監査です。パスワードで異なる画面が表示されることは、隠し領域の存在を隠せることを意味しません。重要情報の保管には使用しないでください。

## Design principles

1. **Security before theatricality** — 諜報アーカイブを思わせるUIは魅力だが、実際の安全性を偽装しない。
2. **Local-first and provider-agnostic** — 平文と復号鍵は原則端末外に出さない。ストレージ事業者は信頼しない。
3. **No proprietary primitives** — Argon2id / HKDF-SHA256 / XChaCha20-Poly1305 など、検証された暗号構成要素を採用候補とする。
4. **Deniability is a separate research gate** — 単一時点・複数時点・アクセスログ観測の各脅威を分け、主張は実証可能な範囲に限る。
5. **Mobile-first** — iOS/Androidネイティブ体験を重視し、常時バックグラウンド処理やPC必須の運用を前提としない。
6. **Reproducible decisions** — 判断、進捗、変更理由は docs と Git 履歴に残す。GitHub Actions は必須要件にしない。

## Current status

- Phase 0 / Foundation documentation — **completed (2026-10-31)**
- Phase 1 / Threat-model and crypto protocol review — **P1.1–P1.5 documents and internal review recorded; implementation/independent audit unverified**
- Rust code — **chunk identity checks pass on rustc 1.99.1; vault sessions, sync and deniability are NOT implemented**
- Phase 2 / Rust Vault — **M5.22 compares one chunk's file_id and ordinal with the caller; `status()` is still NotImplemented**
- Production readiness — **none**

## Documentation index

- [Master plan](docs/00_MASTER_PLAN.md)
- [Threat model and security claims](docs/01_THREAT_MODEL.md)
- [Normative security target (P1.1)](docs/08_SECURITY_TARGET.md)
- [Cryptographic architecture draft](docs/02_CRYPTO_ARCHITECTURE.md)
- [Vault envelope format v0 (P1.3 review candidate)](docs/09_ENVELOPE_FORMAT_V0.md)
- [Adversarial test and fuzz plan (P1.4)](docs/10_TEST_AND_FUZZ_PLAN.md)
- [Internal security design review (P1.5)](docs/11_SECURITY_DESIGN_REVIEW.md)
- [Rust implementation plan and verification status (P2)](docs/12_P2_IMPLEMENTATION.md)
- [Development plan after compiler verification](docs/PLAN.md)
- [Storage, deniability research and sync](docs/03_STORAGE_SYNC.md)
- [Product and intelligence-inspired UX](docs/04_PRODUCT_UX.md)
- [Implementation phases and acceptance gates](docs/05_IMPLEMENTATION_ROADMAP.md)
- [Progress ledger and AI handoff](docs/06_PROGRESS_HANDOFF.md)
- [Foundation architecture decision](docs/decisions/0001-foundation.md)
- [Crypto dependencies, mobile FFI and device keys — ADR-0002](docs/decisions/0002-crypto-dependencies-ffi.md)
- [Envelope and key hierarchy decision — ADR-0003](docs/decisions/0003-envelope-and-key-hierarchy.md)
- [P1.5 scope and security restrictions — ADR-0004](docs/decisions/0004-security-review-scope-and-safety.md)
- [Research and validation references](docs/07_RESEARCH_VALIDATION.md)

**Next work unit:** M6 item 23 — write opaque 32-byte ids into a temporary directory, allowing an identical retry and rejecting a different payload. No crash-safety claim. Task order: [docs/PLAN.md](docs/PLAN.md).

License: [MIT](LICENSE). An open-source license is not a security certification.

## P2.1 source safety warning

The `crates/` tree is a **synthetic-only nonproduction scaffold**, not a usable encrypted vault. `eidoron-crypto` fails closed with `NotImplemented`; `eidoron-format` inspects **untrusted** public byte shapes only. Never import real files or secrets. No cloud provider, operating-system secure keystore integration or hidden container is included.
