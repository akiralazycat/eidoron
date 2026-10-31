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
- Phase 1 / Threat-model and crypto protocol review — **in progress (P1.1 security target authored; implementation unverified)**
- Application / encryption / sync code — **not implemented**
- Production readiness — **none**

## Documentation index

- [Master plan](docs/00_MASTER_PLAN.md)
- [Threat model and security claims](docs/01_THREAT_MODEL.md)
- [Normative security target (P1.1)](docs/08_SECURITY_TARGET.md)
- [Cryptographic architecture draft](docs/02_CRYPTO_ARCHITECTURE.md)
- [Storage, deniability research and sync](docs/03_STORAGE_SYNC.md)
- [Product and intelligence-inspired UX](docs/04_PRODUCT_UX.md)
- [Implementation phases and acceptance gates](docs/05_IMPLEMENTATION_ROADMAP.md)
- [Progress ledger and AI handoff](docs/06_PROGRESS_HANDOFF.md)
- [Architecture decision record](docs/decisions/0001-foundation.md)
- [Research and validation references](docs/07_RESEARCH_VALIDATION.md)

**Next work unit:** P1.2 — choose Rust cryptography dependencies, FFI and device key lifecycle via ADR-0002. P1.3 will then specify the binary envelope; encryption or hidden-space code MUST wait for P1 security design review.

License: [MIT](LICENSE). An open-source license is not a security certification.
