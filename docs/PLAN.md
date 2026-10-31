# Eidoron 開発計画

- 作成: **2026-10-31**
- 最終更新: **2026-10-31（P2.2 M2 鍵スケジュール）**
- 進捗の正本: [06_PROGRESS_HANDOFF.md](06_PROGRESS_HANDOFF.md)
- 検証記録: [12_P2_IMPLEMENTATION.md](12_P2_IMPLEMENTATION.md)
- この文書は作業順の計画である。暗号化の正しさ、監査、本番利用の許可ではない。

## 進捗

| 項目 | 状態 |
|---|---|
| M1.1 依存のピン留め | 完了。`argon2` 0.6.0、`hkdf` 0.13.0、`sha2` 0.11.1、`chacha20poly1305` 0.11.0、`zeroize` 1.9.1。UniFFI と `secrecy` は未導入 |
| M1.2 RFC 9106 Argon2id | 完了。§5.3 の 32 バイトタグと一致 |
| M1.3 RFC 5869 HKDF-SHA-256 | 完了。付録 A.1 テストケース 1 の PRK と OKM が一致 |
| M1.4 XChaCha20-Poly1305 | 完了。draft-irtf-cfrg-xchacha-03 付録 A.3.1 の暗号文とタグが一致 |
| M1.5 `encrypt_authenticated` | 完了（API は閉じたまま）。3 本の既知回答が通ったあとも `NotImplemented` |
| M3.10–14 公開バイトの拒否 | 完了。ヘッダ長、版、スイート、flags、KDF 識別子、Argon2 境界、オブジェクト長、HEAD 長 |
| M2.6–9 鍵スケジュール | 完了。合成定数の `RawPwdKey` / `WrapKey` / `ObjectKey`。期待バイトは Python オラクル。`encrypt_authenticated` は `NotImplemented` |
| M4 オブジェクト AEAD 以降 | 未着手。次の 1 手 |

## 1. 何を作っているか

Eidoron は、ファイルを端末側で暗号化してからクラウドへ置く、プライベートな保管・閲覧エンジンの構想である。出荷候補は **Vault**（存在が見えてよい暗号化アーカイブ）。**Shadow**（パスワードごとに別のファイル空間を見せる研究）と **Specter**（スナップショットやアクセス痕跡への耐性の研究）は、Vault の完成を待たせない別ゲートである。v0 のヘッダは形式が識別できるので、否認可能性の証拠にはならない。

2026-10-31 時点でリポジトリにあるのは、設計文書と、暗号を意図的に実装していない Rust ワークスペースだけである。

| クレート | 今あるもの |
|---|---|
| `eidoron-crypto` | 既知回答テストと v0 鍵スケジュール。`encrypt_authenticated` は常に `NotImplemented` |
| `eidoron-format` | 非信頼な公開バイト列の長さ・magic・版・スイート・Argon2 資源上限だけを見る |
| `eidoron-provider-local` | プロセス内の `HashMap`。同じ ID への異なるバイトは拒否し、同一バイトの再送だけを許す |
| `eidoron-vault` | インポートは `NotImplemented`。ストアの件数と上限定数を返すだけ |
| `eidoron-test-vectors` | 非信頼な形のフィクスチャと、独立計算した鍵スケジュール定数 |

外部クレートは M1 でピン留めした 5 つとその推移的依存だけである。平文のファイル、クラウド、復旧、生体認証、隠し領域は無い。

## 2. 現在地

| 段階 | 状態 |
|---|---|
| P0 計画と ADR-0001 | 完了（文書） |
| P1.1 セキュリティ目標 | 完了（文書）。C01–C08 は未検証 |
| P1.2 依存と FFI（ADR-0002） | 完了（文書）。RustCrypto / UniFFI は候補であり、依存関係には入っていない |
| P1.3 封筒形式 v0 と ADR-0003 | 完了（文書）。136 バイトヘッダ、88 バイトオブジェクト接頭辞、66 バイト HEAD |
| P1.4 敵対的テスト計画 | 完了（文書）。VEC / PAR / CBOR / GRAPH / SYNC は未実行 |
| P1.5 内部レビューと ADR-0004 | 完了（文書）。合成データ・ローカル・単一書き込みの試作だけが条件付きで許可。外部監査は未了 |
| P2.1 ワークスペース | Rust 1.99.1 で fmt / test / clippy を通過 |
| P2.2 プリミティブと鍵スケジュール | M1 と M2 完了。オブジェクトの AEAD API は未実装 |
| 永続化、同期、各 OS、Shadow / Specter | 未着手 |

P2.1 のテスト 10 件が確認しているのは、スタブが失敗して閉じること、公開バイトの形が仕様の長さと一致すること、メモリストアが上書きを拒むこと、である。

## 3. コンパイラで止まっていた原因と、今回直したこと

P2.1 は `cargo` も `rustc` も無い環境で書かれ、PR #7 はビルド未検証のまま main に入った。進捗表の次作業 P2.1-V は、ピン留めした Rust 1.99.1 で次を実行するまでブロックだった。

1. `cargo generate-lockfile --offline`
2. `cargo fmt --all -- --check`
3. `cargo test --workspace --locked --offline`
4. `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`

Rust 1.99.1 がある環境で同じコマンドを実行した。

- コンパイラはソースを受理した。型エラー、edition 2024 の拒否、依存解決の失敗は出ていない。修正前の `cargo test --workspace --locked --offline` も 10 件成功、clippy も警告なしだった。
- 検証ゲートを落としていたのは `cargo fmt --all -- --check`（exit 1）である。rustfmt 1.10.0（toolchain 1.99.1、`58cf8f9c3`、2026-10-13）は次の整形を要求した。意味の変更は無い。
  - `crates/provider-local/src/lib.rs` と `crates/vault/src/lib.rs` の長い `assert_eq!` を折り返す。
  - `crates/test-vectors/src/lib.rs` の `use` を識別子順にする（`HEAD_LEN` を `HEADER_LEN` より前、`ShapeError` を関数名より前）。
- `Cargo.lock` は手書きの注釈付きブートストラップだった。注釈を残したまま `cargo generate-lockfile --offline` を掛けると、Cargo は自動生成ヘッダを先頭に足すだけで、手書きコメントが残る。ロックファイルを削除してから同じコマンドで作り直すと、パッケージグラフは同一（パス依存の 5 クレートのみ、version 4）になり、先頭は Cargo の標準ヘッダだけになった。

適用した変更は、rustfmt の結果と、Cargo 1.99.1 が生成した `Cargo.lock` である。暗号 API は変えていない。

再実行結果（すべて exit 0）:

| コマンド | 結果 |
|---|---|
| `rustc -vV` | `rustc 1.99.1 (58cf8f9c3 2026-10-13)`、`x86_64-unknown-linux-gnu`、LLVM 23.1.1 |
| `cargo fmt --all -- --check` | 差分なし |
| `cargo test --workspace --locked --offline` | ユニットテスト 10 件成功、doctest 0 |
| `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` | 警告なし |
| `cargo tree --workspace --locked --offline` | 外部クレートなし |

`rust-toolchain.toml` の channel `1.99.1` はこのコンパイラと一致した。ピンは変更していない。

## 4. 次の作業

優先度順。1 項目を 1 つの PR に収める。どの項目でも、実在のファイル、実在のパスワード、クラウド、第二の隠しパスワード、本番であるという説明は入れない。期待バイトは、テスト対象の実装を往復させて得た値を書き戻してはならない。公開仕様か、独立した計算の出力を定数にする。

各 PR の完了条件は共通である。失敗するテストを先に追加し、実装し、次の 3 つを通し、[06_PROGRESS_HANDOFF.md](06_PROGRESS_HANDOFF.md) の該当行を同じ PR で更新する。

- `cargo fmt --all -- --check`
- `cargo test --workspace --locked --offline`
- `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`

外部クレートを足す PR だけは、`Cargo.lock` の差分（追加されたクレート名とバージョン）を説明に書く。

### M1. P2.2 プリミティブの既知回答（最優先）

暗号でファイルを包む前に、採用候補のライブラリが公開ベクトルと一致することを固定する。

1. Rust 1.99.1 / edition 2024 でビルドできる `argon2`、`hkdf`、`sha2`、`chacha20poly1305`、`zeroize` のバージョンを一つずつ選び、`[workspace.dependencies]` に正確なバージョンで置く。UniFFI と `secrecy` はこの PR に入れない。オンラインでロックファイルを一度生成し、以後のテストは `--locked` で通す。
2. RFC 9106 に載っている Argon2id の既知回答を 1 件、`eidoron-crypto` のテストに定数で書く。入力と 32 バイト出力が一致することだけを見る。
3. RFC 5869 の HKDF-SHA256 テストケースを 1 件移植し、Extract と Expand の結果を比較する。info 文字列は RFC の例のままでよく、プロトコルの `"eidoron/v0/..."` は次のマイルストーンで使う。
4. XChaCha20-Poly1305 の公開ベクトルを 1 件固定する。鍵 32 バイト、nonce 24 バイト、タグ 16 バイト。出典（RustCrypto のテストベクトル、または libsodium の既知回答）を `crates/test-vectors/README.md` に 1 段落で書く。
5. 上の 3 つが通るまで `encrypt_authenticated` は `Err(NotImplemented)` のままにする。成功した暗号文を返すスタブは追加しない。

### M2. プロトコル鍵スケジュール（M1 の直後）

[09_ENVELOPE_FORMAT_V0.md](09_ENVELOPE_FORMAT_V0.md) の手順を、合成定数だけで実装する。

6. 固定の合成パスフレーズ、salt、`vault_id`、`object_id` から `RawPwdKey`、`WrapKey`、`ObjectKey` を計算する関数を `eidoron-crypto` に追加する。鍵の型は `Debug` で中身を出さない。
7. 期待バイトは、このクレートの往復テスト以外の手段で計算し、`eidoron-test-vectors` に hex 定数として置く。不一致のときは定数を実装の出力へ合わせるのではなく、手順か独立計算を調べる。
8. ラップされた RootSecret について、パスワード違い、AAD の 1 ビット反転、タグの 1 ビット反転を同じ失敗型にまとめる。失敗値に鍵も平文も含めない。
9. `status()` は、プリミティブのテストがリンクされただけでは `NotImplemented` から動かさない。ボルトとしての操作がまだ無い。

### M3. 公開バイトの拒否行列（M1 と並行してよい）

`eidoron-format` だけで閉じる。暗号は呼ばない。入力は既存の `synthetic_untrusted_*` を 1 フィールドだけ変えたものにする。

10. ヘッダ長 0、135、136、137 と、magic の不一致。受理は 136 バイトかつ `EIDORON\0` だけにする（P1.4 PAR-001 の長さと magic）。
11. major、minor、suite、flags、Argon2 version の未知値を、それぞれ `UnsupportedVersion`、`UnsupportedSuite`、`UnsupportedFlags`、`UnsupportedKdf` で拒否する（PAR-002）。
12. Argon2 の境界を表にする。`m` は 65535 / 65536 / 262144 / 262145、`t` は 0 / 1 / 10 / 11、`lanes` は 0 / 1 / 4 / 5、加えて `m < 8 * lanes`。範囲外は `ResourcePolicy`、範囲内は `Ok`（PAR-003）。
13. オブジェクト長 105、106、1,048,680、1,048,681 と、宣言された暗号文長と実長の不一致。検査は入力スライスの範囲だけを見て、宣言長に合わせて確保しない（PAR-005 の長さ部分）。
14. HEAD 長 65、66、67 と magic の不一致（PAR-008 の形だけ）。世代と object id の中身は認証済みとして返さない。

### M4. オブジェクトの AEAD（M1 と M2 の後）

15. 平文は `kind || schema || payload` で、長さ 2 以上 1,048,576 以下。範囲外は AEAD を呼ぶ前に拒否する。暗号文長の受理範囲は 18 以上 1,048,592 以下の既存定数に合わせる。
16. テストから nonce を渡す関数と、OS の CSPRNG から nonce を取る関数を分ける。本番の関数にテスト用シードを付けない。
17. 同じ `object_id` で別の平文を暗号化しようとした呼び出しは拒否する。`MemoryStore` の「同一バイトだけ再送可」と揃える。
18. 復号はタグ検証が成功するまで平文を返さない。エラーの表示文字列に平文と鍵を出さない。
19. RootSecret と鍵の型の `Drop` で `zeroize` を呼ぶ。ドキュメントには、消去がベストエフォートであることだけを書く。

### M5. 認証グラフの最初の純粋関数（M4 の後、完全な CBOR 実装の前）

20. 復号済みバイト列をテストから渡す関数で、commit kind `0x01` かつ generation 0 のとき先行コミットが空であることだけを検査する。CBOR デコーダ全体はこの PR に入れない。
21. ディレクトリ名の拒否（空、スラッシュ、`.`、`..`、NUL）を、暗号も CBOR も使わない関数としてテストする。NFC は次の PR に分ける。
22. チャンクの `file_id` と ordinal が、呼び出し側の期待と違うときに拒否する純粋関数を 1 つ追加する。ストア全体の走査はまだ作らない。

### M6. ディスクへ書く最小実装（M4 の後）

23. 一時ディレクトリに、不透明な 32 バイト ID をファイル名にして書き、同一バイトの再送と内容の違う上書き拒否だけをテストする。クラッシュ安全性と原子的な置換は、この PR の主張に入れない。
24. クラウド、HEAD の条件付き更新、遠隔のパスワード再ラップ、生体認証、Shadow 用の第二パスワードは、M1 から M6 のどれよりも後にする。同期に入る前に、選んだプロバイダの条件付き書き込みを実験した記録が別途要る（P3、ADR-0004）。

## 5. この計画のあいだ、手を付けないもの

- 利用者のファイル、本物のパスワード、署名鍵、バックアップのサンプル。
- 「パスワードを変えると、攻撃者が持つ古いヘッダからも読めなくなる」という動作。再ラップは古い RootSecret を無効にしない、と ADR-0004 にある。
- 隠しボリュームの画面、第二の KDF レコード、メニューを隠すことによる否認。
- 独自の暗号、AES-256-GCM-SIV の追加、UniFFI の先行導入。
- GitHub Actions を、ローカルで上の 3 コマンドが通ることの代替にすること。

## 6. 推奨する次の 1 手

M4 の項目 15 から着手する。オブジェクト平文は `kind || schema || payload` で、長さ 2 以上 1,048,576 以下。範囲外は AEAD を呼ぶ前に拒否する。テスト用 nonce と OS の CSPRNG から取る nonce を分ける。`encrypt_authenticated` は、このオブジェクト AEAD が既知回答と失敗試験を通すまで `NotImplemented` のままにする。
