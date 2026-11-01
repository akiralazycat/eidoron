# Eidoron 開発計画

- 作成: **2026-10-31**
- 最終更新: **2026-11-01（欠けたチャンクと逐次読み）**
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
| M4.15–19 オブジェクト AEAD | 完了。封印のたびに OS CSPRNG から 24 バイトの nonce を取る。同じ平文でも暗号文は変わる。固定 nonce はテストビルドだけ。`status()` は `NotImplemented` |
| M5.20 genesis の先行 | 完了。復号済みバイト列について、kind `0x01` かつ generation 0 のとき先行が null であることだけを検査する。CBOR デコーダ全体は未実装 |
| M5.21 ディレクトリ名 | 完了。保存前に NFC へ正規化する。NFC と NFD の `é` は同じ保存名。空、256 バイト超、`/`、NUL、名前全体が `.` または `..` は拒否 |
| M5.22 チャンク識別 | 完了。復号済みチャンクの `file_id` と big-endian ordinal を呼び出し側の期待と比べる。ストアは走査しない |
| M6.23 同期フォルダへの書き込み | 完了。同じディレクトリの一時ファイルへ書き、`sync_all` のあとリネームする。起動時に `.eidoron-tmp-` を消す。一時ファイルはオブジェクトとして読まない。電源断までの一貫性は未検査 |
| M6.24 分岐の保持 | 完了。中央 HEAD は製品経路ではない。二つの head は衝突として両方残す。`name (1)` と `conflicted copy` はオブジェクトにせず、自動では消さない。S3 の条件付き HEAD は将来の任意バックエンド。遠隔の再ラップ、生体認証、Shadow の第二パスワードは v1 に入れない |
| M6.25 作成と開錠 | 完了。空の同期フォルダに `vault.header` と genesis commit を書く。開錠はヘッダの Argon2id で root をほどく。`Session::status` は `Ok` / `Conflict` / `Incomplete` / `Locked`。`eidoron_crypto::status` は足場フラグのまま `NotImplemented` |
| M6.26 選んだ head のディレクトリ | 完了。`select_head` のあとだけ追記する。ディレクトリはオブジェクト AEAD、名前は NFC。一覧は選択中の head だけ。二つの head を並べる画面は無い |
| M6.27 複数チャンクと置換 | 完了。ファイルはチャンク上限で分割する。`replace_file` は新しいオブジェクトを足し、古いものは残す。`write_file` の同名は `DuplicateName`。選択はフォルダに書かない |
| M6.28 欠けたチャンクと逐次読み | 完了。届いていないチャンクは `Incomplete` で名前を出す。フォルダにあるが復号できないチャンクは `Unavailable`。`read_file_chunks` は検証のあとだけバイトを返す。空ファイルはチャンクゼロ |

## 1. 何を作っているか

Eidoron は、ファイルを端末側で暗号化してからクラウドへ置く、プライベートな保管・閲覧エンジンの構想である。出荷候補は **Vault**（存在が見えてよい暗号化アーカイブ）。**Shadow**（パスワードごとに別のファイル空間を見せる研究）と **Specter**（スナップショットやアクセス痕跡への耐性の研究）は、Vault の完成を待たせない別ゲートである。v0 のヘッダは形式が識別できるので、否認可能性の証拠にはならない。

2026-10-31 時点でリポジトリにあるのは、設計文書と、暗号を意図的に実装していない Rust ワークスペースだけである。

| クレート | 今あるもの |
|---|---|
| `eidoron-crypto` | 鍵スケジュールとオブジェクト AEAD。`encrypt_authenticated` は封じた暗号文を返す。`status()` は足場フラグのまま `NotImplemented` |
| `eidoron-format` | 非信頼な公開バイト列の長さ・magic・版・スイート・Argon2 資源上限だけを見る |
| `eidoron-provider-local` | プロセス内の `HashMap` と、同期フォルダの `TempDirStore`。同じ ID への異なるバイトは拒否し、同一バイトの再送だけを許す |
| `eidoron-vault` | 同期フォルダの作成、開錠、選択した head へのディレクトリ、複数チャンクのファイル、明示的な置換と名前の削除。インポートは `NotImplemented` |
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
| P2.2 プリミティブ、鍵スケジュール、オブジェクト AEAD、同期フォルダのセッション | M1、M2、M4、M6.28 完了。到達不能オブジェクトの回収と、二つの head を並べる画面は未実装 |
| 各 OS、Shadow / Specter | 未着手 |

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
17. **取り下げ（2026-10-31、所有者判断）。** 暗号層は、同じ平文を同じ鍵で再び封じたとき、以前の nonce と暗号文を返さない。封印のたびに OS CSPRNG から新しい 24 バイト nonce を取る。冪等性が要るときはストレージ層が扱う。**同日の追加判断:** そのための内容ハッシュは、HMAC、keyed BLAKE、またはボールト秘密から HKDF した鍵による鍵付きハッシュにするか、暗号文として保存する。平文の素のハッシュは保存しない。詳細は [09_ENVELOPE_FORMAT_V0.md](09_ENVELOPE_FORMAT_V0.md)。
18. 復号はタグ検証が成功するまで平文を返さない。エラーの表示文字列に平文と鍵を出さない。
19. RootSecret と鍵の型の `Drop` で `zeroize` を呼ぶ。ドキュメントには、消去がベストエフォートであることだけを書く。

### M5. 認証グラフの最初の純粋関数（M4 の後、完全な CBOR 実装の前）

20. **完了（2026-10-31）。** 復号済みバイト列を渡す `check_genesis_predecessor`。kind `0x01`、schema `0x00`、generation 0、先行が null のときだけ `EmptyPredecessor`。空のバイト列は null ではない。generation が 0 でないコミットはこの規則の対象外。CBOR デコーダ全体は未実装。期待ラベルは `scripts/genesis_commit_kat.py` が RFC 8949 の優先長で作ったバイト列に付いている。
21. **完了（2026-10-31、同日に NFC を採用）。** `check_directory_name` は先に NFC へ正規化し、その文字列を返す。NFC の `é` と NFD の `e` + U+0301 は同じ保存名になる。空、正規化後に 256 UTF-8 バイト超、`/`、U+0000、名前全体が `.` または `..` は拒否する。`file.txt` と `.hidden` と `...` は受理する。CBOR とディレクトリ集合は未実装。
22. **完了（2026-10-31）。** `check_chunk_identity` は復号済みの `kind || schema || file_id:16 || ordinal:u32be || file_bytes` について、`file_id` か ordinal が期待と違えば同じ `Mismatch` を返す。ペイロードは比べない。ストアは走査しない。

### M6. ディスクへ書く最小実装（M4 の後）

23. **完了（2026-10-31、同日に書き込み手順を更新）。** `TempDirStore` は 32 バイト ID を 64 文字の小文字 hex で書く。内容 ID はそのファイル名にしない。新しいオブジェクトは同じディレクトリの `.eidoron-tmp-` へ書き、ファイルの `sync_all` のあと hex 名へリネームする。`create` は残った一時ファイルを消す。一時ファイルは `get` の対象にならない。同一バイトの再送は `IdenticalRetry`。違うバイトは拒否する。ディレクトリの `sync_all` は試し、失敗しても書き込み成功を取り消さない。電源断のあとディレクトリが一貫する、とは主張しない。
24. **完了（2026-10-31）。** 製品は Cryptomator 型の利用者アプリである。ボルトはローカルフォルダで、Google Drive や Dropbox などの同期は利用者の道具が行う。アプリはクラウド API を呼ばない。中央の HEAD ファイルは置かない。同じ親から分かれた commit は `classify_heads` が `Conflict` とし、どちらの head も捨てない。`name (1)` と `conflicted copy` を含むファイル名はオブジェクト ID ではなく、スキャン結果に残し、削除しない。`ConditionalHead` と [13_S3_CONDITIONAL_HEAD.md](13_S3_CONDITIONAL_HEAD.md) は将来の任意バックエンドである。
25. **完了（2026-10-31）。** `create_vault` は空、または存在しないディレクトリだけを受け、`vault_id`、salt、ラップした root、generation 0 の genesis commit を temp + `sync_all` + rename で書く。中身のあるディレクトリと、既存の `vault.header` は拒否する。`open_vault` はヘッダに書いてある Argon2id パラメータで root をほどく。パスワード違い、タグ不良、壊れたヘッダは同じ `Unavailable`。所要時間が揃うことは測っていない。`Session::status` は一つの完全な履歴なら `Ok`、複数の head なら `Conflict(heads)`、親オブジェクトが無いなら `Incomplete`、`lock` または drop のあとなら `Locked`。drop は root を zeroize する。これはベストエフォートである。`eidoron_crypto::status()` は足場フラグのままで、セッション状態とは別である。
26. **完了（2026-10-31）。** 追記は `select_head` のあと、その head だけに行う。選択していない追記は `HeadNotSelected`、別の head への追記は `WrongHead`。自動マージはしない。他の head のファイルは変えない。選択はメモリ上だけで、フォルダには書かない。開き直すと選択は消える。ディレクトリオブジェクトは kind `0x02` をオブジェクト AEAD で封じ、名前は `check_directory_name` の NFC である。NFC と NFD が同じ名前になる二つは `DuplicateName` で、何も書かない。一覧は選択中の head の根ディレクトリだけを返す。復号できない 64 文字 hex と、commit として読めない kind `0x01` は `status` 全体を `Unavailable` にし、飛ばさない。復号できたディレクトリ、ファイル、チャンクは commit ではないので履歴には入れない。平文の既知回答は `scripts/directory_kat.py`。暗号文の固定ベクトルは足していない。
27. **完了（2026-11-01）。** `append_directory` は空のサブディレクトリオブジェクトを書いてからリンクする。ファイル種別のエントリは拒否し、何も書かない。ファイルは `write_file` だけが足す。空のファイルはチャンクを作らず、読み戻すと空である。それ以外は 1,048,554 バイトごとに分割し、各チャンクを `check_chunk_identity` に通す。記述子のチャンク列は ordinal 順である。8192 チャンクを超える長さは `Unavailable`。`replace_file` は新しいファイルオブジェクトと子 commit を作り、古いオブジェクトは消さない。同名への `write_file` は `DuplicateName`。`delete_entry` は新しい commit のディレクトリから名前を外し、オブジェクトは残す。選択は `select_head` のメモリだけで、フォルダのファイル一覧は変わらない。新しい固定ベクトルは足していない。
28. **完了（2026-11-01）。** 選択中の head、または head が一つのとき、その head から辿れるファイルの記述子かチャンクがフォルダに無いと `status` は `Incomplete { entries }` で、そのファイル名を返す。チャンクファイルが戻ると `Ok` に戻る。フォルダにあるオブジェクトが復号できないときは `Unavailable` のままで、名前の一覧にはしない。`read_file_chunks` は AEAD と `check_chunk_identity` とマニフェストの順が通ったチャンクだけを返す。途中で切れた長さ、順の違い、同じチャンク ID の繰り返しは `Unavailable` で、そのチャンクのバイトは返さない。`read_file` はそれを集める全体読みで、失敗時は途中の平文を返さない。genesis は空のルートディレクトリオブジェクトを書く。到達不能オブジェクトは消さない。衝突コピーは触らない。新しい固定ベクトルは足していない。

## 5. この計画のあいだ、手を付けないもの

- 利用者のファイル、本物のパスワード、署名鍵、バックアップのサンプル。
- 「パスワードを変えると、攻撃者が持つ古いヘッダからも読めなくなる」という動作。再ラップは古い RootSecret を無効にしない、と ADR-0004 にある。
- 隠しボリュームの画面、第二の KDF レコード、メニューを隠すことによる否認。
- 独自の暗号、AES-256-GCM-SIV の追加、UniFFI の先行導入。
- GitHub Actions を、ローカルで上の 3 コマンドが通ることの代替にすること。

## 決まったこと（2026-10-31）

- ディレクトリ名は保存時に NFC へ揃える。正規化後に同じ文字列になる綴りは、同じ名前である。
- 内容 ID は、`RootSecret` と `vault_id` から HKDF-SHA256 で導いた専用鍵による HMAC-SHA256。info は `eidoron/v0/content-id || vault_id`。平文の素のハッシュは使わない。この ID を同期フォルダから見えるファイル名にしてはならない。オブジェクト名は 64 文字の hex ID のままである。
- **製品形態（同日に変更）。** Eidoron は Cryptomator 型の利用者アプリである。ボルトはローカルフォルダで、クラウドとのやり取りは利用者自身の同期ツールが行う。アプリは Google Drive や Dropbox の API を呼ばない。中央 HEAD は製品経路ではない。分かれた head は両方残し、利用者に衝突として見せる。黙って片方を消さない。自動マージはしない。S3 互換の条件付き HEAD は将来の任意バックエンドに下げ、優先度は低い。
- **#17 で採用。** 衝突コピー（`name (1)`、`conflicted copy`）はアプリが自動では消さない。クラッシュ安全性は、検査した一時ファイルの掃除と、成功が返ったあとの完全なバイトまでに限る。電源断の一貫性は主張しない。遠隔の再ラップ、生体認証、Shadow の第二パスワードは v1 に入れない。
- **#18 で採用。** 衝突中は、利用者が head を選ぶまで追記しない。自動マージはしない。ライブラリも、選択した head 以外への追記を拒否する。64 文字 hex で復号できないファイル、および commit として読めない kind `0x01` は `status` を `Unavailable` にし、飛ばさない。パスワード失敗とヘッダ破損の所要時間が同じだとは主張しない。
- **#19 で採用。** ディレクトリがリンクするのは、その場で書いたオブジェクトだけである。ファイルは `write_file` か `replace_file` が作る。同名への `write_file` は `DuplicateName` のままで、黙って上書きしない。置換は `replace_file` だけが行う。選んだ head はメモリに留め、フォルダには書かない。
- **#20 で採用。** 到達しなくなったオブジェクトは自動では消さない。将来の回収は、どの head からも辿れないオブジェクトだけが対象で、衝突コピーには触らない。`delete_entry` は名前だけを外す。再帰削除は別の明示操作である。逐次読みは、検証が終わる前のバイトを返さない。空ファイルはチャンクゼロのままである。

## 未決

- 衝突中に、選択した head のチャンクが欠けているとき。現状は `Conflict` より先に `Incomplete { entries }` を返す。チャンクが揃うと、フォークが残っていれば `Conflict` に戻る。推奨は、この順のままにする。待っているファイル名を先に見せ、もう一方の head はフォルダに残っている。
- `Incomplete` の `entries` に head の ID を足すか。推奨は、選択中の一つの head ではファイル名だけで足りる。選択前に複数 head の欠けを同時に出すようになったら、head の ID を添える。

## 6. 推奨する次の 1 手

選択中の head から、一つのサブディレクトリの中を一覧する。到達しなくなったオブジェクトは消さない。二つの head の中身を並べる画面は作らない。クラウドのアカウントは作らない。
