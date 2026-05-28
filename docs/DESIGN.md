# システム設計書 (v0.4)

**変更履歴**:
- **v0.4** (2026-05-10): GitHub Issues #1-#13 から派生する設計影響項目を v0.4 候補として追加。本文中の差分は実装着手時に【v0.4変更】で明示する。
- **v0.3** (2026-05-09): レビュー2回目12件を反映。変更箇所は【v0.3変更】で明示。
- **v0.2**: v0.1のレビューコメント(T Kaw氏)26件を反映。変更箇所は【変更】で明示。

## v0.4 設計影響項目(GitHub Issues 由来、未実装)

GitHub Issues #1-#18(全件 `docs/STATUS.md §8.1` に展開)のうち、**設計レベルの判断を要するもの** をここに分離して記録する。実装着手時には対応する本文章節を【v0.4変更】で更新する。

| Issue | 対象章 | 設計判断が必要な点 | 状態 |
|---|---|---|---|
| **#3** | §6.5(Review Gates) | Gate の **命名**: 現行 `Gate 0 (parse) / Gate 1 (findings) / Gate 2 (timeline)` → 提案 `Gate 1 / Gate 2 / Gate 3` への 1 オフセット。タブ名・配置(Parse Results & Event Browser を 1 つの Gate タブにまとめる、Findings タブ名を `Findings (Gate 2)` 等に明示)も含む | 🔴 未着手・採否要相談 |
| **#11/#12/#13** | §2(全体構成図)+ §6.5 | **Auto-pilot モード**: Parse / Analyze / (※将来)Timeline review の 3 Gate をすべて事前 skip 設定 → 起動 1 クリックで Tier 0〜3 を完走させるモード。`config/review_gates.yaml` の auto_skip と整合 | 🔴 未着手 |
| **#9** | §6.3 / §7.1 | **Findings 本文 / Timeline Summary の出力言語**: 現状の `--language ja|en` はレポートテンプレートのラベルだけで、**LLM 出力本文は実態として英語固定**。Tactic Agent の system prompt に出力言語指示を入れて根本対応するか、後段で翻訳パスを噛ませるか要検討。DESIGN v0.3 #8/#9 と統合扱い | 🔴 未着手(v0.3 #8/#9 と合流) |
| **#16** | §8(横断機能)新規 §8.5 / REQ-2 | **ケース export / import**: 1 ケース分(DuckDB 行 + workspace tree + findings + reports + parse_review + audit)を可搬な tarball に固める。manifest.json + 全ペイロード SHA-256 で整合保証。詳細は本書「v0.4 追加要件 → REQ-2」 | 🔴 未着手(本セッションで実装着手) |
| **#17** | §4.3 / `config/artifacts.yaml` | **Prefetch パーサのエンジン切替**: SIFT には PECmd が同梱されていないため、`docs/tool_inventory.md` の検証で primary を Plaso (`log2timeline.py --parsers prefetch` + `psort.py`) に変更。PECmd は **opt-in fallback**(PECmd.dll が存在する開発機のみ)。`PARSER_VERSION` も更新 | 🔴 未着手(本セッションで実装) |

> 他の Issue(#1, #2, #4-#8, #10, #14, #18)は **UI 実装 / setup スクリプトの改善で設計レベルの変更を要さない** ため、`STATUS.md §8.1` のみ管理。実装時に必要なら DESIGN.md にも反映する。

## v0.4 追加要件(運用フィードバック由来、未実装)

GitHub Issue ではなく、運用中に発生した要望・改善要求を集約する。本文中の差分は実装着手時に【v0.4変更】で明示する。

| ID | 対象章 | 内容 | 状態 |
|---|---|---|---|
| **REQ-1** | §2 / §4.1 | **ネスト アーカイブ アーティファクトの再帰展開**: 現状 `stage_input` は入力 zip を 1 回だけ展開し、内部の `*.zip` / `*.7z` / `*.tar.gz` 等はそのまま放置している。KAPE / CyLR / Velociraptor / 社内収集スクリプト等は **ホストごと / アーティファクトカテゴリごと** にネストされた圧縮ファイルを作るため、検出パイプラインから不可視になる。Tier 0 のステージ段で発見した対応アーカイブを **再帰的に解凍** し、検出ループの対象に含める。安全装置(下記)とセットで実装する | 🟢 実装完了 (2026-05-11) |
| **REQ-2** | §8(新設 §8.5) | **ケース export / import**(Issue #16): 1 ケースを 1 tarball (.fcz) として可搬化。manifest.json + 全ペイロード SHA-256 で整合保証。詳細は下記「REQ-2 ケース export / import」 | 🔴 本セッションで実装着手 |

### REQ-1 ネスト アーカイブ解凍 — 設計詳細

**スコープ(MVP)** — 以下の形式を共通フレームワークで扱う:

| 拡張子 | バックエンド | 依存 | 備考 |
|---|---|---|---|
| `.zip` | stdlib `zipfile` | 標準 | 旧来の入力フォーマット。CP932/UTF-8 フォールバック |
| `.7z` | `py7zr` (PyPI) | 要追加(`pyproject.toml` に追記) | LZMA/LZMA2/Bzip2 対応。暗号化(パスワード)は skip |
| `.tar` | stdlib `tarfile` | 標準 | symlink / hardlink / device メンバーは reject |
| `.tar.gz` / `.tgz` | stdlib `tarfile` (gzip mode) | 標準 | `tarfile.open(mode='r:gz')` |
| `.tar.bz2` / `.tbz2` | stdlib `tarfile` (bzip2 mode) | 標準 | 同上 `r:bz2` |
| `.tar.xz` / `.txz` | stdlib `tarfile` (xz mode) | 標準 | 同上 `r:xz` |
| `.gz` (単体ファイル) | stdlib `gzip` | 標準 | tarball ではない裸の `.gz`(例: `SYSTEM.gz`)を 1 メンバーとして展開 |

**入口・展開先・反復**:
- `parsers/orchestrator.py::stage_input` の戻り値ルートを起点に、対応拡張子を `rglob` で発見した順に展開
- 展開先: `workspace/extracted/__nested__/<元ファイルの sha256_short>/`
- 原アーカイブと展開後ディレクトリの両方が残るが、検出ループは展開後だけを対象にする(原アーカイブ自体は検出対象から除外)
- 完了後に **再度スキャン** を回し、`max_depth` まで深さ分だけ繰り返す(`.zip` → `.tar.gz` → `.7z` のような異形式チェーンも辿る)

**形式判定**:
- 拡張子 + マジックバイト(`PK\x03\x04` / `7z\xBC\xAF\x27\x1C` / `\x1F\x8B` / tar magic at offset 257 = `ustar`)の両方で判定
- 拡張子だけ偽装した非対応バイナリは skip(`result: "skip:format_mismatch"`)

**安全装置(必須・全形式共通)**:

| 項目 | 上限の既定値 | 動作 |
|---|---|---|
| `max_depth` | 4 | これ以上深いネストは「skip」として `actions.jsonl` に記録、検出対象から除外 |
| `max_total_extracted_bytes` | 50 GiB(設定可) | 累積展開サイズ閾値を超えたら以降の展開を停止し、警告ログ |
| `max_member_uncompressed_bytes` | 4 GiB | 個々のメンバーがこれを超えるとそのアーカイブを skip(bomb 対策) |
| `compression_ratio_cap` | 200 | (合計非圧縮 / 圧縮)比がこれを超えると skip。`.7z` / `.tar.xz` は LZMA で高圧縮になるため `compression_ratio_cap_lzma=500` を別途用意 |
| パストラバーサル | `../` / 絶対パス / シンボリックリンク / ハードリンク / device / FIFO メンバーを展開前にバリデート、違反はアーカイブ全体を skip | |
| 文字コード | zip: CP932/UTF-8 順次フォールバック。tar: utf-8 を既定、失敗時 latin-1。7z: py7zr が UTF-16 内部表現で扱う | |
| 暗号化 | zip/7z でパスワード必要 → skip(`result: "skip:encrypted"`) | |
| tar 特殊メンバー | `tarfile.data_filter` (Python 3.12+) を使用。古い Python では自前バリデータ | |

**監査ログ (`actions.jsonl`)**:
```json
{"type": "nested_extract",
 "format": "7z",
 "src": "evidence/host1/Registry.7z",
 "dst_dir": "workspace/extracted/__nested__/ab12cd34/",
 "members": 142,
 "bytes_uncompressed": 38291812,
 "compression_ratio": 4.2,
 "depth": 1,
 "result": "ok",
 "duration_ms": 312}
```
skip 時は `result: "skip:<reason>"`(`encrypted` / `bomb_ratio` / `bomb_member_size` / `path_traversal` / `format_mismatch` / `depth_exceeded` / `total_size_exceeded` / `missing_backend`)を入れる。

**進捗イベント**: stage フェーズ内で
```json
{"type": "stage", "phase": "extracting_nested",
 "format": "tar.gz", "depth": 2,
 "src": "Registry.tar.gz", "members_extracted": 142}
```
を `--progress` 経由で UI バーに流す。

**検出ルールへの影響**: なし。展開後ディレクトリ配下に出てくる `*.evtx` / `$MFT` / `SOFTWARE` 等は既存の `_DETECTORS` がそのままマッチするため、検出ルール側の変更は不要。

**Review Gate 0 への影響**: パース結果と並んで「ネスト解凍ログ」を Events タブから確認可能にする(`parse_review.json` に `nested_extractions[]` を追加)。形式 / スキップされたアーカイブと理由をレビュアーが確認できるようにする。

**設定ファイル**: `config/staging.yaml` を新規追加し、上記上限値・対象拡張子・依存バックエンドの有無を集約管理。コードにマジックナンバーを書かない。

**依存追加**:
- `pyproject.toml` の `[project.dependencies]` に `py7zr>=0.21` を追加
- `py7zr` が import 失敗時は `.7z` を `result: "skip:missing_backend"` として graceful degradation(ツール全体は動き続ける)
- `scripts/setup.sh` の `pip install` パスに自動含有

**テスト**:
- `tests/fixtures/nested_archives/` に以下のフィクスチャを追加(各 < 1 MB):
  - `nested_zip_2levels.zip`(2 段 zip ネスト)
  - `nested_7z.7z`(7z 直下に EVTX 1 個)
  - `nested_targz.tar.gz`(tar.gz 直下に Registry hive 1 個)
  - `mixed_chain.zip`(zip → 7z → tar.gz の異形式チェーン)
  - `bomb_small.zip`(極小だが高圧縮比 1000:1)
  - `traversal.zip`(`../../etc/passwd` メンバー入り)
  - `traversal.tar`(symlink → `/etc/passwd` 入り)
  - `encrypted.7z`(パスワード付き)
- `tests/parsers/test_stage_input.py` で各上限の発火・skip の `actions.jsonl` 記録を検証(形式ごとに 1 ケース最低)

### REQ-1 のスコープ外(明示)

- VHDX / E01 / RAW disk image — 別 REQ(Sleuth Kit 連携が必要)
- 暗号化アーカイブ — パスワード入力 UI が無いので skip(`result: "skip:encrypted"`)
- 形式 `.rar` / `.cab` / `.iso` — 採否は需要次第、本 REQ では除外
- `max_depth` を超えるネスト — 安全のため skip
- ネスト アーカイブ自体を「アーティファクトとして」パースする(zip のメタデータ抽出等) — 不要

### REQ-2 ケース export / import(Issue #16)

**動機**: 解析を別 PC へ持っていって続きをやる / 同僚にレビュー依頼する / 完了ケースをアーカイブする、いずれの場面でも「ケース 1 件を 1 ファイルで運べる」ことが必須。現状は `outputs/cases.duckdb`(全ケース共有 DB)と `outputs/cases/<id>/`(ファイルツリー)に分散しているので、可搬性ゼロ。

**スコープ(MVP)**:
- `findevil case export --case <id> --out <case>.fcz` で 1 ファイル tarball(`.fcz` = FindEvil Case Zip、中身は `.tar.gz`)を生成
- `findevil case import --in <case>.fcz` で受け側に展開、DuckDB に書き戻し
- Web UI: ケース一覧の "⤓ Export" ボタン + 一覧上部の "⤒ Import" ボタン

**バンドル構造**(tarball 内のルート):
```
<case_id>/
├── manifest.json          # 後述、SHA-256 一覧 + メタ
├── parse_results.jsonl    # DuckDB.parse_results を case_id で絞った行
├── unified_events.jsonl   # DuckDB.unified_events 同上
├── findings/              # outputs/cases/<id>/findings/ そのまま
├── reports/               # outputs/cases/<id>/reports/ そのまま
├── workspace/             # outputs/cases/<id>/ の残り全部
│   ├── extractions/       # 注: パース後の中間 CSV/JSON のみ。原 evidence の zip は除外可
│   ├── actions.jsonl
│   ├── parse_review.json
│   └── ...
└── extractions_original/  # オプション: 元 zip / dir(--include-evidence 指定時のみ)
```

**manifest.json**(必須フィールド):
```json
{
  "schema": "findevil/case-export/v1",
  "case_id": "INC-2026-0001",
  "exported_at": "2026-05-12T08:00:00Z",
  "exported_by": "operator@host",
  "findevil_version": "0.4.0",
  "duckdb_schema_version": "1",
  "include_evidence": false,
  "row_counts": { "parse_results": 12, "unified_events": 30412, "findings": 47 },
  "files": [
    {"path": "parse_results.jsonl", "sha256": "ab12...", "bytes": 18421},
    {"path": "unified_events.jsonl", "sha256": "cd34...", "bytes": 8723091},
    ...
  ]
}
```

**整合保証**:
- export 時: 全ペイロードファイルの SHA-256 を計算 → manifest.files に格納
- import 時: 各 sha256 を再計算して manifest と照合、1 件でも不一致なら abort(`--force` で続行可)
- DuckDB 行は JSONL でやり取り(`SELECT ... WHERE case_id = ?` → JSONL dump、import で `INSERT OR REPLACE`)

**衝突解決**(import 時):
- 同 `case_id` のケースが既にある → 既定では abort、`--overwrite` で既存削除 → 上書き
- DuckDB 側: `DELETE FROM parse_results WHERE case_id = ?` → `INSERT INTO ... SELECT FROM read_json(...)`
- ファイルシステム側: `outputs/cases/<id>/` を一度削除 → tarball 展開

**監査ログ**: 操作毎に `actions.jsonl` に `kind:case_export` / `kind:case_import` を追記(誰が・いつ・何を・整合結果)。

**スコープ外(MVP)**:
- 暗号化 / 署名 — 後続フェーズ(`--sign <key>` / `--encrypt-with <pubkey>`)
- 部分エクスポート(findings だけ等) — そもそも別画面の責務
- 複数ケース一括 — for ループで回せばよい
- evidence 原本のオプション含有 — `--include-evidence` フラグだけ用意し、既定は OFF(サイズ過大対策)

**設計上の懸念**:
- DuckDB 全 case 1 DB なので export 時に他ケースの行を漏らさないこと → JSONL 形式で `case_id = ?` を明示
- `evidence_id` がケースをまたいで衝突する可能性 — manifest にスナップショットして import 時に rename 可能
- ファイルサイズ: workspace は数 GB になり得る。tar.gz で十分(gzip でも EVTX は 1/5〜1/10 圧縮)。`--no-compress` は不要

**実装ファイル**:
- 新規 `internal/exporter/case_export.go`(Go から DuckDB 行 dump → tarball)
- 新規 `internal/exporter/case_import.go`
- `cmd/findevil/main.go` に `case export` / `case import` サブコマンド追加
- `internal/web/handlers.go` に `POST /api/cases/:id/export` / `POST /api/cases/import`
- UI: cases 画面に export/import ボタン

## v0.3 変更一覧 (実装計画)

| # | 章 | 内容 | 現状 | 必要な実装作業 |
|---|---|---|---|---|
| 1 | §2, §4.1 | 複数 Evidence 選択。Evidence ごとに処理し、全完了で次フェーズへ | DB に `evidence` テーブルあり、CLI/UI は単一前提 | UI で複数選択、orchestrator のループ化 |
| 2 | §2, §4.1, §3 | **Review Gate 0** 実装(現状は Gate 1 のみ) | Gate 1 (CLI + WebUI Findings) のみ実装済 | Gate 0 ハンドラ + UI、`config/review_gates.yaml` 反映 |
| 3 | §5.2, §5.3 | Tactic Agent をスライドウィンドウ式に(全件まとめ読みは精度低下) | 現状: prefilter 後の全イベントを 1 ショット | `runner.go` に window 分割 + 結果マージロジック |
| 4 | §4.2 | `tactic_hints` / `technique_hints` を **削除**(未知攻撃を取りこぼす) | 設計書のみに存在、コードでは未使用 | 設計書から削除、Tactic Agent の prefilter 戦略見直し |
| 5 | §4.3 | **ブラウザ履歴** パーサ追加(Web 経由攻撃の追跡) | 未実装 | `parsers/browser_parser.py` 新規(Chrome/Edge/Firefox SQLite) |
| 6 | §4.4 | MCP 関数を Protocol SIFT 拡張、**TTP ベース** で必要アーティファクト取得 | 8 関数(汎用クエリのみ) | `events.by_ttp(tactic_id, technique_id)` 等を新設 |
| 7 | §5.1 | Tier 1 が `case_id + evidence_id` 両方認識(Evidence 追加・相関のため) | runner は両方受け取るが、Web UI/CLI は first evidence のみ渡す | 全 Evidence をループ + Evidence 間相関ロジック |
| 8 | §6.3 + 横断 | **ツール全体の言語切替**(英 / 日)。整合性ルール記述含む | 個別箇所は localized、ツール全体は未対応 | `i18n` 共通レイヤ + UI 言語選択 |
| 9 | §7.1 | レポートの言語選択を一般的なデータセット範囲に拡大 | ja / en のみ | locale データ追加(中・韓・西語等) |
| 10 | §6.6 | Recommendations に **Next step**(できなかった調査の推奨)を含める | recommendations は 3 区分のみ | `next_steps` フィールド追加、Synthesizer で生成 |
| 11 | §8.4 | RAG 構築は MITRE STIX の `enterprise-attack` だけに絞る | RAG 自体未実装 | `rag/build_rag.py` で `enterprise-attack` のみフェッチ |
| 12 | §2, §4.3 | **Washizukami-Collector** 形式の入力に対応 | 一般的な dir / zip のみ | orchestrator の detect ルールに Washizukami 構造追加 |

> 凡例 — 各章の本文中では具体的な仕様変更を【v0.3変更】マーカーで記述。実装作業は別タスクとして順次着手。

---

## 1. 設計原則

このアーキテクチャを成立させる4つの原則を最初に置きます。実装中に迷ったらここに戻ります。

- **原則1 — Tier間の単方向依存**:Tier N は Tier N-1 にのみ依存。逆流禁止（自己修正ループは Tier 2 内で閉じる）
  - 【変更】論点: 自己修正時に Tier 1 を再起動するフローがあるため、完全な単方向ではない。「通常フローは単方向、自己修正フローのみ Tier 2 → Tier 1 の逆流を許可」と整理する。Tier 0 への逆流は禁止。

- **原則2 — Tier 1 エージェントの完全独立**:Tactic Agent 同士は通信しない。共有はパース済みデータのみ。これにより並列実行が可能で、デバッグも容易

- **原則3 — Read-only by construction**:MCP Server は read 系関数のみを露出。原本データへの書き込みは構造的に不可能（prompt-based ではなく architectural）
  - 【変更】補足説明: これは「プロンプトで『書き込むな』と指示する」のではなく、「書き込み用の関数自体がMCPサーバーに存在しない」ことを意味する。つまりエージェントが書き込もうとしても、そもそも呼び出せる関数がない。これにより、LLMが指示を無視しても証拠データが守られる。

- **原則4 — 機械可読 first**:あらゆる中間データ・findings・ログは JSON Lines。HTML/CSV は最終レンダリング層でのみ生成

【変更】**今後の方針**: 最終的にはマルチモデル化を目指すが、まずは Skills 前提で Claude で構築する。マルチモデル対応は後続フェーズで検討する。

---

## 2. システム全体構成図

【変更】ASCII図内のラベルに補足説明を追加。各Tier間にレビューゲートを追加。

```
┌────────────────────────────────────────────────────────────────────┐
│ INPUT: Collector出力 zip (Washizukami-Collector準拠フォーマット)   │
│ ※ ケース番号・Evidence番号・タイムゾーンをユーザーが指定          │
│ 【v0.3変更】複数 Evidence を一度に選択可能。各 Evidence ごとに    │
│           Tier 0 を実行し、全 Evidence のパース完了を待ってから   │
│           Tier 1 に進む(graceful degradation: 一部 Evidence の  │
│           失敗で全体は止めない)                                   │
│ 【v0.3変更】入力フォーマットは Washizukami-Collector             │
│   (https://github.com/tadmaddad/Washizukami-Collector) に準拠    │
│ 【v0.4変更 REQ-1】Evidence 内のネスト アーカイブ (zip/7z/        │
│   tar.gz/tar.bz2/tar.xz/gz) は Tier 0 のステージ段で再帰展開      │
│   される(上限・安全装置・依存 py7zr あり)                        │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ Tier 0: Custom MCP Server (アーティファクト前処理)                │
│                                                                    │
│  zip展開 → 個別パーサー → 統一イベントモデル → DuckDB書込        │
│  (SHA-256検証) (SIFT標準ツール)  (正規化)       (read-only公開)   │
│                                                                    │
│  ※ 各パーサの実行コマンド・成否・標準出力をログに記録             │
│  ※ エラーなく処理できたかを確認可能にする                         │
│  ※ パース結果はUI上から絞り込み・ダウンロード可能                 │
└────────────────────────────────────────────────────────────────────┘
                              │
                    【Review Gate 0】 ← 【v0.3変更】実装対象に追加
                    パース結果・コマンド・成否をレビュー
                    許可/拒否/skip(すべて許可)
                    ※ 現状は未実装(Gate 1 のみ実装済)
                    ※ Phase 2.x で実装予定
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ Tier 1: Tactic Agents (Claude Code subagent × 10並列)             │
│                                                                    │
│  各エージェント = Skills(system prompt) + RAG + 上限設定          │
│  ※ Skills: Tacticの知識・使用ツール制約・思考プロセスを記述       │
│  ※ RAG: MITRE ATT&CK Technique の詳細を都度検索                  │
│  ※ 上限設定: 最大繰り返し回数・トークン上限等の安全装置           │
│                                                                    │
│  出力: TacticReport JSON (findings + negative + IOC + audit)       │
└────────────────────────────────────────────────────────────────────┘
                              │
                    【Review Gate 1】
                    TacticReport + 根拠ログをレビュー
                    許可/拒否/skip  ※ UIはValhuntir参考
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ Tier 2: Synthesizer (統合・自己修正)                              │
│                                                                    │
│  Aggregator: findings集約・重複排除                                │
│  ConsistencyChecker: Tactic間の整合性チェック                     │
│  TimelineBuilder: 時系列再構築(Plasoカラム準拠)                   │
│  Corrector: 矛盾発見時、Tier 1 または Tier 2 を再調査             │
│             ※ Tier 0 パーサは正しければ結果不変のため対象外       │
│                                                                    │
│  出力: CaseSynthesis JSON                                          │
└────────────────────────────────────────────────────────────────────┘
                              │
                    【Review Gate 2】
                    Timeline + 根拠ログをレビュー
                    許可/拒否/skip
                    ※ 許可済みアイテムはフラグ/色で識別・フィルター可
                    ※ レビュー後、未知の怪しい痕跡を再探索
                    ※ 発見分はReview Gate 1に戻してやり直し
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ Tier 3: Report Generator                                          │
│                                                                    │
│  IRレポート → CSV / JSON / HTML                                   │
│  ※ 言語指定可能(日本語/英語)                                     │
└────────────────────────────────────────────────────────────────────┘
```

---

## 3. リポジトリ構造

```
project-root/
├── README.md                      # Try-It-Out 含む
├── pyproject.toml                 # Python 依存
├── docs/
│   ├── requirements.md            # 要件定義書
│   ├── design.md                  # 本書
│   ├── architecture-diagram.{png,drawio}
│   └── meetings/                  # 議事録
├── src/
│   ├── tier0_mcp/                 # MCP Server
│   │   ├── server.py              # MCP entrypoint
│   │   ├── parsers/               # アーティファクト別パーサー
│   │   │   ├── evtx.py
│   │   │   ├── amcache.py
│   │   │   ├── prefetch.py
│   │   │   └── ...
│   │   ├── normalizer.py          # 統一イベントモデル
│   │   ├── indexer.py             # DuckDB書込
│   │   └── tools/                 # MCP関数定義
│   ├── tier1_agents/              # Tactic Agents
│   │   ├── base.py                # 共通基底
│   │   ├── prompts/               # Skills (Tactic毎)
│   │   │   ├── persistence.md
│   │   │   ├── execution.md
│   │   │   └── ...
│   │   ├── runner.py              # subagent起動ラッパ
│   │   └── schemas.py             # TacticReport schema
│   ├── tier2_synthesizer/
│   │   ├── aggregator.py
│   │   ├── consistency.py
│   │   ├── timeline.py
│   │   └── corrector.py
│   ├── tier3_reporter/
│   │   ├── templates/
│   │   │   └── report.html.j2
│   │   ├── renderer.py
│   │   └── mitre_mapper.py
│   ├── review/                    # 【変更】レビューゲート
│   │   └── gate.py
│   └── common/
│       ├── config.py
│       ├── logger.py
│       └── trace.py
├── rag/
│   └── mitre_attack/
│       ├── tactics/
│       │   ├── TA0001_initial_access/
│       │   │   ├── _index.md
│       │   │   ├── T1190.md
│       │   │   └── ...
│       │   └── ...
│       └── build_rag.py           # MITRE STIX → md自動生成
├── config/
│   ├── tactics.yaml               # Tactic Agent定義
│   ├── artifacts.yaml             # アーティファクト優先度
│   ├── caps.yaml                  # max-iterations / token caps
│   └── review_gates.yaml          # 【変更】レビューゲート設定
├── tests/
│   ├── fixtures/                  # テスト用 collector zip
│   ├── test_parsers/
│   ├── test_agents/
│   └── test_e2e/
├── eval/
│   ├── datasets/                  # 評価データセット
│   ├── ground_truth/              # 期待されるfindings
│   └── benchmark.py               # ベンチマーク実行
└── outputs/                       # ケース別実行結果
    └── {case_id}/
        ├── tier0_db.duckdb
        ├── tier1_reports/
        ├── tier2_synthesis.json
        ├── tier3_report.{csv,json,html}
        └── audit_log.jsonl
```

---

## 4. Tier 0 詳細設計 — Custom MCP Server

### 4.1 責務

- collector zip の展開と整合性検証（SHA-256）
- 23種のアーティファクトを **個別パーサー** で構造化
  - 【変更】各パーサの実際に使用したコマンドと、パース成功/失敗（実行後の標準出力含む）をログに記録
  - 【変更】Review Gate 0 で結果をレビューし、許可/拒否が可能。skip（すべて許可）機能あり。最初に各レビューの自動skip設定が可能
- 全イベントを **統一イベントモデル** に正規化して DuckDB に書込
  - 【変更】正規化前のオリジナルパース結果は、UI上から絞り込みとダウンロードが可能
- read-only な型付き MCP 関数を Tier 1 に提供
- 【変更】ケース番号(case_id)・Evidence番号(evidence_id)・タイムゾーン(timezone)をユーザーが実行時に指定。原本をいじらず、どのテーブルにどのcaseのどのevidenceが入っているかを別テーブルで管理する
- 【v0.3変更】**複数 Evidence の同時受付**: 1 ケースに対して複数 Evidence を一度に
  指定可能。orchestrator は Evidence ごとに完全なパースサイクルを回し、全
  Evidence の完了を待ってから Tier 1 に進む。1 Evidence の失敗は他に波及させない
  (graceful degradation)。
- 【v0.3変更】**Washizukami-Collector 形式対応**: 入力 zip / dir のディレクトリ
  構造として `Washizukami-Collector` (https://github.com/tadmaddad/Washizukami-Collector)
  の出力を一級サポート。検出ルールに専用パスパターンを追加。
- 【v0.4変更 (REQ-1)】**ネスト アーカイブの再帰展開**: ステージ済みルート配下に
  含まれる `*.zip` / `*.7z` / `*.tar` / `*.tar.gz` / `*.tar.bz2` / `*.tar.xz` /
  `*.gz` を、上限(`max_depth`/`max_total_bytes`/`compression_ratio_cap` 等)
  に従って再帰展開する。展開先は `workspace/extracted/__nested__/<sha>/`。
  パストラバーサル・bomb・暗号化は事前バリデートして skip し、各操作は
  `actions.jsonl` に `type:"nested_extract"` + `format` で記録。
  `.7z` は `py7zr` を新規依存として追加、未 import 時は graceful skip。
  詳細は冒頭の「v0.4 追加要件」→ REQ-1 を参照。
- 【v0.6 Wave 20h 変更】**artifact-scoped 分析 (関連 tactic だけ + artifact prefilter)**:
  「特定 artifact (例: amcache) だけを深掘り LLM 分析したい」UX 要望に応える。
  `agents.TacticsForArtifact(artifactID)` で `TacticRegistry` の OR-clauses を
  走査し、`artifact_id = '<id>'` を含む tactic だけを抽出 (timeline_review 除外)。
  `agents.Config.ArtifactScope` を非空にすると `queryEventsForTactic` の SQL
  prefilter が `... AND artifact_id = ?` で絞り込まれ、LLM は対象 artifact の
  event だけを見る。`TacticReport.ArtifactScope` で scope を stamp、findings は
  `findings/by-artifact/<artifact>/<tactic>.json` に保存して既存の
  `findings/<tactic>.json` (full-case) を保持。新 endpoint
  `POST /api/cases/{id}/analyze/artifact/{artifact_id}` + Events タブの
  parse_results 表の「Analyze」列ボタンから発火。`JobStatus.subkind` は
  `"artifact=<id>"` で記録。LLM コスト: 関連 tactic 数 × 1 run のみ (full
  Analyze All の 1/3 〜 1/5 程度の想定)。
- 【v0.6 Wave 20d-3 変更】**orchestrator exit_status を artifact-level に基づくよう修正**:
  Wave 18c の `_merge_parse_results` で per-user/per-hive detection の partial-success
  (any-success) が artifact-level OK に格上げされた後でも、orchestrator `_main()`
  は `report.failed` (detection-level 集計、merge 前) を見て exit 2 を返していた。
  SRL-2018-V06 で OK 15 / NOT_PRESENT 2 / FAIL 0 達成にも関わらず exit 2 → CI
  false-positive が発生する。`OrchestratorReport` に `artifact_succeeded` /
  `artifact_failed` field を追加し、`run()` で `_merge_parse_results` を in-memory で
  再適用して artifact-level の failed 数を計算。`_main()` の exit code 判定を
  `report.artifact_failed == 0` に変更 (DB write なし、低リスク)。stdout summary は
  従来通り detection-level を表示し operator は個別 per-user の挙動を確認できる。
- 【v0.6 Wave 20d-2 変更】**hayabusa CSV timestamp を DuckDB 互換に正規化**:
  Hayabusa CSV は `chrono::DateTime` の default Display で `"YYYY-MM-DD HH:MM:SS.ms +00:00"`
  (時刻と offset の間に space) を出すが、DuckDB の timestamp parser は space を
  許容せず `ConversionException` を投げる。`_bulk_insert_unified_events` で 1 行でも
  fail するとバッチ全体が roll back され他 parser の event も全消失するため、影響
  範囲は orchestrator 全体に波及する。`parsers/hayabusa_parser.py::_normalise_hayabusa_ts(ts)`
  を新設、正規表現 `r"\s+([+-]\d{2}:?\d{2})$"` で末尾の space + offset を offset 単独に
  置換、`_convert()` で row の Timestamp を取った直後に適用。payload 側の raw 値は
  そのまま保持 (debugging visibility)。
- 【v0.6 Wave 20b 変更】**LLM 実測メトリクスを Audit に追加 (per_event_sec 再キャリブ基盤)**:
  Wave 20a の `(events × per_event_sec=5s) + buffer=300s` 式は経験則で、実測値
  から再回帰キャリブできるよう `internal/agents/schemas.go::Audit` に 3 field
  追加 (すべて `omitempty`): **PromptSizeChars** (skill + userMsg + correction
  context + feedback の最大文字数。iter ごとに feedback が累積するため最終 iter
  を上限と見なす)、**MaxEvents** (`r.cfg.MaxEvents` の prefilter 上限。既存
  `InputEvents` は実 window サイズで MaxEvents 以下)、**DurationAPIMS**
  (claude-code の `duration_api_ms` から populate、Anthropic SDK は 0 のまま)。
  `EngineResponse` に `DurationAPIMS` を plumb、`Runner.Run()` の iter loop で
  prompt 上限を tracking、success / fail 両 path で Audit に write。既存
  findings.json への侵襲ゼロ、後ほど `(DurationSec, InputEvents, PromptSizeChars,
  CacheHitTok)` を回帰式に投入して per_event_sec を実測ベースに再キャリブする
  ための data 蓄積を開始する。
- 【v0.6 Wave 20d 変更】**image_extractor を hive transaction logs + NTFS ADS sparse 対応に拡張**:
  EZ Tools のうち AmcacheParser / AppCompatCacheParser は registry hive が dirty
  かつ同 dir に `.LOG1`/`.LOG2` が無いと parse を abort する厳格仕様
  (RECmd は許容するため SRL-2018 では registry OK / amcache + shimcache FAIL の
  非対称が発生し気付きにくかった)。**triage list の拡張**: 全 system hive
  (`SYSTEM/SOFTWARE/SECURITY/SAM/DEFAULT`) と `Amcache.hve` および per-user
  (`NTUSER.DAT/UsrClass.dat`) について `.LOG1`/`.LOG2` sibling を triage に追加。
  **$UsnJrnl:$J Alternate Data Stream の正しい抽出**: TSK の `ifind -n 'path:adsname'`
  は ADS suffix を silent strip して file inum のみ返すため、続く
  `icat <inum>` は file の default `$DATA` (= $UsnJrnl の場合 32 byte の $Max
  metadata stream) を返してしまい MFTECmd が `File type: Unknown` で abort する。
  `_extract_one` で path に `:` を含む場合は専用ブランチに分岐 →
  `_resolve_ads(raw, off, inum, ads_name)` が `istat <inum>` の attribute table を
  regex で parse して `<inum>-128-<attr_id>` spec を返す → `_icat_to_file_sparse`
  で 64 KiB block 単位の sparse-aware writer (zero block は `seek(SEEK_CUR)` で
  書き込まない、SHA-256 は full stream に対して計算) を介して抽出。
  $J は 9 GB 非常駐 sparse でも on-disk 37 MB (sparse ratio 0.43%) で staging 可。
  この変更で SRL-2018-V05 の amcache / shimcache / usn_journal の 3 FAIL が
  解消、MFTECmd で 428,275 USN entries 抽出に成功。
- 【v0.6 Wave 20d 変更】**parser 個別の dispatch / CLI フラグ修正**:
  altpf が稀に 131072 char 超の `FilesAccessed` 列を出力するため
  `parsers/prefetch_parser.py` の module load 時に `csv.field_size_limit(sys.maxsize)`
  を設定 (これが無いと `_csv.Error` が orchestrator の exception 経路に流れて
  rc=None / stderr 空のままパーサ全体が失敗)。Hayabusa v2 以降の `csv-timeline`
  は default で対話 Scan Wizard を起動し、stdin が pipe (subprocess) だと
  `IO(NotConnected) "not a terminal"` で panic exit 101 となるため、
  cmd vector に `--no-wizard` (a.k.a. `-w`) フラグを追加。
- 【v0.6 Wave 20a 変更】**LLM 呼び出しの動的 wall-clock budget**:
  各 Tactic Agent / anomaly_hunter / synthesizer corrector / timeline reviewer の
  timeout を従来 10-20 分の固定値から `internal/agents/timeouts.go::ComputeTimeout(tactic, maxEvents)`
  で動的計算するように変更。線形式 `(events × per_event_sec) + buffer`、clamp
  `[floor, ceiling]`、anomaly_hunter は 1.5× multiplier (6 lens + 既存 findings 全要約)。
  全 5 つの knob を環境変数 (`FINDEVIL_LLM_TIMEOUT_PER_EVENT_SEC` / `BUFFER_SEC` /
  `FLOOR_SEC` / `CEILING_SEC` / `ANOMALY_MULT`) で上書き可能、不正値は default
  fallback。CLI `--timeout-seconds 0` で auto-compute、explicit 指定で bypass。
  `--dry-run` 出力に `wall_clock_budget` を表示して operator が事前検証可能。
- 【v0.6 Wave 19 変更】**LLM タイムアウト 10m → 20m、MaxEvents 200 → 100**:
  SRL-2018 (16 GB E01) を Web UI から Analyze All した際、anomaly_hunter が
  ~100-200 KB の長文プロンプト (200 events × 6 lens + 既存 findings 要約) を捌けず
  10 分 timeout で SIGKILL される事象が発生。10 Tactic Agent も symmetric risk が
  あるため全 LLM 経路を対称に拡張 (Wave 20a で更に動的化)。
- 【v0.6 Wave 18 変更】**image_extractor の dir-mode triage 完全修復**:
  Wave 8 から無自覚に壊れていた 3 つのバグを修正 (`_is_directory` が istat line 0
  のみ判定で常に False、`fls` に path を渡していて inum を期待する API と不整合、
  `_list_dir` の regex が path 含み出力に non-match)。同時に triage label を friendly
  名 (`scheduled_tasks/dir`) → NTFS source path 保持 (`Windows/System32/Tasks`) に
  統一し、orchestrator の glob detector (`**/System32/Tasks/**` 等) が staging tree
  上で自然に一致するように。`$Recycle.Bin` を system triage に、
  `AppData/Local/ConnectedDevicesPlatform` を per-user triage に追加。
  parser dispatch 例外時の `started_at=""` で persist 中断する副次バグも修正
  (現在は `now_iso_utc()` で生成し、`_upsert_parse_result` でも空文字防御変換)。
- 【v0.6 Wave 18c 変更】**`_merge_parse_results` を partial-success policy に**:
  per-user artifact (jumplists / shellbags / registry / lnk / browser_history) で
  「1 user で Recent 空 / hive 無し → fail() で merged 全体 FAIL」を「any-success
  で OK 化 (exit_code=0 正規化、failed user は notes に列挙)」に変更。Examiner が
  notes で「どの user に何が無かったか」を一目で追跡可能。
- 【v0.6 Wave 16 変更】**evidence テーブルの主キーを `(case_id, evidence_id)` 複合 PK に変更**:
  以前は `evidence_id` 単独 PK で、同じ triage zip を 2 ケースで同じ evidence_id を
  使って parse すると 2 回目の `INSERT INTO evidence` が PK 違反で **silent fail**
  していた (`handlers.go::parseOneEvidence` で error を `_` 捨て)。これにより
  Analyze All 時の `evidence` テーブル空チェック (`allEvidenceIDs`) で「`case "X"
  has no registered evidence; run parse first`」エラーが発生していた。Wave 16 で
  schema を複合 PK に変更し、`internal/casedb/manager.go::migrateEvidencePK()` で
  旧 DB (v0) を起動時に自動 in-place 移行する (`PRAGMA table_info` で PK 列を
  検出 → 単独 PK なら ALTER RENAME + CREATE 新スキーマ + INSERT COPY + DROP)。
  併せて `handlers.go` の `RegisterEvidence` 戻り値 error を握りつぶさず parse の
  失敗として表面化、UI 側 `pollPipeline()` も case 切替時に **全 interval を
  clearInterval** することでケース間のステータス混線を解消。
- 【v0.6 Wave 15 変更】**prefix-tolerant detector + 実装済 17 種の必須試行**:
  TANAKA / KAPE-NTFS bundled / FastIR 等の collector は tree を flatten し、
  ファイル名に `<drive>_` (例: `C_$MFT`) または `<user>_` (例: `Tanaka_NTUSER.dat`,
  `Tanaka_Default_History`) の token を prepend する。orchestrator はこれを
  `parsers/_collector_prefix.py` の 6 個の basename regex で吸収する
  (MFT / USN / NTUSER / UsrClass / Chromium History / Firefox places.sqlite)。
  さらに `config/artifacts.yaml` に登録された **実装済 17 種すべて** を毎ケース
  必ず判定し、入力に該当アーティファクトが見つからない場合は parse_results
  に sentinel `command="(not present in input)"` の行を追加する (parser は
  invoke しない、`exit_code=NULL` / `row_count=0`)。actions.jsonl にも
  `kind="skip"` / `reason="not_present_in_input"` で記録。これにより
  Review Gate 0 (Web UI Events タブの Parse Results) で「OK / EMPTY /
  NOT_PRESENT / FAIL」の 4 ステータスが常に揃って表示され、ユーザは
  「parser バグ」「収集対象外」「実装漏れ」を即座に判別できる。

### 4.2 統一イベントモデル

【変更】Plasoのカラム構造に準拠してタイムライン構築に使用する。レジストリパスのカラムを追加。case_id・evidence_id・timezoneを追加。

```python
class UnifiedEvent:
    event_id: str              # UUID
    case_id: str               # 【変更】ケース番号
    evidence_id: str           # 【変更】エビデンス番号
    timestamp: datetime        # UTC
    timestamp_source: str      # "actual" | "inferred" | "filesystem"
    display_timezone: str      # 【変更】ユーザー指定タイムゾーン (例: "Asia/Tokyo")
    source_artifact: str       # "evtx", "prefetch", "amcache", ...
    source_path: str           # 元ファイルパス
    target_registry: str | None # 【変更】対象レジストリパス
    event_type: str            # アーティファクト固有（例: "process_execution"）
    host: str | None
    user: str | None
    process: str | None
    target: str | None         # 対象ファイル/レジストリキー等
    raw: dict                  # アーティファクト固有の生データ
    # 【v0.3変更】tactic_hints / technique_hints は削除。理由:
    #   パース時点で ATT&CK ラベルを付けると、ラベリングルール外の
    #   未知の攻撃痕跡を Tier 1 が拾えなくなるリスクが高い。
    #   Tier 1 は SQL prefilter (artifact / Event ID / payload LIKE) で
    #   関連イベントを取り、最終判断は LLM 側で行う。
```

【v0.3変更】**未知攻撃の取りこぼし防止**: パース時点での ATT&CK 紐付け
(`tactic_hints` / `technique_hints`) は **行わない**。代わりに Tier 1 の
prefilter ロジック(`internal/agents/tactic_queries.go::TacticRegistry`)で
対象 Tactic に関連しうる広めのイベント集合を抽出し、最終的な ATT&CK 帰属は
LLM が文脈ごと判断する。これにより、ラベリングルール未知の手口でも
findings として残る余地を残す。

### 4.3 アーティファクト優先順位

23種を全部Phase 2で書くのは現実的でないため、優先度3階層で管理。

【変更】アーティファクトごとに使用するツールを明記。Skillsに「このツールでこのアーティファクトをパースしてね」と記載し、エージェントが別ツールを使わないよう制約する。

**P0（MVPで必須・5種）**

| アーティファクト | 使用ツール | 補足 |
|---|---|---|
| Windows Event Logs (evtx) | EvtxECmd, Plaso (log2timeline.py) | CSV/JSON出力、タイムライン統合 |
| Amcache | AmcacheParser | 実行ファイルのハッシュ取得 |
| Prefetch | **Plaso (`log2timeline.py --parsers prefetch`)** + PECmd opt-in fallback | 【v0.4変更 #17】SIFT 標準には PECmd が同梱されていないため、Plaso を **primary** に変更。PECmd は `/opt/zimmermantools/PECmd.dll` が存在する開発機でのみ fallback として動作。プログラム実行時刻の証拠 |
| Registry | RECmd, RegRipper | 永続化メカニズム・ユーザー活動 |
| Scheduled Task XML | MFTECmd, Plaso, reg | タスク登録・実行履歴（Skills記載） |

**P1（MVP+で対応・7種)** ※【v0.3変更】ブラウザ履歴を追加

| アーティファクト | 使用ツール | 補足 |
|---|---|---|
| Shimcache | AppCompatCacheParser | 実行プログラム履歴 |
| MFT / USN Journal | MFTECmd | NTFSタイムライン・変更履歴 |
| Shellbags | SBECmd | フォルダアクセス履歴 |
| Jumplists | JLECmd | 最近アクセスしたファイル・アプリ |
| LNK Files | LECmd | ショートカットファイルのメタデータ |
| Recycle Bin | RBCmd, Rifiuti | 削除ファイルの元名・削除日時 |
| **【v0.3変更】Browser History** | SQLECmd / browser-history Python lib | Chrome / Edge / Firefox の履歴 SQLite。Web 経由攻撃(URL ドライブバイ・フィッシング遷移)の起点を追跡できる |

**P2（時間あれば）**

| アーティファクト | 使用ツール | 補足 |
|---|---|---|
| Timeline (Win10/11) | WxTCmd | アクティビティ履歴 |
| Volatility 3 memory forensics | Volatility 3 (vol.py) | プロセス・ネットワーク・注入コード |
| W3C (IIS, Firewall等) | Plaso, EvtxECmd | Webサーバーログ・FWログ |
| Windows Defender MPLog | EvtxECmd | マルウェア検知・対応履歴 |
| Windows Error Reporting | Plaso | クラッシュ報告・不審動作追跡 |
| PowerShell transcripts | Siftgrab, Plaso | PowerShellコマンド全記録 |
| SSH auth logs | Plaso, grep | ログイン試行・不正アクセス |
| SRUM | SrumECmd | アプリごとのネットワーク/CPU使用量 |
| UserAssist | RECmd | プログラム実行回数・最終実行日時 |
| JSON/JSONL (Suricata等) | Plaso, jq | フィルタリング・加工 |
| Delimited logs (CSV, TSV等) | psort.py, Timeline Explorer | タイムライン整理・分析 |
| Apache/Nginx logs | Plaso, grep/awk | タイムライン化・抽出 |

### 4.4 MCP 関数カタログ

【変更】原案として、まず Protocol SIFT の関数をベースに構築する。具体的なツール指定はSkillsに記載する方針。

execute_shell は **絶対に提供しない**。これが審査基準#4 Constraint Implementation の核です。提供するのは型付きクエリ関数のみ:

| 関数 | 用途 | 戻り値 |
|---|---|---|
| case.get_metadata() | ケースID、対象ホスト、評価期間、【変更】timezone | dict |
| events.query(tactic, time_range, event_types, limit) | 統一イベント検索 | list[UnifiedEvent] |
| events.timeline(time_range, host) | 時系列イベント | list[UnifiedEvent] |
| evtx.get_logon_events(time_range, logon_types) | 4624/4625 等 | list |
| registry.get_run_keys(hive) | 自動起動キー | list |
| registry.get_value(hive, key, value) | 特定値取得 | dict |
| scheduled_tasks.list(filter) | スケジュールタスク一覧 | list |
| prefetch.get_executions(executable_name) | 実行履歴 | list |
| amcache.get_entries(filter) | 実行記録 | list |
| mft.find_files(path_pattern, time_range) | MFTでのファイル検索 | list |
| process.tree(host, time_range) | プロセスツリー再構築 | tree |
| mitre.get_technique_md(technique_id) | RAG: Techniques md取得 | str |
| mitre.search_techniques(tactic, keywords) | RAG: 関連 Techniques 検索 | list |
| 【変更】parser.get_command_log(evidence_id) | パーサの実行コマンド・引数・結果取得 | list |
| 【変更】parser.get_raw_output(evidence_id, artifact) | オリジナルパース結果の取得 | str |
| 【変更】review.get_pending(gate_id) | レビュー待ちアイテム一覧 | list |
| 【変更】review.approve(item_id) | レビュー承認 | bool |
| 【変更】review.reject(item_id, reason) | レビュー拒否 | bool |
| 【v0.3変更】events.by_ttp(tactic_id, technique_id, time_range, evidence_ids) | **TTP 起点**で関連イベントを取得。Tactic / Technique を指定すると、内部マッピングで適切な artifact / Event ID / payload pattern を選んで横断検索 | list[UnifiedEvent] |
| 【v0.3変更】mitre.required_artifacts(technique_id) | Technique を解析するのに必要な artifact 種別と取得関数を返す | list[{artifact, suggested_fn}] |
| 【v0.3変更】correlation.cross_evidence(event_ids, time_window_seconds) | 複数 Evidence にまたがる相関(同一 IP からの 2 ホストへのログオン等)を検出 | list[CorrelationCluster] |

【v0.3変更】**Protocol SIFT 拡張方針**: 当初案の汎用クエリ関数群に対して、 Tactic Agent の現実的な使い方を踏まえた **TTP ベース API** を追加する。Tactic Agent は「自分が担当する TA000X / T1XXX に必要なアーティファクト一式」を 1 リクエストで取得でき、関数を順に呼び続ける iter 数を削減できる。

各関数のスキーマ(入出力)を厳格に定義することで、Claude Code 側の hallucination を構造的に抑制できます。

---

## 5. Tier 1 詳細設計 — Tactic Agents

### 5.1 起動方式

Claude Code の **Task ツール（subagent）** で各 Tactic Agent を並列起動します。Phase 0 で Claude Code subagent の仕様確認が必須です。

```python
# 概念コード — 【v0.3変更】case_id + evidence_ids 両方を受け取る
async def run_tier1(case_id, evidence_ids: list[str]):
    # Evidence 単位 × Tactic 単位の 2 次元並列。Evidence 間の相関は
    # Tier 2 (cross_evidence) で取るため、Tier 1 では各 (evidence × tactic)
    # を独立に実行する。
    tasks = []
    for ev_id in evidence_ids:
        for tactic in ["initial_access", "execution", "persistence", ...]:
            tasks.append(run_tactic_agent(tactic, case_id, ev_id))
    reports = await asyncio.gather(*tasks, return_exceptions=True)
    return reports
```

【v0.3変更】**`case_id + evidence_id` 両方の認識が必須**: 単一 Evidence しか
扱わないと、後から Evidence が追加された場合の差分実行や、Evidence 間の
相関分析(同一 IP・同一アカウントの cross-host 痕跡)ができない。
runner / Web UI / CLI のすべてで `evidence_ids` をリストとして受け取り、
1 件のみ指定された場合は従来動作と互換にする。

return_exceptions=True は **graceful degradation** のため。1エージェントが失敗してもケース全体は完走させます。失敗は最終レポートに「未実行」として明示。

【変更】Tier 1 の処理後に、人間が TacticReport とその根拠となるオリジナルログをレビューできる **Review Gate 1** を設ける。許可されたものだけが次の Tier に進む。skip（すべて許可）機能あり。UIは Valhuntir (https://github.com/AppliedIR/Valhuntir) を参考にする。

### 5.2 各エージェントへの入力

各 Tactic Agent には以下を与えます:

- **Static**: Skills（Tactic固有のsystem prompt）、出力JSONスキーマ、思考プロセス指示
- **Per-case**: case_id、【変更】evidence_id、対象期間、host情報、【変更】timezone
- **Tool access**: MCP関数のサブセット（Tactic に必要なものだけ）
- **RAG hint**: 担当 Tactic の _index.md（Techniques 一覧 + 概要）
- **上限設定（caps）**: max_iterations=3, max_tokens=50,000
  - 【変更】caps = 上限設定。エージェントの暴走を防ぐための最大繰り返し回数・トークン上限等の安全装置
- 【v0.3変更】**スライドウィンドウ方式**: 関連すると判断したアーティファクト
  全件を1度に LLM に渡すと、コンテキスト溢れで前後の繋がりが失われる
  / 飛ばし読みされる(精度低下)。各 Tactic Agent はイベントを時刻順に並べ、
  N 件(例: 200 件)単位のウィンドウで回し、各ウィンドウから出た findings を
  最終マージする。ウィンドウ間で重複した audit_id はマージ、隣接ウィンドウ
  境界に跨る攻撃チェーンの取りこぼしを防ぐためウィンドウは 20% オーバーラップ。

ツールアクセスを **サブセットに絞る** ことで、エージェントが本来見るべきでないアーティファクトに迷い込むのを防ぎます。これも architectural guardrail。

### 5.3 Skills 構造（system prompt）

```markdown
# あなたの役割
あなたは MITRE ATT&CK の {tactic_name} ({tactic_id}) を担当する専門 IR アナリストです。

# 思考プロセス（必ず守ること）
1. mitre.get_technique_md() で担当 Tactic の Techniques 一覧を取得
2. 関連性の高い Techniques を3〜5個選定
3. 各 Technique について、対応するアーティファクトを events.query() 等で確認
4. 痕跡が見つかった場合: finding として記録（evidence, confidence, reasoning）
5. 痕跡がなかった場合: negative_finding として「ここを見て無かった」を明記
6. 全ての主張は MCP 関数の戻り値に基づくこと。推測は禁止

# 出力（必ずこの JSON スキーマで返すこと）
{schema}

# 制約
- max_iterations: {max_iter}
- 不明な場合は confidence="low" として記録、推測で断定しない
- evidence には必ず source_artifact と event_id を含める
```

【変更】ステップ2「関連性の高い Techniques を3〜5個選定」について: 並列実行のため1個でも機能するが、関連性の高い Techniques をまとめることでコンテキスト内での相互参照効果が期待できる。この数はベースライン観察結果に基づいて調整する。

### 5.4 TacticReport スキーマ

```json
{
  "tactic_id": "TA0003",
  "tactic_name": "Persistence",
  "case_id": "INC-2026-001",
  "evidence_id": "EV-001",
  "started_at": "2026-04-25T...",
  "finished_at": "2026-04-25T...",
  "status": "completed | partial | failed",
  "findings": [
    {
      "finding_id": "uuid",
      "technique_id": "T1547.001",
      "technique_name": "Registry Run Keys / Startup Folder",
      "summary": "短い要約",
      "confidence": "high | medium | low",
      "evidence": [
        {
          "source_artifact": "registry",
          "event_id": "uuid (UnifiedEventのID)",
          "excerpt": "key=..., value=..."
        }
      ],
      "reasoning": "なぜこの finding に至ったかの推論"
    }
  ],
  "negative_findings": [
    {
      "technique_id": "T1547.005",
      "checked_via": ["registry.get_run_keys()", "events.query(...)"],
      "rationale": "確認したが該当エントリ無し"
    }
  ],
  "audit": {
    "iterations": 2,
    "tokens_used": 23150,
    "tool_calls": [
      {"tool": "registry.get_run_keys", "args": {}, "ts": "...", "trace_id": "..."}
    ]
  }
}
```

negative_findings は **Tier 2 の整合性チェックの基礎** になるので必須項目。

---

## 6. Tier 2 詳細設計 — Synthesizer

### 6.1 サブコンポーネント構成

Synthesizer は単一のエージェントではなく、4つのモジュールで構成します。

```
[Aggregator] → [ConsistencyChecker] → [TimelineBuilder] → [Corrector]
                                                              │
                                                  必要なら Tier 1 / Tier 2 を再起動
                                                  ※ Tier 0 パーサは対象外
```

【変更】矛盾発見時の再調査対象は Tier 1 と Tier 2 のみ。Tier 0 のパーサは正しく動いていれば結果は変わらないため対象外とする。

### 6.2 Aggregator（集約）

- 10個の TacticReport を受け取り、findings を全部マージ
- 重複排除（同じ evidence event_id を指す findings はマージ）
- ケースサマリ統計を生成（Tactic毎finding数、confidence分布等）

### 6.3 ConsistencyChecker（整合性チェック）

ルールベースで矛盾を検出。LLM ではなく **明示的ルール** にすることで、再現性と監査性を確保。

【変更】ルールの記述は日本語で作成し、内容を確認する。

【v0.3変更】**ツール全体の言語切替**: ルール文言・UI ラベル・レポートテンプレートを含めて、 ツール起動時に英 / 日 を選択可能にする。`config/i18n/<lang>.yaml` で文言一括管理し、Web UI のヘッダにも言語切替を出す。整合性ルール R1〜R4 の記述もこの仕組みに統合。

主要ルール例:
- **R1**: Defense Evasion で Event Log Clear (Event ID 1102) ありなのに、Lateral Movement / Credential Access の finding が極端に少ない → Event Log が消されて見えなくなっている可能性
- **R2**: Persistence finding ありなのに、Execution の痕跡（Prefetch/Amcache）が無い → 不整合
- **R3**: Lateral Movement で 4624 type 3 の流入ありなのに、流入元ホストでの Lateral Movement finding が無い（マルチホスト時）
- **R4**: Initial Access の特定時刻と、それ以前に Execution finding がある → 時系列矛盾

各ルールヒットは inconsistency レコードとして残し、Corrector に渡します。

### 6.4 TimelineBuilder

【変更】Plasoのカラム構造に準拠してタイムラインを構築する。

- 全 finding の evidence event_id を辿って UnifiedEvent を取得
- timestamp で時系列ソート（表示は display_timezone で変換）
- 連続イベントをクラスタリング（例:同一プロセスツリー内の event 群）
- Kill Chain 順での攻撃ステップ推定:
  - 最古の Initial Access finding を起点
  - 因果関係（プロセス起動連鎖、ログオン連鎖）で次の Tactic イベントへ繋ぐ
  - 各ステップを attack_step として連結

### 6.5 Corrector（自己修正ロジック）

inconsistency を受けて、該当 Tactic Agent を **再起動** します。

【変更】再調査対象は Tier 1 と Tier 2 のみ。Tier 0 パーサは再実行しない。

```
inconsistency 発見
    ↓
影響を受ける Tactic Agent を特定 (Tier 1 / Tier 2 のみ)
    ↓
追加コンテキスト（矛盾の詳細、再調査ヒント）を付与
    ↓
当該 Agent を再実行（max_correction_rounds = 1 で打ち切り）
    ↓
新 finding をマージ、不整合解消を確認
    ↓
解消できない場合は CaseSynthesis に「未解決の不整合」として残す
```

この**「未解決の不整合」を断定せずレポートに残す姿勢**こそが、審査基準#2 IR Accuracy で「幻覚を避ける」という評価につながります。

【変更】**Review Gate 2**: Tier 2 の処理後に、人間が Timeline とその根拠となるオリジナルログをレビューできる。一度許可されたものと同じものは、フラグや色で確認でき、フィルターアウトできる。許可されたものが次の Tier に進む。skip（すべて許可）機能あり。

【変更】**レビュー後の再探索**: Review Gate 2 通過後、Timeline をもとに未知の怪しいファイルや痕跡を再度探しに行く機能を設ける。発見分（許可タグがついていないもの）は Review Gate 1 に追加し、そこからやり直す。Tier 2 も同様。許可済みのものは識別・skip可能。（2周目はskip推奨）

### 6.6 CaseSynthesis スキーマ

```json
{
  "case_id": "INC-2026-001",
  "evidence_id": "EV-001",
  "timezone": "Asia/Tokyo",
  "executive_summary": "...",
  "intrusion_path": [
    {"step": 1, "tactic": "TA0001", "technique": "T1190", "timestamp": "...", "evidence_ids": [...]},
    {"step": 2, "tactic": "TA0002", "technique": "T1059.001", "timestamp": "...", "evidence_ids": [...]}
  ],
  "affected_scope": {
    "compromised_hosts": [...],
    "compromised_accounts": [...],
    "data_at_risk": [...]
  },
  "timeline": [
    {"timestamp": "...", "event_id": "...", "summary": "...", "tactic": "...", "technique": "..."}
  ],
  "findings_by_tactic": {},
  "inconsistencies": [
    {"rule": "R2", "description": "...", "resolved": true, "resolution": "..."}
  ],
  "recommendations": {
    "containment": [...],
    "eradication": [...],
    "recovery": [...],
    "next_steps": [
      // 【v0.3変更】今回のパース範囲では確認できなかった項目を、
      // 「次に何を調べるべきか」のアクションとして列挙する。
      // 例: 「F-collection-002 で言及された C:\Users\IEUser\AppData\
      //   Local\Temp\fubuki.exe の実ファイルが未取得。VirusTotal 照合
      //   とサンドボックス解析を推奨」
      // 例: 「Lateral Movement で 4624 type 3 の流入元 (10.x.x.x) に
      //   対応するホストの Evidence が未収集」
      // 例: 「Win10 Timeline DB が空のため、ユーザーアクティビティの
      //   検証はメモリイメージ取得 + Volatility 3 で補完を推奨」
    ]
  },
  "mitre_mapping": [
    {"tactic": "TA0003", "technique": "T1547.001", "evidence_count": 2, "confidence": "high"}
  ],
  "audit": {
    "total_tokens": 285000,
    "total_iterations": 14,
    "correction_rounds": 1,
    "execution_time_seconds": 1247
  },
  "timeline_review": { /* §6.7、optional */ }
}
```

### 6.7 TimelineReviewer (Tier 2 LLM パス、v0.5 追加)

ConsistencyChecker (R1–R4) は **構造的矛盾** を検出するが、**集約的な時系列の性質**(dwell time / off-hours クラスタ / バースト / LM 速度 / timestomp の痕跡 等)はルールで捕捉しきれない。TimelineReviewer は Synthesizer の最終段で起動する **任意の LLM パス** で、`skills/timeline_review.md` に書かれた **12 観点** を適用してタイムラインを論評する。

設計原則: **LLM の論評は補足、判定は引き続き Tier 1 + ConsistencyChecker の責務**。TimelineReviewer の `observations[]` は examiner-facing なヒントであり、自動アクション(Corrector の再起動等)には使わない。

#### 観点 12 種

| # | perspective | フォーカス | 主参照 |
|---|---|---|---|
| 1 | `kill_chain_order` | ATT&CK Tactic の逆順 (Execution が IA より早い等) | MITRE — Tactic は厳密順序ではないが、>1h の逆行は要観察 |
| 2 | `time_gap` | 隣接イベントの 24h / 7d 以上のギャップ | cyberengage.org: "gaps must be acknowledged" |
| 3 | `off_hours` | 業務外時間(22:00–06:00 + 休日)の活動クラスタ | Mandiant / Red Canary |
| 4 | `burst` | ≤5 分で ≥5 findings(自動化シグナル) | — |
| 5 | `velocity` | IA→Impact までの dwell time(<2h / 2–72h / 72h+) | Mandiant 2024: median 7d |
| 6 | `lateral_movement_speed` | ホスト間遷移の時間幅、<60s で複数ホップ | Red Canary WinRM/WMI 検知 |
| 7 | `execution_corroboration` | Execution finding に Prefetch / Amcache / Sysmon-1 / 4688 のうち何件が対応するか | SANS FOR508 |
| 8 | `persistence_dormancy` | Run キー作成後 7d 以内に対応する実行があるか | — |
| 9 | `defense_evasion_bookend` | Log clear (1102) の前後 ±24h での finding 状態 | ConsistencyChecker R1 と協調 |
| 10 | `anti_forensic` | `$SI` < `$FN`、ミリ秒が `.000000`、未来時刻 | MITRE T1070.006 / Magnet Forensics |
| 11 | `multi_host_correlation` | 複数ホストで同 technique 出現 / LM が期待される場面で host_count=1 | SANS "stitching" |
| 12 | `account_lifecycle` | 新規ローカルアカウント / サービス / タスク作成のタイミング異常 | Security 4720 / 7045 / 4698 |

#### 入力

```jsonc
{
  "case_id": "...",
  "evidence_ids": [...],
  "language": "ja",          // 出力プローズ言語
  "window": {"min":"...", "max":"...", "span_hours": 137.5},
  "host_count": 2,
  "hosts": [...],
  "tactics_observed": ["TA0001","TA0002","TA0003","TA0005"],
  "attack_steps": [...],        // ルールベース inferAttackSteps の結果
  "consistency_warnings": [...],// R1–R4 hits(参考情報)
  "top_findings": [...],        // confidence 順 ≤50 件
  "timeline_excerpt": [...]     // ts 昇順 ≤200 件
}
```

ペイロード上限: `MaxExcerpt=200` / `MaxFindings=50`(`config.TimelineReviewCfg` で上書き可)。LLM コンテキストを 50k token 以下に保つ目安。

#### 出力スキーマ

```jsonc
{
  "schema": "findevil/timeline-review/v1",
  "case_id": "...",
  "evidence_ids": [...],
  "language": "ja",
  "narrative": "<4–8 sentence のストーリーライン>",
  "observations": [
    {
      "observation_id": "TR-001",
      "perspective": "kill_chain_order|time_gap|off_hours|burst|velocity|lateral_movement_speed|execution_corroboration|persistence_dormancy|defense_evasion_bookend|anti_forensic|multi_host_correlation|account_lifecycle",
      "severity": "info|warning|critical",
      "summary": "...",
      "evidence_audit_ids": ["..."],
      "related_finding_ids": ["F-execution-002"],
      "related_tactic_ids": ["TA0002","TA0005"],
      "reasoning": "...",
      "next_step": "<optional>"
    }
  ],
  "open_questions": [...],
  "summary_stats": {
    "dwell_time_hours": 137.5,
    "host_count": 2,
    "tactics_observed_count": 4,
    "observations_by_severity": {"info":2,"warning":3,"critical":0}
  },
  "audit": {
    "engine": "claude-code",
    "model": "...",
    "input_tokens": 0, "output_tokens": 0,
    "duration_seconds": 0,
    "skill_file": "skills/timeline_review.md",
    "skipped_reason": "<set when LLM unavailable>",
    "phantom_audit_ids_dropped": 0
  }
}
```

#### 整合性保証

- **audit_id バリデーション**: LLM が幻覚した audit_id は Synthesizer 側 (`filterPhantomObservations`) で除去、`Audit.PhantomIDsDropped` にカウント
- **graceful**: スキル不在 / engine 初期化失敗 / JSON パース失敗 / LLM 呼び出し失敗 のいずれも、空 `observations[]` + `Audit.SkippedReason` を残して synthesis 自体は成功扱い

#### Review Gate との関係

Review Gate 2 (Timeline) は本機能の **承認用 UI** として位置付ける(未実装、Wave 8 候補)。観点が増えても本ドキュメントの DESIGN を変えず、`skills/timeline_review.md` に追記するだけで反映可能。

---

## 7. Tier 3 詳細設計 — Report Generator

### 7.1 出力フォーマット

| 形式 | 用途 | 構造 |
|---|---|---|
| **JSON** | 機械可読・他ツール連携 | CaseSynthesis をそのまま、または整形 |
| **CSV** | Splunk/Excel取り込み | findings.csv, timeline.csv, iocs.csv の3ファイルに分解 |
| **HTML** | 人間が読む最終レポート | テンプレート、目次・章構成・図表 |

【変更】レポートの言語は指定可能（日本語 / 英語）。

【v0.3変更】**レポート言語選択肢の拡大**: ja / en の 2 言語固定から、Claude が一般的なデータセットでカバーする主要言語(中・韓・西・仏・独・葡 等)を選択可能にする。実装上は `internal/reporter/dict_<lang>.go` を追加 + テンプレートが辞書キー参照になっているので、各言語の翻訳辞書を足すだけで増やせる。最終文章生成は LLM プロンプトの language 指定で対応。

### 7.2 HTML レポートの章構成

1. Executive Summary
2. Affected Scope（影響範囲）
3. Intrusion Path（侵入経路）— Kill Chain ダイアグラム
4. Timeline（攻撃の時系列）
5. Findings by Tactic（MITRE ATT&CK 順）
6. Inconsistencies & Open Questions（未解決事項）
7. Recommendations（Containment / Eradication / Recovery）
8. 【変更】IOC Summary（IOC一覧: ファイルハッシュ、不審ファイルパス、IP、ドメイン等）
9. MITRE ATT&CK Mapping（技術一覧）
10. Audit Trail（エージェント実行ログのサマリ）
11. Appendix:Evidence（全 evidence の詳細）

### 7.3 MITRE Mapper

mitre_mapping セクションは ATT&CK Navigator の JSON layer 形式でも出力できるようにすると、提出時のインパクトが大きいです（Stretch候補）。

---

## 8. 横断機能設計

### 8.1 設定管理 (config/)

YAML で集中管理。コードに数値を散らさない。

```yaml
# config/caps.yaml
tier1:
  max_iterations_per_agent: 3
  max_tokens_per_agent: 50000
  agent_timeout_seconds: 600
tier2:
  max_correction_rounds: 1
  consistency_rules_enabled: [R1, R2, R3, R4]
case:
  total_token_budget: 1000000
  total_timeout_seconds: 1800
```

```yaml
# config/tactics.yaml
agents:
  - id: persistence
    tactic_id: TA0003
    enabled: true
    mcp_tools_allowed:
      - registry.*
      - scheduled_tasks.*
      - events.query
      - mitre.*
    rag_path: rag/mitre_attack/tactics/TA0003_persistence/
```

【変更】レビューゲート設定:
```yaml
# config/review_gates.yaml
gates:
  gate_0:
    enabled: true
    auto_skip: false          # true にすると全自動
    skip_on_success: true     # パース成功のみ自動skip
  gate_1:
    enabled: true
    auto_skip: false
  gate_2:
    enabled: true
    auto_skip: false
```

### 8.2 ロギング・監査

- フォーマット:JSON Lines
- 保存先:outputs/{case_id}/audit_log.jsonl
- フィールド:timestamp, trace_id, tier, component, event, payload
- すべての MCP 関数呼び出し、エージェント起動/終了、LLMトークン使用、エラーをログに
- 【変更】MCPの先のパーサの実行コマンド・引数もログに記録する

trace_id は **finding まで逆引き可能** にする鍵。これが審査基準#5 Audit Trail Quality で満点を取るための核心です。

### 8.3 エラー処理方針（graceful degradation）

| 失敗箇所 | 対応 |
|---|---|
| アーティファクトパース失敗 | 該当だけスキップ、partial_data フラグ立てて続行 |
| Tactic Agent 失敗 | TacticReport に status="failed" 記録、ケース全体は続行 |
| Synthesizer 整合性ルール失敗 | 該当ルールだけスキップ、レポートに警告記載 |
| Tier 3 レンダリング失敗 | JSON はかならず出る、CSV/HTML は失敗してもJSON経由で復元可能 |

【変更】各レビューポイント（Review Gate 0/1/2）で、各失敗箇所をレビュー可能にする。失敗した箇所の詳細（エラーメッセージ、実行コマンド、標準出力）をUIで確認できる。

### 8.4 RAG 構築方針

rag/build_rag.py で MITRE 公式 STIX (mitre/cti リポジトリ)から自動生成。

【v0.3変更】**スコープを `enterprise-attack` に限定**: mitre/cti は ICS / Mobile / Pre-attack 等も含むが、本ツールの対象は Windows サーバー / クライアントの IR なので enterprise だけで十分。フェッチ対象を `https://github.com/mitre/cti/tree/master/enterprise-attack` のみに絞ることで、RAG サイズを 1/3 程度に圧縮できコンテキスト効率も向上する。

```
rag/mitre_attack/tactics/
├── TA0001_initial_access/
│   ├── _index.md           # Tactic概要 + Techniques一覧
│   ├── T1190.md            # 自動生成 (公式記述)
│   ├── T1190.windows.md    # 手書き (Windowsアーティファクト検出ロジック)
│   └── ...
```

*.windows.md は P0 アーティファクトでカバーできる優先 20〜30 Techniques に対してのみ手書き。これが独自性の源泉。

【変更】Valhuntir (https://github.com/AppliedIR/Valhuntir) のシグネチャベース系ルールを参考にする。Forensic RAG — Sigma、MITRE ATT&CK、LOLBAS、Atomic Red Team など23の信頼できる情報源から収集した22,000件以上のレコードを対象としたセマンティック検索を目指す。トレーニングデータではなく、信頼できる参考文献に基づいてLLM分析を実施する方針。

---

## 9. 実装スタック

| 層 | 推奨技術 | 理由 |
|---|---|---|
| 言語 | Python 3.11+ | DFIR ライブラリ豊富、Claude Code SDK |
| MCP | Anthropic公式 Python SDK | 公式サポート |
| DB | DuckDB | SPL経験者に親和性高、ファイル単一でポータブル、SQL強力 |
| パーサ | python-evtx, regipy, prefetch-parser, libregf-python | 実績ある OSS |
| HTML | Jinja2 | デファクト |
| CSV | pandas | 安定 |
| ロギング | structlog | 構造化ログ標準 |
| テスト | pytest + pytest-asyncio | 並列処理テスト対応 |
| パッケージ管理 | uv または poetry | uv 推奨（高速） |
