# Pipeline 詳細フロー — INPUT から最終レポートまで

本書は **「証拠を投入してから HTML/CSV/JSON レポートが出るまで内部で何が起きているか」**
を、実装コードに即して段階ごとに分解したリファレンスです。
設計理由 (WHY) は `docs/DESIGN.md`、
利用者向けの使い方は `docs/USER_GUIDE.md` / `docs/QUICKSTART.md` を参照してください。

凡例:
- **[GO]** Go 側実装 (`cmd/tlvb`, `internal/...`)
- **[PY]** Python 側実装 (`parsers/...`)
- **[LLM]** Claude が実際に推論する箇所
- **[Gate]** Human-in-the-loop の Review Gate
- **[DB]** DuckDB (`outputs/cases.duckdb`) への読み書き

---

## 0. 全体俯瞰

```
ユーザー入力 (zip / dir / E01 / VHDX / 個別 hive 等)
        │
        ▼
┌──────────────────────────── Tier 0 ─────────────────────────────┐
│ Stage 0-A  ケース/Evidence 登録           [GO]                   │
│ Stage 0-B  入力ステージング・整合性検証    [PY]                   │
│ Stage 0-C  ディスクイメージ展開           [PY] (条件付き)         │
│ Stage 0-D  ネスト アーカイブ再帰展開       [PY]                   │
│ Stage 0-E  Artifact 検出                  [PY]                   │
│ Stage 0-F  個別パーサ実行 (17 種)          [PY]                   │
│ Stage 0-G  統一イベント正規化              [PY]                   │
│ Stage 0-H  DuckDB 永続化                   [PY][DB]               │
│ Stage 0-I  parse_review.json 生成          [PY]                   │
└──────────────────────────────────────────────────────────────────┘
        │
        ▼
   ╔══ Review Gate 0 ══╗  parse 結果・コマンド・成否レビュー [Gate]
        │
        ▼
┌──────────────────────────── Tier 1 ─────────────────────────────┐
│ Stage 1-A  Tactic 単位の SQL Prefilter      [GO][DB]              │
│ Stage 1-B  EventWindow 構築 (200 件/window) [GO]                  │
│ Stage 1-C  Skill 読み込み + User Message    [GO]                  │
│ Stage 1-D  Tactic Agent 実行 (×10 並列)    [LLM]                  │
│ Stage 1-E  findings JSON 検証 + 永続化       [GO]                  │
│ Stage 1-F  Anomaly Hunter (Tier 1.5)        [LLM]                 │
└──────────────────────────────────────────────────────────────────┘
        │
        ▼
   ╔══ Review Gate 1 ══╗  findings レビュー [Gate]
        │
        ▼
┌──────────────────────────── Tier 2 ─────────────────────────────┐
│ Stage 2-A  Aggregator (重複排除・集約)        [GO]                │
│ Stage 2-B  ConsistencyChecker (R1〜R4)        [GO][DB]            │
│ Stage 2-C  TimelineBuilder + IntrusionPath    [GO][DB]            │
│ Stage 2-D  Corrector (再起動ループ)            [GO][LLM]          │
│ Stage 2-E  TimelineReviewer (12 観点)         [LLM] (任意)        │
│ Stage 2-F  CaseSynthesis JSON 生成             [GO]               │
└──────────────────────────────────────────────────────────────────┘
        │
        ▼
   ╔══ Review Gate 2 ══╗  timeline レビュー [Gate] (未実装)
        │
        ▼
┌──────────────────────────── Tier 3 ─────────────────────────────┐
│ Stage 3-A  Approved-only フィルタ             [GO]                │
│ Stage 3-B  JSON / CSV / HTML レンダリング      [GO]               │
│ Stage 3-C  IOC / MITRE Mapping 整形            [GO]               │
└──────────────────────────────────────────────────────────────────┘
        │
        ▼
   outputs/cases/<case_id>/reports/{report.json, findings.csv,
                                     timeline.csv, iocs.csv, report.html}
```

CLI と Web UI は同じ内部関数を呼びます (`cmd/tlvb/main.go` の `runParse` /
`runAnalyze` / `runSynthesize` / `runReport` ↔ `internal/web/handlers.go` の
`POST /api/cases/:id/parse` ほか)。違いはトリガと進捗の出し方だけです。

---

## Tier 0 — Parse (証拠を構造化する)

CLI: `tlvb parse --case <id> --evidence <id> --input <path>`
Web UI: ケース画面の `+ Add evidence` → Parse modal

### Stage 0-A. ケース/Evidence 登録 [GO]

- `internal/casedb/manager.go` が起動時に `outputs/cases.duckdb` を open。
  必要なら `migrateEvidencePK()` で旧 v0 スキーマ (`evidence_id` 単独 PK)
  を `(case_id, evidence_id)` 複合 PK に in-place 移行 (Wave 16)。
- `RegisterEvidence` が `case_id` / `evidence_id` / `timezone` / 入力パス /
  fingerprint (SHA-256 + size) を `evidence` テーブルに INSERT。
- `actions.jsonl` に `kind:"case_register"` / `kind:"evidence_register"`
  の監査行を追記。

### Stage 0-B. 入力ステージング・整合性検証 [PY]

`parsers/orchestrator.py::stage_input()`

1. 入力が `.zip` なら `zipfile` で `workspace/extracted/` に展開
   (CP932/UTF-8 順次フォールバック、シンボリックリンク・パストラバーサル拒否)。
2. 入力がディレクトリならコピーせず原本パスをそのまま `extractions_root` に。
3. 進捗イベント `{"type":"stage","phase":"extracting"}` を stderr に
   `PROGRESS|<json>` 行で emit (UI バーが受信)。

### Stage 0-C. ディスクイメージ展開 [PY] (条件付き)

`parsers/image_extractor.py`

`--input-mode=image` または `auto` で magic byte 判定が image を返した場合のみ起動。

- **E01 / Ex01**: `ewfmount` で raw を FUSE マウント → mmls でパーティション
  特定 → `fls` + `icat` で triage subset (Windows/System32/config,
  Windows/Prefetch, $MFT, $UsnJrnl:$J, NTUSER.DAT/UsrClass.dat per-user 等) を
  ステージング tree に抽出。
- **VHDX / VHD / VMDK**: `qemu-nbd` 経路 (sudo 要)。
- **`$UsnJrnl:$J` (NTFS ADS sparse stream)**: TSK の `ifind` は ADS suffix を
  silent strip するため、Wave 20d 以降 `_resolve_ads()` が `istat` の attribute
  table を regex parse → `<inum>-128-<attr_id>` spec → `_icat_to_file_sparse()`
  が 64KiB ブロック sparse-aware writer で抽出 (9GB stream を on-disk 37MB に圧縮)。
- 抽出後の staging dir が以降 Stage 0-D 以降の `input_path` になる。

### Stage 0-D. ネスト アーカイブ再帰展開 [PY] (REQ-1)

`parsers/_archive.py::extract_nested_recursively()`

- 対象: `.zip` / `.7z` / `.tar` / `.tar.gz` / `.tar.bz2` / `.tar.xz` / `.gz`
- 展開先: `workspace/extracted/__nested__/<sha256_short>/`
- 安全装置 (`config/staging.yaml` で集中管理):
  - `max_depth=4` / `max_total_extracted_bytes=50GiB`
  - `max_member_uncompressed_bytes=4GiB` / `compression_ratio_cap=200`
    (LZMA は 500)
  - パストラバーサル / シンボリックリンク / device メンバ / 暗号化 → skip
- 各操作は `actions.jsonl` に `type:"nested_extract"` + 結果コード で記録
  (`ok` / `skip:encrypted` / `skip:bomb_ratio` 等)。

### Stage 0-E. Artifact 検出 [PY]

`parsers/orchestrator.py::detect()`

- `_DETECTORS` (glob ルール表) と専用 pass (shellbags, lnk 等) で `*.evtx`,
  `$MFT`, `Amcache.hve`, `SYSTEM/SOFTWARE/SECURITY/SAM/DEFAULT`,
  `Prefetch/*.pf`, `NTUSER.DAT`, `Tasks/`, ブラウザ SQLite, ...を発見。
- `_collector_prefix.py` の 6 regex で TANAKA / KAPE-NTFS / FastIR が prepend
  する prefix (`C_$MFT`, `Tanaka_NTUSER.dat` 等) を吸収 (Wave 15)。
- 検出結果は `Detection(artifact_id, parser_module, input_path, mode)`
  リストとして返る。

### Stage 0-F. 個別パーサ実行 (17 種) [PY]

artifact_id ごとに対応する `parsers/<x>_parser.py::parse(req)` を呼ぶ。
入出力インターフェースは `parsers/base.py::ParseRequest` /
`ParseResult` で統一。各パーサは `_ezt_csv.py::run_simple_ezt()` を使う
~30 行の薄いラッパー (例外: prefetch, mft, image_extractor, browser_history)。

| Tier | artifact_id | 主要ツール / バックエンド |
|---|---|---|
| P0 | `evtx` | EvtxECmd (`dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll`) |
| P0 | `amcache` | AmcacheParser |
| P0 | `prefetch` | **altpf (`/opt/altpf/altpf`) primary** → Plaso `psteal.py` fallback (Wave 12) |
| P0 | `registry` | RECmd (+ Kroll_Batch.reb) |
| P0 | `scheduled_tasks` | Plaso `log2timeline.py --parsers winjob,winreg` + `psort.py` |
| P1 | `shimcache` | AppCompatCacheParser |
| P1 | `mft` | MFTECmd (`$MFT` 単体) |
| P1 | `usn_journal` | MFTECmd (`$J` mode) |
| P1 | `shellbags` | SBECmd (per-user) |
| P1 | `jumplists` | JLECmd (per-user) |
| P1 | `lnk` | LECmd |
| P1 | `recyclebin` | RBCmd |
| P1 | `win10timeline` | WxTCmd |
| P1 | `browser_history` | DuckDB から Python が SQLite を直接 read (Chrome/Edge/Firefox) |
| P2 | `srum` | SrumECmd |
| Opt | `hayabusa` | Hayabusa `csv-timeline --no-wizard` (Wave 20d) |
| Opt | `washizukami_audit` | Washizukami-Collector の付属メタ JSON |

実装上のポイント:
- 各パーサは **subprocess で外部ツールを起動 → CSV を読み込み → 統一 schema
  に正規化** という共通の流れ。
- 失敗しても例外を上に投げず `ParseResult(success=False, error=...)` を返す
  (graceful degradation)。
- `parse_results.started_at` / `finished_at` は `now_iso_utc()` で必ず埋める
  (空文字だと DuckDB の TIMESTAMP NOT NULL で bulk insert 全体が roll back する)。

### Stage 0-G. 統一イベント正規化 [PY]

`parsers/base.py::UnifiedEvent` のフィールドへマッピング:

```python
event_id            # UUID
case_id, evidence_id
timestamp           # UTC (ISO-8601)
timestamp_source    # "actual" | "inferred" | "filesystem"
display_timezone    # "Asia/Tokyo" 等、psort -z にも伝播
source_artifact     # "evtx" / "prefetch" / ...
source_path         # 元ファイルの相対パス
target_registry     # レジストリキーパス (任意)
event_type          # parser ごとに定義 ("process_execution" 等)
host, user, process, target
raw                 # parser 固有 dict (全カラム)
```

- Hayabusa CSV の timestamp `"YYYY-MM-DD HH:MM:SS.ms +00:00"` (space あり)
  は `_normalise_hayabusa_ts()` が末尾 ` +00:00` → `+00:00` に正規化
  (Wave 20d-2)。空白を残すと DuckDB の timestamp parser が
  `ConversionException` を投げ batch 全体が roll back する。
- `tactic_hints` / `technique_hints` 列は **持たない** (v0.3 で削除)。
  ラベリングは Tier 1 の SQL prefilter + LLM 判定に一元化。

### Stage 0-H. DuckDB 永続化 [DB]

`parsers/orchestrator.py::persist()` が 2 テーブルに書く:

- `parse_results`: artifact ごとに 1 行
  (artifact_id, command, exit_code, stderr_tail, started_at, duration_s,
  row_count, ...)。`_merge_parse_results()` が per-user/per-hive を
  any-success に昇格 (Wave 18c)。
- `unified_events`: 全イベント 1 行ずつ
  (`_bulk_insert_unified_events` で chunked insert)。

`exit code` 判定 (`OrchestratorReport.artifact_failed`) は merge 後の
artifact-level でカウント (Wave 20d-3)。

### Stage 0-I. parse_review.json 生成 [PY]

`workspace/parse_review.json` に Review Gate 0 用のサマリ:
artifact-level の `OK / EMPTY / NOT_PRESENT / FAIL` 4 ステータスと、各
artifact について最初に試みたコマンド・stderr 末尾・ネスト解凍ログを格納。
`detect()` が見つけなかった implemented artifact は
`not_present_results()` が sentinel 行 (`command="(not present in input)"`,
`exit_code=NULL`) を追加するので、UI は実装 17 種を必ず表示できる
(Wave 15)。

### 🟦 Review Gate 0 [Gate]

Web UI `Events タブ → Parse Results 表`。

- 各 artifact の **コマンド・stderr・row_count・duration** を確認
- 行クリックで raw CSV / JSONL を絞り込みダウンロード
- `config/review_gates.yaml::gates.gate_0.auto_skip=true` で全自動 skip。
- "Analyze All" modal の "Auto-pilot" チェックで Parse 完了と同時に
  Gate 0 を skip → Tier 1 へ自動遷移 (Issue #11/#12/#13)。

---

## Tier 1 — Analyze (Tactic Agent × 10 並列)

CLI: `tlvb analyze --case <id> [--tactic <slug>] [--evidence-id <id>]`
Web UI: ケース画面の "Analyze All" / Events タブの artifact 行 "Analyze" ボタン

### Stage 1-A. Tactic 単位の SQL Prefilter [GO][DB]

`internal/agents/tactic_queries.go::TacticRegistry` には 10 Tactic
(`initial_access` / `execution` / `persistence` / `privilege_escalation` /
`defense_evasion` / `credential_access` / `discovery` /
`lateral_movement` / `collection` / `impact`) の `OrClauses` (生 SQL)
が登録されている。例:

```sql
-- persistence の例
artifact_id='registry' AND target_registry LIKE '%\\Run%'
OR artifact_id='scheduled_tasks'
OR artifact_id='evtx' AND event_type IN ('4698','7045')
OR ...
```

`queryEventsForTactic(ctx, db, caseID, spec, maxEvents, artifactScope)` が
全 `OrClauses` を `OR` で連結 + `case_id=?` + (任意) `artifact_id=?` で
prefilter し、最古から最大 `MaxEvents=100` 件を返す。

artifact-scoped analyze (Wave 20h) は `agents.TacticsForArtifact(artifactID)`
で「その artifact_id を含む OR-clause を持つ tactic」だけに絞り、
さらに SQL prefilter にも `AND artifact_id = ?` を加える。

### Stage 1-B. EventWindow 構築 (200 件/window)

スライドウィンドウ (DESIGN §5.2 v0.3 変更): イベントを時刻昇順に並べ、
N 件 (現状 default) を 1 ウィンドウとし、隣接ウィンドウは 20%
オーバーラップ。`runner.go::Run` の iter ループで window を順次処理し、
findings は最後に audit_id をキーにマージ。

### Stage 1-C. Skill 読み込み + User Message [GO]

- `skills/<tactic_slug>.md` を `os.ReadFile` で読む (system prompt)。
- `buildUserMessage()` がテンプレ展開:

```text
You are analysing {tactic_name} ({tactic_id}) for case {case_id}
(evidence_ids={...}, window={min}..{max}, total_matching={N}).
Apply the methodology in your system prompt.
Below is the EventWindow JSON: ...
```

### Stage 1-D. Tactic Agent 実行 [LLM]

`internal/agents/engine.go::Engine` interface の実装は 2 つ:

- **`claude-code`** (default): `internal/agents/claude_code.go`
  ローカル `claude` CLI を `--print --output-format json` で起動 → JSON
  応答から `result` を抽出。`duration_api_ms` も pick up (Wave 20b)。
- **`anthropic-api`**: `internal/agents/anthropic.go`
  Anthropic Python SDK 経由で direct API 呼び出し。`ANTHROPIC_API_KEY` 必須。

`Runner.Run()` の iter ループ (最大 `max_iterations=3`):

1. system prompt + user message + (前 iter の) correction feedback を組み立て
2. Engine に投げる
3. 応答から JSON ブロックを抜き出し `TacticReport` に Unmarshal
4. 失敗時は feedback を補強して次 iter (例: "JSON 中の audit_id は実在
   する unified_events の event_id でなければならない")
5. 検証通過 or iter 上限で打ち切り

wall-clock budget は Wave 20a 以降 `ComputeTimeout(tactic, maxEvents)` で
`(events × per_event_sec) + buffer`、clamp `[floor, ceiling]`、
anomaly_hunter は 1.5×。環境変数 `TLVB_LLM_TIMEOUT_*` で上書き可能。

### Stage 1-E. findings JSON 検証 + 永続化 [GO]

`validateEvidence()` が finding 内 `evidence[].event_id` を実在する
unified_events と照合し、幻覚 ID は drop (Audit に
`PhantomIDsDropped` カウント)。

保存先:
- **full-case analyze**: `outputs/cases/<id>/findings/<tactic>.json`
- **artifact-scoped analyze** (Wave 20h): `outputs/cases/<id>/findings/by-artifact/<artifact>/<tactic>.json`

`TacticReport` には Wave 20b で `Audit.PromptSizeChars` / `MaxEvents` /
`DurationAPIMS` が追加され、`scripts/calibrate.py` 経由で
`per_event_sec` を実測ベースに再回帰できる。

### Stage 1-F. Anomaly Hunter (Tier 1.5) [LLM]

`internal/agents/anomaly_hunter.go::AnomalyHunter`

- 10 Tactic Agent 完了後 (Web UI なら自動連鎖、CLI なら
  `tlvb analyze --tactic anomaly_hunter`) に起動
- 既存 findings 全件を summary 化 + 6 レンズ (`buildAnomalyCandidates`):
  unusual_path / unusual_time / unusual_user / unusual_image_amcache /
  unusual_amcache_link_paths / unusual_image_evtx
- ATT&CK 既存カテゴリに収まらない異常を `Findings` として書き出し
  (`outputs/cases/<id>/findings/anomaly_hunter.json`)

### 🟧 Review Gate 1 [Gate]

Web UI `Findings タブ`。各 finding 行に Approve / Reject / Note 入力。

- 一括選択・絞り込み (tactic / confidence / artifact / search)
- "✕ cancel" で進行中ジョブを中断可能
- Approve した finding のみが Tier 2/3 に流れる
- `gate_1.auto_skip=true` または "Auto-pilot" で全 Approve 扱い
- 取り消し可能 (undo)

---

## Tier 2 — Synthesize (集約・整合性・タイムライン・自己修正)

CLI: `tlvb synthesize --case <id>`
Web UI: "Synthesize" ボタン

`internal/synthesizer/synthesizer.go::Synthesize(ctx, cfg)` が以下 8 ステップ
+ optional Corrector + optional TimelineReviewer を順次実行。

### Stage 2-A. Aggregator [GO]

`aggregator.go::Aggregate(caseID, findingsDir)`

- `findings/<tactic>.json` を全部読む (Approve 状態は別ファイル
  `findings/approvals.json` で管理、ここでは生 findings を集める)。
- 同じ `audit_id` (= 元 event_id) を指す findings をマージ。
- `Reports[]` (tactic ごとの TacticReport) と `Stats` (confidence 分布等) を返す。

### Stage 2-B. ConsistencyChecker (R1〜R4) [GO][DB]

`consistency.go::CheckConsistency(ctx, db, caseID, agg)`

明示的なルールベース (LLM 不使用):

| Rule | 検知内容 | severity |
|---|---|---|
| **R1** | Defense Evasion で Event ID 1102 (Log Clear) ありなのに LM/CredAccess finding が極端に少ない | warning |
| **R2** | Persistence finding ありなのに Execution の Prefetch/Amcache が無い | warning |
| **R3** | LM で 4624 type 3 の流入ありなのに、流入元ホストでの LM finding が無い | warning |
| **R4** | Initial Access の特定時刻より前に Execution finding がある (時系列矛盾) | warning |

ヒットは `Inconsistency{Rule, Severity, Description}` で返り、
Corrector の入力になる。

### Stage 2-C. TimelineBuilder + IntrusionPath [GO][DB]

`timeline.go::BuildTimeline(ctx, db, caseID, agg)`

1. 全 finding の `evidence[].event_id` から `unified_events` を SELECT
2. timestamp 昇順にソート (display_timezone で表示変換)
3. 連続イベントクラスタリング (同一 process tree 内など)
4. `inferAttackSteps()` で Kill Chain 順の `IntrusionPath[]` 推定
   (最古 IA finding を起点に因果連鎖)
5. `unresolved` = どこにも紐付けられなかった event_id リスト

### Stage 2-D. Corrector (再起動ループ) [GO][LLM]

`corrector.go::Correct(ctx, cfg, agg, inconsistencies)`

- 影響を受ける Tactic Agent を特定 (例: R2 → execution Agent を再起動)
- 「矛盾の詳細・再調査ヒント」を追加コンテキストとして渡し再実行
  (`max_correction_rounds=1` で打ち切り)
- 新 finding をマージ → ConsistencyChecker を再実行
- 解消できなければ `unresolved_rules` として CaseSynthesis に残す
  (断定はしない方針)

### Stage 2-E. TimelineReviewer [LLM] (任意・v0.5)

`timeline_review.go::ReviewTimeline(ctx, cfg, timeline, steps, inc, agg)`

- skill: `skills/timeline_review.md`
- 入力ペイロード上限: timeline_excerpt ≤200 件 / top_findings ≤50 件
- 12 観点 (kill_chain_order / time_gap / off_hours / burst / velocity /
  lateral_movement_speed / execution_corroboration / persistence_dormancy /
  defense_evasion_bookend / anti_forensic / multi_host_correlation /
  account_lifecycle) を当てて `observations[]` 出力
- 幻覚 audit_id は `filterPhantomObservations()` で除去
- LLM 失敗時は `observations=[]` + `Audit.SkippedReason` で graceful skip
  (synthesis 自体は成功扱い)

### Stage 2-F. CaseSynthesis JSON 生成 [GO]

`outputs/cases/<id>/synthesis.json` に書き出し。主要フィールド:

```jsonc
{
  "case_id", "evidence_id(s)", "timezone",
  "executive_summary",          // generateExecutiveSummary()
  "intrusion_path": [...],      // Kill Chain ステップ
  "affected_scope": { "compromised_hosts": [...] },
  "timeline": [...],            // 時系列クラスタ
  "findings_by_tactic": { ... },
  "inconsistencies": [...],
  "recommendations": {
      "containment": [...], "eradication": [...], "recovery": [...],
      "next_steps": [...]       // generateNextSteps()
  },
  "mitre_mapping": [...],
  "timeline_review": { ... },   // §6.7 結果 (任意)
  "audit": { "total_tokens", "total_iterations", "correction_rounds", ... },
  "failed_artifacts": [...]     // exit_code != 0 の parse_results
}
```

### 🟩 Review Gate 2 [Gate] (未実装)

Web UI Timeline タブ。設計のみで未実装。

---

## Tier 3 — Report

CLI: `tlvb report --case <id> --format html --language ja`
Web UI: "Generate Report" ボタン → 完了後ダウンロードリンク

`internal/reporter/renderer.go::Render(cfg)` が以下を実行。

### Stage 3-A. Approved-only フィルタ [GO]

`filterToApproved(cs)` が `findings/approvals.json` を読み、
Approve されていない finding を `findings_by_tactic` / `timeline` /
`intrusion_path` から除外。Gate を skip した場合は全件 Approve 扱い。

### Stage 3-B. JSON / CSV / HTML レンダリング [GO]

- **JSON** (`json_report.go`): `CaseSynthesis` を整形して 1 ファイルで出力
- **CSV** (`csv_report.go`): 3 ファイルに分解
  - `findings.csv`: tactic / technique / confidence / summary / audit_ids
  - `timeline.csv`: timestamp / host / artifact / summary / tactic / technique
  - `iocs.csv`: ハッシュ / パス / IP / ドメイン
- **HTML** (`html_report.go`): Go `html/template` で 11 章構成
  (Executive Summary / Affected Scope / Intrusion Path / Timeline /
  Findings by Tactic / Inconsistencies / Recommendations / IOC Summary /
  MITRE ATT&CK Mapping / Audit Trail / Appendix Evidence)。
  `dict(lang)` (`reporter/dict_ja.go` / `dict_en.go`) でラベル切替。

### Stage 3-C. IOC / MITRE Mapping 整形 [GO]

- IOC は timeline + findings の payload から hash/path/IP/domain を抽出して
  重複排除。
- MITRE Mapping は `buildMITREMapping(agg)` が tactic→technique→
  evidence_count を集計 (ATT&CK Navigator JSON layer 形式の出力は stretch)。

最終物:

```
outputs/cases/<case_id>/reports/
├── report.html
├── report.json
├── findings.csv
├── timeline.csv
└── iocs.csv
```

---

## 横断機能

### 監査ログ (`outputs/cases/<id>/actions.jsonl`)

各 stage の主要操作 (case 登録 / parse 起動 / parse 完了 /
nested_extract / analyze 起動 / approval / export / import) を JSONL で追記。
`trace_id` で finding まで逆引き可能。

### ジョブ管理 (`internal/web/jobs.go`)

Web UI からのトリガは `JobStatus(kind, subkind)` で管理:
- `kind`: `parse` / `analyze` / `synthesize` / `report`
- `subkind`: `tactic=<slug>` / `artifact=<id>` (Wave 20h) など
- `cancel` button で context cancel → 子プロセスに SIGTERM

### ケース可搬性 (`.fcz` tarball)

`tlvb case export --case <id> --out <case>.fcz`:
1. `parse_results` / `unified_events` を `case_id` でフィルタして JSONL dump
2. `findings/` / `reports/` / `workspace/` を tar に追加
3. 全ファイル SHA-256 を計算 → `manifest.json` に格納
4. tar.gz として固める

`tlvb case import --in <case>.fcz` は逆操作。SHA-256 一致しない場合は
abort (`--force` で続行可)。

### MCP (Tier 0 公開関数)

`internal/mcp/` が型付き read-only 関数を 10 個公開:
`case.get_metadata` / `events.query` / `events.timeline` /
`evtx.get_logon_events` / `registry.get_run_keys` / `registry.get_value` /
`scheduled_tasks.list` / `prefetch.get_executions` / `amcache.get_entries` /
`mitre.search_techniques`。**`execute_shell` は構造的に存在しない**
(原則 3 — Read-only by construction)。

Claude Code / Claude Desktop から本 MCP サーバを設定すれば、外部から
直接 finding / event / case をクエリできる。

---

## 関連ドキュメント

- 設計理由 (WHY): `docs/DESIGN.md` §1〜§9
- 使い方ガイド: `docs/USER_GUIDE.md` / `docs/QUICKSTART.md`
- パーサ・ツール検証結果: `docs/tool_inventory.md`
- テスト計画: `docs/TEST_*.md`
