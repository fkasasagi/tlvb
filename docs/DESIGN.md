# TLVB システム設計書 (v0.1)

**最終更新**: 2026-05-29
**ステータス**: **v0.1 主要パイプライン (a)-(g) 完走済**。
Tier 0 / 1A (build + runtime + Hayabusa pass-through) / 1B (MVP + 強化済 prefilter)
/ 2 (受動 + 能動 + lenient JSON parser + fallback) / 3 (HTML/CSV/JSON Reporter) すべて
動作確認済。残りは (d) Review UI と coverage 拡張のみ。詳細は `docs/STATUS.md`

## 0. 設計思想

TLVB は findevil(Windows フォレンジック自律 IR エージェント)の構造を引き継ぎつつ、
**「シグネチャ駆動 SQL + 抽象観察 + タイムライン解析」** の 3 層を明確に分離した
リエンジニア版である。findevil との根本的な差分:

| 観点 | findevil | TLVB |
|---|---|---|
| Tier 1 の単位 | 10 ATT&CK tactic に固定、tactic ごとに LLM が SQL を生成 | rule 単位、build 時に 1 度だけ LLM で SQL 化して cache |
| Runtime LLM コスト | 1 ケースあたり Tier 1 で 10 回呼ぶ | Tier 1A で 0 回。Tier 1B のみ |
| 検出ロジックの根拠 | skills/*.md の経験則 | Sigma / Hayabusa / ATT&CK STIX の公開ルール corpus |
| 後段の役割 | Tier 2 は受動的に findings を整合 | Tier 2 は能動的に wide-range SQL を生成して仮説検証 |

## 1. アーキテクチャ

```
INPUT (collector zip / disk image / live triage)
  ↓
Tier 0   Parser ×N (Python)
         → DuckDB cases.duckdb の unified_events に正規化
         ※ findevil から流用
  ↓
─────────────────── 【Build 時 (lazy, model/corpus 更新で増分)】 ────
  rules/sigma/upstream/**.yml         (git submodule)
  rules/hayabusa/upstream/hayabusa/** (git submodule, Hayabusa 独自分のみ)
  rules/stix/mitre-attack/**          (git submodule)
  rules/custom/**.yml                 (社内ルール)
        ↓  cmd/tlvb rules build  (Go + Anthropic Messages API)
  outputs/rules.duckdb の rule_sql_cache テーブル
     PK: (rule_id, rule_source)
     無効化キー: (rule_sha256, schema_version, model_id)
     cost guard: --dry-run / --budget-yen / --max-rules / 中断 resume
──────────────────────────────────────────────────────────────────
  ↓
Tier 1A  Signature-driven Runtime (★LLM ゼロ)
         cached SQL 実行 → hit = 即 finding
         → findings/by-rule/<rule_source>/<rule_id>.json
  ↓
Tier 1B  Skills-driven Anomaly
         skills/*.md (findevil 12 個流用) 由来の cached SQL 実行
         + 1A findings を context として LLM が抽象パターン推論
         + LLM が必要なら新 SQL 考案 → cache 追記 (LLM 自身が hit/新規判定)
         → findings/by-skill/<skill>.json
  ↓
Tier 2   Timeline Analysis Agent
         受動: findings cluster の ±N 分 raw timeline を LLM 分析
         能動: 仮説駆動 wide-range SQL で広域探索
         → synthesis.json (attack chain + 矛盾解消)
  ↓
Tier 3   Reporter (HTML / CSV / JSON, ja/en, findevil 流用)
```

## 2. Tier 0 — Parser 層 (findevil 流用)

17 アーティファクト + 5 skeleton。`parsers/orchestrator.py` がディスパッチ。
各パーサは Python サブプロセスで EZ Tools / Hayabusa / Plaso 等を呼び、
出力を **UnifiedEvent** (DuckDB の `unified_events` 8 カラム) に正規化。

スキーマは `internal/casedb/schema_doc.go::UnifiedEventsDDL`。詳細は `CLAUDE.md`
の「実装済みパッケージマップ」を参照。本 v0.1 で改修予定なし。

## 3. Tier 1A — Signature-driven SQL Agent

### 3.1 Rule corpus

`rules/` 配下に 4 ソース。memory / Sysmon 専用ルールはデフォルトで除外
(後日 sysmon EVTX が parse された case では自動有効化 — 詳細は 3.5)。

| Source | Submodule | 件数 | TLVB build 対象 |
|---|---|---:|---:|
| Sigma 公式 | SigmaHQ/sigma | 3132 | 599 |
| Hayabusa built-in | Yamato-Security/hayabusa-rules | 193 (hayabusa/ のみ) | 137 |
| ATT&CK STIX | mitre/cti | 858 (enterprise-attack/attack-pattern) | 474 |
| Custom | (社内) | 0 | 0 |
| **合計** | | **4183** | **1210** |

build 対象外の内訳:
- Sysmon 専用: 1913 件 (Sigma 1857 + Hayabusa 56)
- 非 Windows (Linux/macOS): 899 件
- Revoked: 149 件 (STIX)
- Deprecated: 12 件 (STIX)

### 3.2 Build パイプライン

実装: `internal/rulebuild/pipeline.go` + `internal/rulebuild/anthropic.go`
CLI: `tlvb rules build [--dry-run] [--budget-yen N] [--max-rules N] [--source S] [--force]`

build の流れ (1 ルールあたり):

```
rulesrepo Loader が RawRule を生成
    ↓
rulesdb.UpsertPending — (rule_sha256, schema_version, model_id) 整合チェック
    ├ signature 一致 + state=built → 何もしない (cache hit)
    └ signature 変化 or state≠built → state=pending にリセット
    ↓
LLM (Anthropic Sonnet 4.6) に rule YAML/JSON + SchemaDoc を渡す
    ↓
JSON 出力 {sql, prefilter_artifacts, notes} をパース
    ↓
SQL を validateSQL() で検証:
  - SELECT or WITH で始まること
  - INSERT/UPDATE/DELETE/DROP/CREATE/PRAGMA を含まないこと
  - 「case_id = ?」を含むこと
  - 末尾セミコロンを含まないこと
    ↓
合格: rulesdb.MarkBuilt(sql, prefilter_artifacts)
不合格 or LLM エラー: rulesdb.MarkFailed(err) — 次回 build で retry
```

### 3.3 Build cost guard

`--dry-run` で `(rules=N, est_input_tokens=M, est_cost_yen=Y)` を表示し、
実 API を呼ばずに規模を確認できる。

- `--budget-yen <N>`: 実コストが N 円を超えたら新規 LLM 呼び出しを停止。
  途中まで build 済みの行は cache に残るので、次回起動で続きから。
- `--max-rules <N>`: N 件で停止 (デバッグ用)。
- `--force`: signature 一致でも再 build。LLM プロンプトをチューニングしたとき用。

レート (デフォルト Sonnet 4.6 / 150 yen/USD):
- 入力: 450 yen / 1M token
- 出力: 2250 yen / 1M token
- Cache read: 45 yen / 1M token (prompt cache hit 分)

実機 dry-run: 1210 件 build で **est ~2011 yen (worst case)**。prompt-cache
で実コストは 30-60% 程度になる見込み。

### 3.4 Runtime

実装: `internal/tier1a/runner.go::Run`。

```
ケース C のロード時:
  1. rulesdb から state='built' な行を全件取得 (ListAll filter)
  2. 各行について:
     a. row.prefilter_artifacts が case の parse_results に含まれていなければ skip
     b. row.sql を `WHERE case_id = ?` の `?` に case_id を bind して実行
     c. 結果行が 1 件以上あれば finding 生成 (cap MaxEvidence 行)
  3. severity ベースで Review Gate 1A の auto-approve (medium 以下) / require-review
     (critical/high) を AutoApproveByLevel が振り分け
  4. 1 SQL のエラーで全体は止めない (graceful)
```

加えて **Hayabusa pass-through pass** (`internal/tier1a/hayabusa_passthrough.go`):
- Tier 0 で Hayabusa が事前検知した unified_events (`artifact_id='hayabusa'`) を
  RuleID でグループ化、rule_source="hayabusa" として findings 化
- 1 SQL クエリで全部取得 → ストリーミング処理 (cluster ごと 1 Finding)
- level info/low はデフォルト除外 (`--include-info-level` で opt-in)

CLI: `tlvb analyze CASE_ID --tier 1a [--skip-hayabusa-passthrough] [--include-info-level]`

finding スキーマ (実装後):
```json
{
  "finding_id": "<uuid>",
  "rule_id": "f239b326-2f41-4d6b-9dfa-c846a60ef505",
  "rule_source": "sigma",
  "rule_meta": {
    "title": "Password Dumper Remote Thread in LSASS",
    "level": "high",
    "mitre_techniques": ["T1003.001"]
  },
  "evidence": [
    {"audit_id": "abc...", "ts_utc": "2024-...", "artifact_id": "evtx", "event_type": "..."},
    ...
  ],
  "approved": false,
  "approved_by": "auto:severity-rule" | "examiner-name" | null,
  "reject_reason": null
}
```

### 3.5 Sysmon / メモリの後日有効化

ルール側で `requires_artifact: [sysmon_evtx]` メタを保存しておけば、
- Build 時: 含めて build (cache に置く)
- Runtime: Tier 0 の parse_results を見て、`sysmon_evtx` が無ければ skip

これにより「後日 Sysmon ありケースが来た」ときに再 build 不要で自動 ON。
v0.1 では sysmon を含めない方針 (CLI flag `--include-sysmon` で opt-in)。

## 4. Tier 1B — Skills-driven Anomaly Agent (MVP 実装済)

findevil の `skills/*.md` 12 個 (10 tactic + anomaly_hunter + timeline_review)
をそのまま流用。v0.1 MVP では skill 1 つ (`anomaly_hunter.md`) のみ active。

実装: `internal/tier1b/`(runner / prior / prefilter / types)

### 4.1 v0.1 MVP の Runtime

```
1. findings/by-rule/**/*.json から Tier 1A の prior findings を読み込む
   → 既存 audit_ids + key timestamps + (source, level) 集計を作る
2. unified_events を stratified サンプリング (per-artifact LIMIT、
   EVTX ノイズ EID 4656/4658/4663/4703/5152/5156/5158 等を SQL 除外)
3. 候補に 5 lens でスコアリング:
   A0 — artifact diversity boost (非 evtx へ +1〜+3)
   A1 — off-hours (h<6 or h>=22 UTC)
   A2 — suspicious path (Temp / AppData / Public / ProgramData)
   A4 — rare process (image_count < 3)
   A5 — adjacency (±30 min around prior finding timestamps)
4. top N (default 200) を skill prompt + AnomalyContext JSON と一緒に
   claude CLI に渡す
5. LLM が JSON 配列 [{lens, summary, description, severity, audit_ids,
   technique_id, tactic}, ...] を返す
6. findings/by-skill/anomaly_hunter.json に AnomalyReport として保存
```

CLI: `tlvb analyze CASE_ID --tier 1b [--dry-run] [--max-events N]
                                     [--include-info-level] [--model M]`

### 4.2 v0.2 で実装予定の Hybrid Cache

cache hit 判定は **LLM 自身**に任せる:
- cache 一覧 (skill / intent_summary / SQL fingerprint) を LLM に見せて
  「これを使う or 新規作る」を判断させる
- cache 肥大化したら RAG で事前絞り込み

build パイプラインも skill の canonical query 部分は Tier 1A と同じ
`rule_sql_cache` を再利用する (rule_source = "skill")。

### 4.3 検証済の Tier 1B 独自価値

実機 Win11 で 4 件の new finding を生成、いずれも Tier 1A (Hayabusa pass-through
含む) が拾えなかった artifact 経由:
- [critical/A2] mimi.exe + procdump64 in C:\Users\Public — credential dumping
- [high/A4] Discovery burst @ 13:54Z (whoami / systeminfo / nltest cascade)
- [high/A4] **Anti-recovery cluster** @ 14:00Z — vssadmin / wbadmin / bcdedit /
  wbengine / vds (テストシナリオ Step 7 を 1 件で完全捕捉)
- [medium/A5] RDPINPUT.EXE first-run @ 06:32Z next morning

## 5. Tier 2 — Timeline Analysis Agent (MVP + 能動モード 実装済)

実装: `internal/tier2/` (loader / cluster / timeline / runner /
active_search / json_lenient)

### 5.1 受動モード

`findings/by-rule/` と `findings/by-skill/` 全体を時間軸で cluster
(default 30 分 gap):
1. `LoadFindings` で by-rule/** + by-skill/* を統一 Finding 配列に
2. `EnrichTimestamps` で Tier 1B audit_id → ts_utc を bulk lookup
3. `ClusterFindings` で時間軸ソート + gap 閾値内を merge
4. 各 cluster について `FetchClusterTimeline` で ±5 分の raw events を
   stratified サンプリング (per-artifact、EVTX ノイズ EID 除外)
5. per-cluster LLM call: skill (`skills/timeline_review.md`) + cluster
   context (findings + raw timeline) → JSON {narrative, attack_phase,
   mitre_techniques, open_questions}
6. overall LLM call: per-cluster narratives → case-wide story

LLM 出力の JSON parse は `json_lenient.go` の `decodeFirstJSON` で 3 段リカバリ:
markdown fence / prose preamble / 末尾 trailing junk / double `}}` / 期待型と
逆の wrap (struct ↔ array) を許容。失敗時は raw response を
`outputs/cases/<id>/synthesis_debug/cluster<N>_*.txt` に保存して、narrative
には raw text を入れる degraded 動作。

overall LLM は retry + fallback 戦略:
- 1 回目: 完全な per-cluster narrative
- 失敗時 3 秒待機 → 2 回目: 1500 char に truncate (context size 対策)
- 2 回目も失敗 → `fallbackOverallStory` で per-cluster を決定論的に連結

CLI: `tlvb synthesize CASE_ID --tier 2 [--cluster-gap-minutes N]
                                       [--timeline-window-minutes N]
                                       [--active-search] [--dry-run]`

### 5.2 能動モード (★実装済)

実装: `internal/tier2/active_search.go::RunActiveSearch`

cluster の open_questions に対し LLM が SQL を最大 3 本提案 →
`validateActiveSearchSQL` で安全検証(case_id=? prefix / SELECT only /
single ? / no DDL/DML / no trailing ;)→ DuckDB で実行 →
LLM が結果を解釈して narrative addendum を書く。

各 SQL は最大 50 行を `TimelineEvent` で retain、総 hits 数は別途カウント。
SynthAudit に `ActiveSearchEnabled`, `ActiveSQLAttempted`, `ActiveSQLSucceeded`
を集計。

実機 Win11: 6 SQL 全部成功し、「procdump→mimi.exe リネーム masquerade」を
amcache の同一 SHA1 で完全裏付け、LSASS dump artifact の不在を honest
報告、RDP source IP の field path 修正必要を明示するなど、forensic
report 品質の補強として機能。

### 5.3 出力

`synthesis.json` に CaseSynthesis = (clusters + overall_story +
mitre_mapping + open_questions + audit) を出力。
SynthCluster は (id, start_ts, end_ts, attack_phase, narrative,
finding_refs, mitre_techniques, open_questions, active_search) を含む。
Tier 3 はこれだけ読めばよい。

## 6. Tier 3 — Reporter (TLVB v0.1 新規実装)

実装: `internal/tier3/` (types / render / html / csv)

synthesis.json を入力に、3 形式の output を `outputs/cases/<id>/reports/` に
書き出す:

- **HTML**: 単一 self-contained ファイル (~26 KB)、inline CSS、外部 JS なし、
  dark mode 対応 (prefers-color-scheme)、severity badge (critical/high/medium/
  low/info の 5 段階カラー)、MITRE technique セルに attack.mitre.org の
  絶対 URL リンク、ja/en の UI ラベル辞書(narrative は LLM 出力を verbatim)
- **CSV**: findings.csv / mitre.csv / clusters.csv の 3 本、UTF-8 BOM 付き
  で Excel 自動検出可
- **JSON**: synthesis.json の pretty-print コピー(reports/ ディレクトリを
  self-contained にするための archival 用)

CLI: `tlvb report CASE_ID --tier 3 [--format html,csv,json] [--language ja|en]
                                   [--synthesis PATH] [--out-dir DIR]`

注: 旧 `internal/reporter/` (findevil の TacticReport 用) はそのまま残置、
v0.1 では `--tier 3` の付かない `tlvb report` で起動可能(legacy 経路)。

## 7. データモデル

### 7.1 `cases.duckdb` (findevil 流用)
- `cases` (case_id PK, name, examiner, timezone, created_at, status)
- `evidence` (evidence_id, case_id, path, sha256, size_bytes, ...)
- `parse_results` (case_id, artifact_id PK, started_at, exit_code, row_count, ...)
- `unified_events` — 中心テーブル、`internal/casedb/schema_doc.go::UnifiedEventsDDL` 参照

### 7.2 `outputs/rules.duckdb` (TLVB 新規)
- `rule_sql_cache (rule_id, rule_source, rule_sha256, schema_version, model_id,
                   sql, state, generated_at, prefilter_artifacts, rule_meta, error_message)`
- PK: `(rule_id, rule_source)`
- 詳細は `internal/rulesdb/manager.go` のコメント参照

### 7.3 ケース毎ファイル (TLVB)
```
outputs/cases/<id>/
├── findings/
│   ├── by-rule/<rule_source>/<rule_id>.json   ← Tier 1A
│   ├── by-skill/<skill>.json                  ← Tier 1B
│   └── anomaly/<n>.json                        ← Tier 1B 追加クエリ findings
├── synthesis.json                              ← Tier 2 出力
├── reports/{report.html, findings.csv, ...}    ← Tier 3 出力
├── parse_review.json                           ← Review Gate 0 状態
├── findings_review.json                        ← Review Gate 1A/1B 状態
└── actions.jsonl                               ← 監査ログ
```

## 8. Review Gate

| Gate | 対象 | 形式 |
|---|---|---|
| Gate 0 | Tier 0 parse_results | findevil 流用、artifact 単位で OK/EMPTY/NOT_PRESENT/FAIL |
| Gate 1A | Tier 1A findings | severity (Sigma `level:`) で auto-approve、手動 override 可、cluster 単位バルク可 |
| Gate 1B | Tier 1B findings | 全件 Examiner レビュー (件数が少ない想定) |
| Gate 2 | Tier 2 timeline | findevil 流用 |

## 9. MCP server

`internal/mcp/server.go` を read-only ガードのまま拡張:
- 既存 10 tool (Tier 0) を保持
- 新規追加 (v0.1 後半):
  - `list_findings_by_rule(case_id, rule_source?, state?)`
  - `get_finding(case_id, finding_id)`
  - `search_findings(case_id, query)`
  - `get_synthesis(case_id)`
  - `list_cache_status()` (rule_sql_cache の集計)

すべて read-only。`execute_shell` は絶対公開しない。

## 10. CLI

```
tlvb case init|export|import|vacuum ...          (findevil 流用)
tlvb parse --case-id ... --input PATH            (findevil 流用)
tlvb rules build [--engine claude-code|anthropic-api] [--dry-run]
                 [--budget-yen N] [--max-rules N] [--source S]
                 [--rule-ids ID1,ID2,...] [--force]
tlvb rules list  [--source S] [--state pending|built|failed] [--show-sql]
tlvb analyze CASE_ID --tier 1a [--source S] [--rule ID] [--max-evidence N]
                               [--skip-hayabusa-passthrough]
                               [--include-info-level]
tlvb analyze CASE_ID --tier 1b [--max-events N] [--model M] [--dry-run]
                               [--timeout-minutes N]
tlvb synthesize CASE_ID --tier 2 [--cluster-gap-minutes N]
                                 [--timeline-window-minutes N]
                                 [--max-rows-per-cluster N]
                                 [--active-search] [--model M] [--dry-run]
tlvb report CASE_ID --tier 3 [--format html,csv,json] [--language ja|en]
                             [--synthesis PATH] [--out-dir DIR]
tlvb review CASE_ID [--gate 0|1a|1b|2] [--examiner NAME]
tlvb run CASE_ID --tier all --evidence PATH                        TLVB one-shot
       [--skip-parse|--skip-1a|--skip-1b|--skip-2|--skip-report]
       [--active-search] [--format html,csv,json] [--language ja|en]
tlvb run CASE_ID --evidence PATH                                   legacy findevil pipeline
tlvb status CASE_ID [-v] [--db PATH] [--rules-db PATH] [--case-root DIR]
tlvb serve [--port 8080]                                           Web UI
tlvb mcp-serve                                                     MCP server (stdio)
tlvb version
```

## 11. 既知の制約と未解決事項

1. **Build cost guard の token 推定が worst-case**: 実際は prompt cache で
   30-60% 削減される。dry-run 表示にも注記しているが、より精度の高い推定
   モデル (cache hit rate 推定) は v0.2 で検討。
2. **Tier 1B の hybrid cache 未実装**: MVP では cache hit 判定 + 都度新 SQL
   生成 + cache 追記の hybrid フローは未実装。LLM 任せの hit 判定は cache
   が大きくなったら選択が重くなる懸念もあり、RAG 事前絞り込みも併せて
   v0.2 で実装予定。
3. **Forensic 系ルール (LOLBAS / Atomic Red Team / DFIR Report)** は未取り込み。
   v0.1 では Sigma + Hayabusa が大半をカバー (Hayabusa pass-through で 32
   ルール、Sigma cached SQL で 3 ルール検知の実績)。
4. **能動 SQL モード (Tier 2)** の hypothesis 生成戦略は実機 1 case で検証
   済み (6 SQL 全部成功)。複数 case での挙動観察 + プロンプトチューニングは
   今後の課題。
5. **(d) Review UI Gate 1A** 未実装。CLI でも `tlvb review CASE_ID --gate 1a`
   経由で承認可能だが、Web UI 経由の severity badge + cluster 単位バルク UI
   は v0.2 候補。
6. **findevil → TLVB のリネーム移行**: ドキュメント / scripts に findevil
   名義が残存。CLAUDE.md「★ findevil → TLVB リネーム移行中」参照。

## 12. v0.1 実装サマリ

| 区分 | パッケージ / ファイル | 目的 |
|---|---|---|
| Tier 0 | `parsers/`, `internal/casedb/` | 17 アーティファクトパース、unified_events ingest (findevil 流用) |
| Tier 1A build | `internal/rulesrepo/`, `internal/rulebuild/`, `internal/rulesdb/` | Sigma/Hayabusa/STIX loader, LLM → SQL, rule_sql_cache |
| Tier 1A runtime | `internal/tier1a/` | cached SQL 実行、Hayabusa pass-through |
| Tier 1B | `internal/tier1b/` | skill-driven prefilter + LLM 推論 |
| Tier 2 | `internal/tier2/` | cluster + per-cluster LLM + overall + active-search + lenient JSON |
| Tier 3 | `internal/tier3/` | HTML / CSV / JSON renderer |
| CLI | `cmd/tlvb/` | dispatcher、status、run --tier all |
| Doc | `README.md`, `docs/DESIGN.md`, `docs/STATUS.md`, `CLAUDE.md` | 設計と運用ガイド |
