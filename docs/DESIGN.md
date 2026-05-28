# TLVB システム設計書 (v0.1)

**最終更新**: 2026-05-29
**ステータス**: Tier 1A の build 基盤まで実装済。runtime 以降は未着手 (`docs/STATUS.md` 参照)

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

### 3.4 Runtime (★未実装)

cached SQL を実行して finding 出力する部分。設計は決まっているが実装は次セッション。

```
ケース C のロード時:
  1. rulesdb から state='built' な行を全件取得
  2. 各行について:
     a. row.prefilter_artifacts が case の parse_results に含まれていなければ skip
     b. row.sql を `WHERE case_id = ?` の `?` に case_id を bind して実行
     c. 結果行が 1 件以上あれば finding 生成
  3. severity ベースで Review Gate 1A の auto-approve / require-review 振り分け
```

finding スキーマ (案):
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

## 4. Tier 1B — Skills-driven Anomaly Agent (★未実装)

findevil の `skills/*.md` 12 個 (10 tactic + anomaly_hunter + timeline_review)
をそのまま流用。runtime の流れ:

```
1. skill から派生した cached SQL 群を実行 (build 時に skill ごとに canonical query を生成)
2. SQL 結果 + Tier 1A findings を LLM プロンプトに同梱
3. LLM が skill の観点で「これは怪しい」を判定 → finding 化
4. LLM が「もう一段別の角度で見たい」と判断すれば新 SQL を考案
   → cache に類似 query があれば再利用、なければ新規生成して cache に追記
   → 実行 → 結果を 2. のループに戻す
```

cache hit 判定は **LLM 自身**に任せる:
- cache 一覧 (skill / intent_summary / SQL fingerprint) を LLM に見せて
  「これを使う or 新規作る」を判断させる
- cache 肥大化したら RAG で事前絞り込み (v0.2 以降)

build パイプラインも skill の canonical query 部分は Tier 1A と同じ
`rule_sql_cache` を再利用する (rule_source = "skill")。

## 5. Tier 2 — Timeline Analysis Agent

### 5.1 受動モード (findevil 同方向、再設計予定)

`findings/by-rule/` と `findings/by-skill/` 全体を時間軸で cluster
(例: 30 分以内は同じ cluster)。各 cluster について:
- 中心時刻の ±N 分 raw timeline をクエリ
- 攻撃連鎖の物語を LLM に再構成させる
- 矛盾チェック (R1-R4、findevil から流用)

実装は findevil の `internal/synthesizer/synthesizer.go` を中心に改修。

### 5.2 能動モード (★新規)

LLM が「X が起きたなら Y がその前 / 後 / 全期間にあるはず」と仮説を立て、
wide-range SQL を生成して timeline を探索。Tier 1B と同じ hybrid cache。

例: 「Persistence の Run キー書き込みを 1A が検出 →
  Tier 2 の能動モードが『その後 7 日間以内に Run キーから起動された
  プロセスがあるはず』という仮説で wide-range クエリを生成」

これにより Mandiant の dwell time 7 日問題 (findevil で課題だった
「時間幅が広いケースで Persistence の後段が検出されない」) を解消する狙い。

### 5.3 出力

`synthesis.json` に attack chain + cross-evidence correlation を出力。
Tier 3 はこれだけ読めばよい。

## 6. Tier 3 — Reporter (findevil 流用)

`internal/reporter/` を流用。HTML 11 セクション / CSV / JSON、ja/en。
finding 入力形式が by-rule になるので、HTML テンプレを tactic 軸で集計する
小改修が必要 (synthesis.json で集計済みなので最小)。

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
tlvb case init|export|import|vacuum ...        ← findevil 流用
tlvb parse --case-id ... --input PATH          ← findevil 流用
tlvb rules build [--dry-run] [--budget-yen N] [--max-rules N]
                 [--source sigma|hayabusa|stix] [--force]
tlvb rules list  [--source S] [--state pending|built|failed] [--show-sql]
tlvb analyze CASE_ID [--tier 1a|1b|2] [--rule|--skill|--tactic]   ← v0.1 後半
tlvb synthesize CASE_ID [--active-search]                          ← v0.1 後半
tlvb report CASE_ID [--format html,csv,json] [--language ja|en]   ← findevil 流用
tlvb review CASE_ID [--gate 0|1a|1b|2] [--examiner NAME]
tlvb run CASE_ID --evidence PATH                                  ← 全パイプライン一括
tlvb serve [--port 8080]                                          ← Web UI
tlvb mcp-serve                                                    ← MCP server
tlvb version
```

## 11. 既知の制約と未解決事項

1. **Build cost guard の token 推定が worst-case**: 実際は prompt cache で
   30-60% 削減される。dry-run 表示にも注記しているが、より精度の高い推定
   モデル (cache hit rate 推定) は v0.2 で検討。
2. **Tier 1B の cache hit 判定を LLM 任せ**: cache が大きくなったら LLM の
   選択が重くなる懸念。RAG 事前絞り込みは v0.2。
3. **Forensic 系ルール (LOLBAS / Atomic Red Team / DFIR Report)** は未取り込み。
   v0.1 では Sigma が大半をカバーしている想定。v0.2 で LOLBAS を追加検討。
4. **能動 SQL モード (Tier 2)** の hypothesis 生成戦略は未検証。実装後に
   実ケースで挙動を観察してチューニング。
5. **findevil → TLVB のリネーム移行**: ドキュメント / scripts に findevil
   名義が残存。CLAUDE.md「★ findevil → TLVB リネーム移行中」参照。
