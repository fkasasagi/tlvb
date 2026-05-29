# Changelog

All notable changes to TLVB.

## [v0.1] — 2026-05-29

🎉 **TLVB v0.1**: Tier 0/1A/1B/2/3 + 横断機能 (CLI / Web UI / MCP) を含む主要
パイプラインがすべて完走。実機 Windows 11 トリアージ zip で攻撃シナリオ 8 step を
end-to-end で検知・再構成・レポート出力できることを確認済。

### Highlights

- 🟢 **Tier 1A (Signature SQL Agent)** — Sigma + Hayabusa-rules + ATT&CK STIX
  の 3 corpus 取り込み、LLM-driven build パイプライン、cached SQL 実行、
  Hayabusa pass-through
- 🟢 **Tier 1B (Skills-driven Anomaly)** — 5 lens 強化 prefilter + claude CLI
  推論、prefetch / amcache などの非 EVTX artifact から差分検知
- 🟢 **Tier 2 (Timeline Analysis)** — 受動 cluster narrative + 能動 hypothesis-
  driven SQL + lenient JSON parser + overall retry/fallback
- 🟢 **Tier 3 (Reporter)** — self-contained HTML (dark mode, severity badge,
  MITRE link) + UTF-8 BOM 付き CSV + JSON copy
- 🟢 **One-shot pipeline** `tlvb run CASE_ID --tier all` — parse → 1A → 1B → 2 → 3
- 🟢 **Inspection** `tlvb status CASE_ID` — case + cache + reports の状態を一括表示

### 実機 Win11 e2e 検証 (86 MB トリアージ zip)

| Tier | 出力 |
|---|---|
| Tier 0 | 470,372 unified_events (mft 459k / evtx 5.6k / hayabusa 1k / amcache 2k / ...) |
| Tier 1A | 3 sigma cached SQL hits + 32 Hayabusa pass-through findings |
| Tier 1B | 4 anomaly findings (LSASS dumping / discovery burst / **anti-recovery cluster** / 翌朝 RDP) |
| Tier 2 | 2 temporal clusters with narrative + 6 active-search SQL succeed |
| Tier 3 | self-contained HTML 26 KB |
| 全工程 | ~5 分 (parse 除く analyze+synthesize+report) |

### Tier 0 — Parser 層 (findevil から流用)

- 17 アーティファクトパーサ (evtx/amcache/prefetch/registry/scheduled_tasks/
  shimcache/mft/shellbags/jumplists/lnk/recyclebin/win10timeline/usn_journal/
  hayabusa/srum/browser_history/washizukami_audit)
- 5 種 skeleton (sqlecmd/bulk_extractor/yara/volatility3/w3c_iis)
- イメージ取り込み (E01/raw/VMDK/VHD/VHDX) + ネスト アーカイブ再帰展開
- DuckDB unified_events への bulk ingest

### Tier 1A — Signature-driven SQL Agent

#### Build パイプライン
- `internal/rulesrepo/`: SigmaHQ/sigma (3132 ルール) / Yamato-Security/hayabusa-rules
  hayabusa/ subdir (193 ルール) / mitre/cti (858 attack-pattern) を git submodule
- Non-Windows / Sysmon-only / revoked / deprecated は loader 側で skip
- `internal/rulebuild/`: Anthropic API + claude-code CLI の 2 engine
- `validateSQL`: SELECT-only / case_id 必須 / single ? placeholder / no DDL/DML /
  no semicolon。SQL string literal 内の "delete" 等は許可 (regex で literal を strip)
- `internal/rulesdb/`: `rule_sql_cache (rule_id, rule_source, rule_sha256,
  schema_version, model_id, sql, state, ...)` テーブル、無効化キー 3 つ組
- Cost guard: `--dry-run` で token 推定、`--budget-yen` / `--max-rules` /
  `--rule-ids` flag、中断 → resume 可

#### Runtime
- `internal/tier1a/runner.go::Run`: cached SQL を case の prefilter_artifacts と
  照合してから実行、1 SQL 失敗で全体は止めない (graceful)
- Severity ベース auto-approve (`AutoApproveByLevel`): critical/high はレビュー
  必須、それ以外は auto-approve
- Hayabusa pass-through (`internal/tier1a/hayabusa_passthrough.go`): Tier 0 の
  Hayabusa 検知を RuleID でグループ化して finding 化、info/low はデフォルト除外
- finding 出力: `findings/by-rule/<source>/<rule_id>.json` (1 rule = 1 file)
- CLI: `tlvb analyze CASE_ID --tier 1a`

### Tier 1B — Skills-driven Anomaly Agent (MVP)

- `internal/tier1b/`: prior findings + heuristic prefilter + claude CLI
- 5 lens で score (A0 artifact diversity / A1 off-hours / A2 suspicious path /
  A4 rare process / A5 adjacency to prior findings)
- Stratified per-artifact sampling (high-volume MFT が小 artifact を crowd out
  しないように), EVTX ノイズ EID (4656/4658/4663/4703/5152/5156/5158 等) を
  SQL レベルで除外
- skill: `skills/anomaly_hunter.md` (findevil 流用)
- 出力: `findings/by-skill/anomaly_hunter.json` (AnomalyReport, 複数 finding を
  配列で)
- CLI: `tlvb analyze CASE_ID --tier 1b`

### Tier 2 — Timeline Analysis Agent

#### 受動モード
- `LoadFindings`: by-rule + by-skill を統一 Finding に正規化
- `EnrichTimestamps`: Tier 1B audit_id → ts_utc を bulk lookup
- `ClusterFindings`: 30 分 gap で時間軸 cluster
- `FetchClusterTimeline`: per-cluster ±5 分の raw events を stratified
  サンプリング (artifact-aware shrinkPayload で Excerpt 化)
- per-cluster LLM call → narrative + attack_phase + mitre_techniques + open_questions
- overall LLM call → case-wide story
- skill: `skills/timeline_review.md` (findevil 流用)

#### 能動モード (`--active-search`)
- 各 cluster の open_questions に対し LLM が SQL を最大 3 本提案
- `validateActiveSearchSQL`: case_id=? prefix / SELECT only / single ? /
  no DDL/DML / no semicolon
- 結果を LLM に再投入して narrative addendum を生成
- 実機 Win11: 6 SQL 全部成功 ("procdump→mimi.exe リネーム masquerade" を amcache
  の同一 SHA1 で完全裏付け 等)

#### Lenient JSON parsing
- `decodeFirstJSON`: markdown fence / prose preamble / trailing junk / double
  `}}` / 期待型と逆の wrap (struct ↔ array) を許容
- parse 失敗時は raw response を `synthesis_debug/cluster<N>_*.txt` に保存して
  narrative には raw text を入れる degraded 動作

#### Overall retry + fallback
- 1 回目: 完全な per-cluster narrative
- 失敗時 3 秒待機 → 2 回目: 1500 char に truncate (context size 対策)
- 2 回目も失敗 → `fallbackOverallStory` で per-cluster narrative を決定論的に
  連結 (Executive Summary が必ず埋まる)

CLI: `tlvb synthesize CASE_ID --tier 2 [--active-search]`

### Tier 3 — Reporter

- `internal/tier3/`: types / render / html / csv
- HTML: 単一 self-contained ファイル、inline CSS、dark mode、severity badge、
  MITRE link、ja/en UI labels
- CSV: findings.csv / mitre.csv / clusters.csv、UTF-8 BOM 付き
- JSON: synthesis.json の pretty-print コピー
- CLI: `tlvb report CASE_ID --tier 3 [--format html,csv,json] [--language ja|en]`

### 横断機能

- **One-shot pipeline**: `tlvb run CASE_ID --tier all --evidence PATH
  [--active-search] [--skip-parse|--skip-1a|--skip-1b|--skip-2|--skip-report]`
- **Inspection**: `tlvb status CASE_ID [-v]` — case metadata + parse_results +
  findings (by source/severity) + synthesis 状態 + rule SQL cache 集計 +
  reports/ ファイル一覧
- **MCP server**: read-only (`tlvb mcp-serve`)、Tier 0 の 10 tool は findevil
  から流用
- **Web UI**: `tlvb serve --port 8080`

### 設計判断

- **Tier 1A runtime は LLM ゼロ**: cached SQL のみ。LLM コストは build 時に 1 度
- **rule_id は上流の原 ID を改変しない**: Sigma UUID / STIX T-number / Hayabusa
  UUID をそのまま、`rule_source` 補助カラムで分離
- **Sysmon 専用ルールはデフォルト除外**: `requires_artifact` で動的有効化可
- **Severity ベース auto-approve**: critical/high はレビュー必須、それ以外は auto
- **graceful degradation**: 1 SQL 失敗 → 全体は止めない、Cluster LLM 失敗 →
  raw text で残す、Overall LLM 失敗 → 決定論的 fallback

### Known limitations

- (d) Review UI Gate 1A は未実装 (CLI 経由のみ)
- Tier 1B の Hybrid Cache (canonical SQL 蓄積 + LLM 都度生成) は v0.2 で実装予定
- Forensic 系 ルール (LOLBAS / Atomic Red Team / DFIR Report) は v0.2 で取り込み検討
- findevil → TLVB のドキュメント / scripts 名義残置 (`CLAUDE.md` 参照)

### Test data

- ユーザ提供 Win11 トリアージ zip (86 MB) で end-to-end 動作確認
- Ground Truth: 8 step 攻撃シナリオ (LNK初期侵入 → 永続化 → 偵察 → C2 NXDOMAIN
  試行 → 認証情報窃取(擬似) → 横展開 → ランサム/Anti-recovery → 痕跡消去)

---

(v0.1 より前は変更履歴ありません — プロジェクトは v0.1 で初期 release)
