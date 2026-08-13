# TLVB システム設計書 (v0.1)

**最終更新**: 2026-05-29
**ステータス**: **v0.1 主要パイプライン (a)-(g) 完走済**。
Tier 0 / 1A (build + runtime + Hayabusa pass-through) / 1B (MVP + 強化済 prefilter)
/ 2 (受動 + 能動 + lenient JSON parser + fallback) / 3 (HTML/CSV/JSON Reporter) すべて
動作確認済。残りは (d) Review UI と coverage 拡張のみ。

## 0. 設計思想

### スコープ — Windows インシデント対応のディスクフォレンジック

TLVB が対象とするのは、**Windows のサイバーインシデント対応文脈における
ディスクフォレンジック**である。具体的には、triage 収集物またはディスクイメージ
(E01 / raw / VMDK / VHD / VHDX)として取得した**ディスク常駐**アーティファクト
(MFT / EVTX / レジストリ / prefetch / amcache / shimcache / shellbags / jumplists
/ LNK / SRUM / ブラウザ履歴 / Web サーバログ 等)を解析対象とする。

ライブの**メモリフォレンジック**および**ネットワーク / パケット(PCAP)フォレンジック**は
デフォルトで対象外。メモリ・Sysmon 依存ルールはルール側に `requires_artifact` メタを
保持し、当該アーティファクトが証拠に含まれていない限り runtime で skip する
(後日 Sysmon あり/メモリありケースが来れば再 build 不要で自動 ON)。

TLVB は moai(Windows フォレンジック自律 IR エージェント)の構造を引き継ぎつつ、
**「シグネチャ駆動 SQL + 抽象観察 + タイムライン解析」** の 3 層を明確に分離した
リエンジニア版である。moai との根本的な差分:

| 観点 | moai | TLVB |
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
         ※ moai から流用
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
         skills/*.md (moai 12 個流用) 由来の cached SQL 実行
         + 1A findings を context として LLM が抽象パターン推論
         + LLM が必要なら新 SQL 考案 → cache 追記 (LLM 自身が hit/新規判定)
         → findings/by-skill/<skill>.json
  ↓
Tier 2   Timeline Analysis Agent
         受動: findings cluster の ±N 分 raw timeline を LLM 分析
         能動: 仮説駆動 wide-range SQL で広域探索
         → synthesis.json (attack chain + 矛盾解消)
  ↓
Tier 3   Reporter (HTML / CSV / JSON, ja/en, moai 流用)
```

## 2. Tier 0 — Parser 層 (moai 流用)

17 アーティファクト + 5 skeleton。`parsers/orchestrator.py` がディスパッチ。
各パーサは Python サブプロセスで EZ Tools / Hayabusa / Plaso 等を呼び、
出力を **UnifiedEvent** (DuckDB の `unified_events` 8 カラム) に正規化。

スキーマは `internal/casedb/schema_doc.go::UnifiedEventsDDL`。本 v0.1 で改修予定なし。

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

moai の `skills/*.md` 12 個 (10 tactic + anomaly_hunter + timeline_review)
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
   LLM に渡す
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
1. `LoadFindings` で by-rule/** + by-skill/* を統一 Finding 配列に。
   **Review Gate 1A/1B で `rejected` になった finding はここで除外**
   (Gate は Tier 2 の前に回る運用。examiner が誤検知と判断したものを
   ストーリーの起点にしない)。除外件数は `SynthAudit` に残す
2. `EnrichTimestamps` で Tier 1B audit_id → ts_utc を bulk lookup
3. `ClusterFindings` で時間軸ソート + gap 閾値内を merge
4. 各 cluster について `FetchClusterTimeline` で **±30 分** の raw events を
   stratified サンプリング (per-artifact、EVTX ノイズ EID 除外)
5. per-cluster LLM call: skill (`skills/timeline_review.md`) + cluster
   context (findings + raw timeline) → JSON {narrative, attack_phase,
   mitre_techniques, open_questions, **follow_up_events**}
6. **追跡ループ (§5.1.1)**: 5 で LLM が攻撃と判定したイベントが窓の芯より
   外にあれば、窓を伸ばして 4→5 をやり直す
7. overall LLM call: per-cluster narratives → case-wide story

窓幅の既定を 30 分にしたのは cluster gap と揃えるため。findings が 30 分以内
なら同一エピソードとして merge される以上、その同じスパン内の raw events は
分析が当然見てよい文脈である。窓を広げてもコストはほぼ増えない — サンプラは
「検知への近接順・アーティファクト毎に上限」で選ぶので、密なアーティファクト
(EVTX/MFT) が返す行は窓幅によらずほぼ同じ。文脈が増えるのは疎な
アーティファクト (lnk / prefetch / browser_history) の側。

#### 5.1.1 追跡ループ (chase loop)

**問題**: 従来は 1 クラスタ 1 回の LLM 呼び出しで打ち切っていた。攻撃活動が
窓の外に続いていても Tier 2 はそこを見に行かないため、「dwell 期間は静か
だった」という誤った所見が残る。

findings レベルの連鎖は既に存在する (30 分 gap の `ClusterFindings`、および
Hayabusa passthrough が medium 以上を全部 finding 化する)。**抜けているのは
「シグネチャは鳴らなかったが Tier 2 の LLM が攻撃と判断したイベント」の先**で、
そこが追跡の切れ目になっていた。

**発火条件** = Tier 1 のシグネチャ検知 (= cluster の findings) と Tier 2 LLM が
「もっと周りを見たい」と挙げたイベント (= `follow_up_events`) の和集合のうち、
Review Gate で reject されていないもの。判定の主体は既存の verdict であって、
新しいヒューリスティックを足すわけではない。

**`follow_up_events` は主張ではなく要求**である点が要。ここに挙げることは
「これは攻撃だ」という断定ではなく「この周辺をもう一度見せてくれ」という
依頼で、**判断がつかないイベントほど挙げるべき**。窓を広げることこそが
その不確実性を解消する手段だから。初版では逆に「不確実なら挙げるな」と
指示してしまい、実ケース `winrm_spray_case` で機能が完全に不発になった —
モデルは検知スパンの 6 分後のログオフと再起動を narrative の根拠に使い、
「攻撃者のクリーンアップか正規の作業か本データでは断定できない」と正しく
書いた上で、指示どおり `attack_events` を空で返した。最も追跡すべき場面で
必ず止まる設計だった。

あわせて、prompt 内の findings には audit_id が入っていないため「findings が
既にカバーしているものは挙げるな」は**モデルには追従不能な指示**だった。
timeline の各行に `Detected: true` を付けて判定可能にしてある。

**ループ**: 各 cluster について

```
hull   = [StartTS, EndTS]                 // findings 由来の芯
window = [hull.lo - W, hull.hi + W]       // W = TimelineWindow (30 分)

for round := 0; ; round++ {
    resp := onePass(window)                    // LLM 1 call
    confirmed := resolveTS(resp.follow_up_events) // 窓内イベントの ts

    grew := hull を confirmed の min/max まで拡張できたか
    if !grew || round >= MaxChaseRounds { break }

    window = clampToNeighbours(hull.lo-W, hull.hi+W)
    ChaseAnchors += confirmed
    FetchClusterTimelineRange(window)           // 再取得 (excerpt は作り直し)
}
```

窓の伸ばし幅は機械的に `+W` (30 分) で、「どこまで伸ばすか」に追加の LLM
判断は挟まない。判断は「そのイベントは攻撃か」だけで、それは per-cluster
分析が既に下している。

**anchor の伝播が要**: サンプラは anchor への近接順で行を選ぶ。窓を伸ばした
先には findings 由来の anchor が無いので、`ChaseAnchors` (LLM が攻撃と判定した
イベントの ts) を anchor に混ぜないと新領域の行がほとんど選ばれず、窓を
広げた意味が消える。

**隣接クラスタでの clamp — 隙間の中点で分ける**: 窓は隣接クラスタとの境界で
止める。追跡した攻撃活動が境界を越えた場合は、hull もそこで止め (越えた先は
隣のクラスタが説明すべき領分)、`ContinuesIntoNext` / `ContinuesFromPrev` を
立てる。

**フラグは「窓が境界に届いた」ではなく「追跡した活動が境界を越えた」で立てる**
— ここは証拠に基づく主張だから。窓は隙間の半分より広ければ必ず境界に届く
ので、既定 (cluster gap 30 分 / 窓 30 分) では **gap が 31〜59 分の隣接ペアは
追跡ゼロ・flag ゼロでも必ず境界に届く**。それでフラグを立てると、最頻出の帯域
で根拠のない連続性を毎回 LLM に教え込むことになり、「finding は必ず evidence で
裏付ける」という本システムの原則に反する。prompt 側のキー名も
`attacker_activity_traced_toward_next_cluster` とし、フラグが**無い**ことは
「そこまで追跡が届かなかった」だけで「活動が無かった」ではない、と明示する。

境界は**隣接クラスタとの隙間の中点** (`clusterBoundaries`)。隣人の hull の端
を境界にすると、クラスタ i-1 が前方へ、クラスタ i が後方へ、**同じ隙間を
両方が解析してしまう** (どちらも隣人の hull までは伸ばせるため)。中点なら
両クラスタが同じ 1 本の境界を見るので重複が原理的に起きない。さらに中点は
必ず両者の hull の外側にあるため、`clampWindow` の「自 hull は削らない」
規則と衝突しない (hull の端を境界にすると、この 2 つは両立しない)。

**この clamp は追跡ループだけでなく初回 fetch にも適用する。** 窓が ±30 分に
なったことで、hull 間隔が 60 分未満の隣接クラスタは**追跡を 1 度もしなくても
初回の窓が重なる**。実際 `winrm_spray_case` の実走では、clamp 前の実装で
クラスタ 1 の窓終端 (10:25:02) とクラスタ 2 の窓開始 (10:09:37) が 15 分 24 秒
重複し、同じ raw timeline が両方の LLM パスに渡っていた。

merge はしない — クラスタ ID / 件数が変わると Review Gate 2 UI・
synthesis.json 消費側・Tier 3 への波及が大きいため。連続性の事実はフラグ
として prompt と synthesis.json に載せ、「30 分 gap で別エピソードに見えた
が実際は活動が途切れていなかった」を overall pass と Tier 3 が拾えるように
する。これは dwell 期間の解釈を変える所見なのでレポートに残す価値がある。

**コスト制御** (エージェントの暴走防止 — 反復回数・タイムアウトには必ず上限を置く):
- 1 ラウンド = クラスタあたり LLM 1 call 追加。`--timeline-chase-rounds`
  (既定 2、0 で無効)
- on-demand evidence fetch の予算 (`--max-evidence-rounds`) は**ラウンド毎に
  リセットせず、クラスタ単位で共有**する。両ループが掛け算にならず、
  1 クラスタのコストは `(chase rounds + 1) 回の分析 + evidence rounds` に
  収まる。「最終パスでのみ fetch」も検討したが、どのパスが最終かは実行前に
  判らず +1 call になるため採らなかった
- ラウンドが失敗したら直前のラウンドの結果を採用してループを抜ける
  (graceful degradation — 1 エージェントが失敗してもケース全体は完走させる)。
  追加ラウンドの LLM 応答が
  parse 不能でも、既に出来ている narrative は上書きしない
- 上限に達してもまだ攻撃イベントが出続けている場合は
  `SynthAudit.chase_rounds_capped` に記録する。「その区間は探索し切った」と
  レポートに誤読させないため

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
                                       [--timeline-chase-rounds N]
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
finding_refs, mitre_techniques, open_questions, active_search) に加え、
追跡ループの結果 (window_start / window_end / chase_rounds /
continues_into_next / continues_from_prev) を含む。
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

注: 旧 `internal/reporter/` (moai の TacticReport 用) はそのまま残置、
v0.1 では `--tier 3` の付かない `tlvb report` で起動可能(legacy 経路)。

## 7. データモデル

### 7.1 `cases.duckdb` (moai 流用)
- `cases` (case_id PK, name, examiner, timezone, created_at, status)
- `evidence` (evidence_id, case_id, path, sha256, size_bytes, ...)
- `parse_results` (case_id, evidence_id, artifact_id PK, started_at, exit_code, row_count, ...)
  — evidence 単位の orchestrator run が自分の行を持つ (旧 PK=(case_id, artifact_id) からは自動 migration、legacy 行は evidence_id='')
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
| Gate 0 | Tier 0 parse_results | moai 流用、artifact 単位で OK/EMPTY/NOT_PRESENT/FAIL |
| Gate 1A | Tier 1A findings | severity (Sigma `level:`) で auto-approve、手動 override 可、cluster 単位バルク可 |
| Gate 1B | Tier 1B findings | 全件 Examiner レビュー (件数が少ない想定) |
| Gate 2 | Tier 2 timeline | moai 流用 |

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
tlvb case init|export|import|vacuum ...          (moai 流用)
tlvb parse --case-id ... --input PATH            (moai 流用)
tlvb rules build [--dry-run]
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
tlvb run CASE_ID --evidence PATH                                   legacy moai pipeline
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
6. **共有基盤の旧名残置**: 一部のコード / doc に共有基盤由来の旧名 (findevil) が
   残る場合は `tlvb` と読み替える。姉妹プロジェクト moai (旧 findevil) との関係は
   `NEW_CONTRIBUTIONS.md` を参照。

## 12. v0.1 実装サマリ

| 区分 | パッケージ / ファイル | 目的 |
|---|---|---|
| Tier 0 | `parsers/`, `internal/casedb/` | 17 アーティファクトパース、unified_events ingest (moai 流用) |
| Tier 1A build | `internal/rulesrepo/`, `internal/rulebuild/`, `internal/rulesdb/` | Sigma/Hayabusa/STIX loader, LLM → SQL, rule_sql_cache |
| Tier 1A runtime | `internal/tier1a/` | cached SQL 実行、Hayabusa pass-through |
| Tier 1B | `internal/tier1b/` | skill-driven prefilter + LLM 推論 |
| Tier 2 | `internal/tier2/` | cluster + per-cluster LLM + overall + active-search + lenient JSON |
| Tier 3 | `internal/tier3/` | HTML / CSV / JSON renderer |
| CLI | `cmd/tlvb/` | dispatcher、status、run --tier all |
| Doc | `README.md`, `docs/DESIGN.md` | 設計と運用ガイド |
