# TLVB

**TLVB** — *Timeline Longa, Vita Brevis*
(タイムラインは長く、人生は短い。だから自動化で攻撃の痕跡を炙り出す)

*English: [README.md](README.md)*

Sigma / Hayabusa / ATT&CK STIX / skills-driven anomaly detection を組み合わせて、
Windows のディスクフォレンジック・アーティファクトから攻撃の痕跡を抽出し、
LLM が攻撃チェーンを再構成して HTML/CSV/JSON レポートまで吐く自律型 IR エージェント。

> 📺 **デモ動画を見る →** <https://youtu.be/ATSJYtP4kCw>
> Web UI で調査を一通り回す様子を画面ごとに解説。

**スコープ — Windows インシデント対応のディスクフォレンジック。** TLVB が対象とするのは
**ディスク常駐**の Windows アーティファクト(MFT / EVTX / レジストリ / prefetch / amcache /
shimcache / shellbags / jumplists / LNK / SRUM / ブラウザ履歴 / Web サーバログ 等)で、
triage 収集物またはディスクイメージ(E01 / raw / VMDK / VHD / VHDX)として取得したものを解析する。
ライブの**メモリフォレンジック**や**ネットワーク / パケット(PCAP)フォレンジック**は対象外
(メモリ・Sysmon 依存ルールは、当該アーティファクトが証拠に含まれていない限り無効のまま)。

## 状態

🟢 **v0.1 全パイプライン (a)-(g) 完走**。実機 Windows 11 トリアージで
攻撃シナリオ 8 step を end-to-end で検出・再構成・レポート出力できることを
2026-05-29 時点で確認済み。システム図は [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)、
ハッカソンの新規実装と流用基盤の差分は [`NEW_CONTRIBUTIONS.md`](NEW_CONTRIBUTIONS.md) を参照。

```
INPUT (collector zip / disk image / live triage)
  ↓
Tier 0   Parser ×N (Python) → unified_events @ DuckDB         🟢
  ↓        EZ Tools / Hayabusa / Plaso / SrumECmd / 等を wrap
Tier 1A  Signature-driven (★ runtime LLM ゼロ)                🟢
          build 時に Sigma/Hayabusa/STIX → SQL を cache
          runtime: cached SQL 実行 + Hayabusa pass-through
  ↓     → findings/by-rule/<source>/<rule_id>.json
Tier 1B  Skills-driven Anomaly                                🟢
          off-hours / 不審 path / rare process / adjacency
          で 5×N サンプルを LLM に渡し抽象パターン抽出
  ↓     → findings/by-skill/<skill>.json
Tier 2   Timeline Analysis                                    🟢
          findings を 30 分 gap でクラスタリング、±5 分 raw
          timeline と一緒に per-cluster narrative を LLM 生成
          --active-search で open_questions を SQL で深掘り
  ↓     → synthesis.json
Tier 3   Reporter                                             🟢
          HTML (self-contained, dark mode, MITRE link) / CSV / JSON
        → outputs/cases/<id>/reports/
```

## 使い方

TLVB は基本 **Web UI** で操作するツールです — Examiner はブラウザから調査一式を回します。
コマンドラインも用意していますが、こちらはスクリプト化・ヘッドレス/CI 実行・MCP 連携向けです。

### 1. セットアップ (初回のみ)

```bash
# 依存検証 + .venv 作成 + go build + vendored ルール SQL cache の import を自動実行。
# これだけで Tier 1A まで動く状態になる。
./scripts/setup.sh
```

### 2. Web UI で動かす (主たる使い方)

```bash
./bin/tlvb serve --port 8080      # ブラウザで http://localhost:8080/ を開く
                                  # リモート / VM 外からは http://<host-ip>:8080/
```

ブラウザ上で:

- **ダッシュボードでケースを作成**し、証拠を指定する — collector の `.zip`、
  ディスクイメージ (E01 / raw / VMDK / VHD / VHDX)、または triage ディレクトリ。
- **🤖 Autopilot** で全パイプライン (Tier 0 parse → 1A → 1B → 2 → 3) をワンクリック
  一気通貫実行。あるいは **Parse / Analyze / Synthesize / Report** の各ボタンで
  段階実行も可能(各ボタンにライブ進捗バー + ETA)。
- **Review Gate** は各タブに内蔵: **Events** タブで parse 結果を承認/却下 (Gate 0)、
  **Findings** タブで署名 + 異常 findings (Gate 1A — 重要度ベース自動承認 +
  クラスタ単位のワンクリック一括承認)、**Timeline** タブで再構成した攻撃タイムライン
  (Gate 2)。
- **レポートの閲覧とダウンロード** (HTML / CSV / JSON) は **Report** タブから。
  **IOCs**・**MITRE ATT&CK** マップ・Tier 別の **Audit** トレイルもそれぞれ専用タブ。
  元の証拠は一切変更しません。

画面ごとの詳細は [`docs/USER_GUIDE.ja.md`](docs/USER_GUIDE.ja.md) を参照。

### 3. または コマンドラインから (スクリプト / 自動化 / ヘッドレス)

```bash
# 1 コマンドで全 Tier 実行 (証拠の置き場所は任意: zip / ディスクイメージ / triage ディレクトリ)。
# Tier 2 の自己修正・再シーケンス active-search エージェント (自律性の見せ場: 失敗クエリを
# 自分で直し、0 件のときは別仮説へ pivot する) は既定 ON。安価・非エージェント実行は
# --no-active-search を付ける。
./bin/tlvb run MY-CASE-001 --tier all --evidence /path/to/triage.zip

# 段階的に走らせる場合 (Tier 1A の SQL cache は setup.sh が import 済み)
./bin/tlvb case init --case-id MY-CASE-001 --name "Sep IR" --examiner alice
./bin/tlvb parse --case-id MY-CASE-001 --evidence-id EV-001 --input triage.zip
./bin/tlvb analyze MY-CASE-001 --tier 1a
./bin/tlvb analyze MY-CASE-001 --tier 1b
./bin/tlvb synthesize MY-CASE-001 --tier 2 --active-search
./bin/tlvb report MY-CASE-001 --tier 3 --format html,csv,json --language ja

# (任意) ルールを自前で再生成するときだけ submodule + LLM が必要。
#   setup.sh が vendored の SQL cache を import 済みなので通常は不要。
git submodule update --init --recursive          # Sigma / Hayabusa / mitre-attack
./bin/tlvb rules build --max-rules 100

# read-only MCP サーバ (Tier 0): stdio で MCP クライアントから接続
./bin/tlvb mcp-serve
```

TLVB は **API ファースト**:LLM トランスポートはリポジトリルートの `.env.local`
に一度だけ設定します。TLVB は全サブコマンドの起動時にこれを読み込みます。
**Anthropic API**(`ANTHROPIC_API_KEY`)または **Vertex AI**(Google Cloud 上の
Anthropic、サービスアカウントキー経由)を使います。

```
# TLVB はリポジトリルートの .env.local を起動時に読み込む。シェル環境変数がファイルより優先。
# トランスポートは1つだけ設定する。両方ある場合は Anthropic API キーが優先される。

# --- Anthropic API (推奨) ---
ANTHROPIC_API_KEY=sk-ant-...

# --- または Vertex AI (Google Cloud 上の Anthropic、サービスアカウントキー) ---
# サービスアカウント JSON キーファイルのパスを指す:
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
# ...またはパスの代わりにキーを単一行 JSON 文字列でインライン指定:
# GOOGLE_APPLICATION_CREDENTIALS_JSON={"type":"service_account", ...}
ANTHROPIC_VERTEX_PROJECT_ID=your-gcp-project   # 任意: 無ければ GOOGLE_CLOUD_PROJECT、さらに無ければキーの project_id
CLOUD_ML_REGION=global                          # 任意: Vertex リージョン。Claude が global エンドポイント提供なら "global"(それ以外は us-east5 等)
# TLVB_VERTEX_MODEL=claude-opus-4-8             # 任意: 自分のリージョンの正確な Vertex publisher model id
```

期待される出力込みの手順は [`docs/QUICKSTART.ja.md`](docs/QUICKSTART.ja.md)、設計全体は [`docs/DESIGN.md`](docs/DESIGN.md) を参照。

## 工夫した点 — なぜこの設計か

**設計思想:再現性はシグネチャ、文脈は LLM。** LLM 単体は非決定的で、同じ証拠でも
2 回走らせれば 2 通りの物語が出てくる。そこで TLVB はまずシグネチャで再現性のある
ベースラインを固め(Tier 1A, **runtime LLM ゼロ**)、そのベースラインを *文脈として*
LLM に渡し、シグネチャでは表現しきれない過検知と見逃しを探させる。AI を持ち込む
重要な狙いの一つはまさにこの相互補完 — **シグネチャの速度 × LLM の文脈理解** — で、
見逃しと過検知の双方を同時に押し下げることにある。

**見逃しを減らす。** Tier 1B の異常検知エージェントは Tier 1A のシグネチャ所見を
文脈として読み込み、シグネチャでは言い表しにくいもの — 業務時間外(オフアワー)の
実行・不審なパス・稀少なプロセス・近接して起きた事象 — を LLM で抽象パターンとして
抽出する。必要なら新しい検索クエリを提案する。続く Tier 2 は、あるシグネチャヒットを
起点に周辺ログを **能動探索 SQL** で深掘りして裏取りし、**痕跡が無ければ別仮説へ
切り替える**。

**過検知を減らす。** LLM はシグネチャヒットを周辺文脈で評価し、正規運用由来のノイズ
(プロビジョニング操作の痕跡など)を切り分ける。各所見を **`confirmed`**(シグネチャに
よる一致)と **`inferred`**(LLM 推論)に区別したうえで、重要度ベースの自動承認と
人間の Review Gate で誤検知を落とす。

**必要なら実ファイルの中身を見る。** 解析の中でファイルの中身を確認したくなったとき、
LLM はファイルを名前で要求し、TLVB は Evidence(ディスクイメージ / triage 収集物)を
**read-only** でマウントして当該ファイルだけを `extractions/on-demand/` に抽出し、
中身を LLM に戻す — シェルは介さず、元の証拠には一切触れない。

**低コスト設計。** LLM が介在するのは、文脈理解が本当に効く数カ所だけに限定している。
Tier 1A は runtime で何も払わず(コストは build 時に 1 度だけ)、runtime の LLM 予算は
異常推論とタイムライン統合にのみ充てる。

**改善につながる Audit ログ。** Audit トレイルにはプロンプトだけでなくエージェントの
*思考* — 立てた **open questions** とそれに対する **answer** — まで記録する。これにより
失敗したとき *なぜそう結論したのか* を辿れ、原因を当て推量せずに改善につなげられる。

**ケースをまたいで学習する。** LLM があるケースのために自分で考えたクエリが hit し、
*かつ* そのケースを越えて一般化できる(ケース特有の情報を除いても効果が残る)とき、
TLVB はそれを candidate から **canonical なカスタムシグネチャ**へ昇格させ、以降すべての
ケースで再利用する。

## 検出能力(2026-05-29 実機検証)

86 MB の Win11 トリアージ zip を 1 コマンドで処理:

| 段 | 件数 | 例 |
|---|---|---|
| Tier 0 unified_events | 470,372 | mft 459k / evtx 5.6k / hayabusa 1k / amcache 2k / lnk 11 / ... |
| Tier 1A cached SQL | 3 | Eventlog Cleared / LSASS Dump Keyword In CommandLine 等 |
| Tier 1A Hayabusa pass-through | 32 | Mimikatz Execution / Suspicious Eventlog Clearing / etc. |
| Tier 1B Skills-driven Anomaly | 4 | mimi.exe+procdump masquerade / Anti-recovery cluster (vssadmin+wbadmin+bcdedit) 等 |
| Tier 2 attack-chain narrative | 2 clusters | 主活動 13:50-14:23 / 翌朝 06:32 RDP 再侵入 (16.5h dwell time) |
| Tier 2 active-search | 6 SQL | "procdump → mimi.exe リネーム" を amcache で SHA1 完全裏付け |
| Tier 3 HTML report | 26 KB | ブラウザ直開き可 (inline CSS, dark mode) |

総時間: **約 5 分**(parse は別、analyze+synthesize+report のみ計測)。

## 設計判断

- **Tier 1A runtime は LLM ゼロ**:cached SQL を実行するだけ。LLM コストは
  build 時に 1 度だけ (~ルール 1 本あたり数円、Sonnet 4.6)
- **rule_id は上流の原 ID を改変しない**:Sigma UUID / STIX T-number / Hayabusa
  UUID をそのまま使い、`rule_source` 補助カラムで分離
- **Sysmon 専用ルールはデフォルト除外**:実 IR で Sysmon 未導入が多いため。
  `requires_artifact` で動的有効化可
- **Severity ベース auto-approve**:critical/high はレビュー必須、それ以外は
  自動 approve。手動 override 可

## セキュリティと human-in-the-loop

ガードレールはプロンプトではなくコードで強制している:MCP サーフェスは **read-only**
(`execute_shell` なし、DB は `access_mode=read_only` でオープン)、active-search の SQL は
**SELECT のみ / 単一バインド / DDL 禁止**で検証、Tier 1A は **runtime で LLM を呼ばない**、
元の証拠は決して変更しない。各 Review Gate での承認/却下は**人間のみ**の操作で、
エージェントに自己承認の能力は無い。詳細は [`docs/SECURITY_GUARDRAILS.md`](docs/SECURITY_GUARDRAILS.md)
と [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §2-§4 を参照。

## 主要ドキュメント

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — エンドツーエンドのパイプライン、セキュリティ境界、自己修正(図つき)
- [`NEW_CONTRIBUTIONS.md`](NEW_CONTRIBUTIONS.md) — ハッカソンの新規実装と流用基盤の差分
- [`docs/ACCURACY.md`](docs/ACCURACY.md) — 検出精度 / 誤検出 / 見落とし / ハルシネーションの自己評価
  - [`eval/winrm_spray_accuracy.md`](eval/winrm_spray_accuracy.md) — WinRM-spray データセットのケース別精度自己評価(過剰主張抑止シナリオ: 認証情報窃取が Defender/AMSI に遮断されたケース)
- [`docs/QUICKSTART.ja.md`](docs/QUICKSTART.ja.md) — 詳細な手順(自分で試す方法込み)
- [`docs/USER_GUIDE.ja.md`](docs/USER_GUIDE.ja.md) — 初心者向け完全ガイド + 用語集
- [`docs/EVIDENCE_DATASETS.md`](docs/EVIDENCE_DATASETS.md) — TLVB が何でテストされ、データがどこから来たか
- [`docs/EXECUTION_LOG.md`](docs/EXECUTION_LOG.md) — エージェント実行ログ & finding のトレーサビリティ
- [`docs/SECURITY_GUARDRAILS.md`](docs/SECURITY_GUARDRAILS.md) — 強制されるセキュリティ境界
- [`docs/DESIGN.md`](docs/DESIGN.md) — TLVB v0.1 設計書

## ライセンス

LICENSE 参照。
