# TLVB

**TLVB** — *Timeline Longa, Vita Brevis*
(タイムラインは長く、人生は短い。だから自動化で攻撃の痕跡を炙り出す)

*English: [README.md](README.md)*

Sigma / Hayabusa / ATT&CK STIX / skills-driven anomaly detection を組み合わせて、
Windows フォレンジック・アーティファクトから攻撃の痕跡を抽出し、
LLM が攻撃チェーンを再構成して HTML/CSV/JSON レポートまで吐く自律型 IR エージェント。

## 状態

🟢 **v0.1 主要パイプライン (a)-(g) 完走**。実機 Windows 11 トリアージで
攻撃シナリオ 8 step を end-to-end で検出・再構成・レポート出力できることを
2026-05-29 時点で確認済み。詳細は `docs/STATUS.md`。

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

詳細は `docs/DESIGN.md` 参照。

## 検出能力(2026-05-29 実機検証)

86 MB の Win11 トリアージ zip(`docs/STATUS.md §0 のテスト) を 1 コマンドで処理:

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

## 主要ドキュメント

- `docs/DESIGN.md` — TLVB v0.1 設計書
- `docs/STATUS.md` — 実装ステータストラッカー (single source of truth)
- `CLAUDE.md` — Claude Code 用ガイド + 設計確定事項の規約
- `docs/QUICKSTART.md` — 詳細な手順(動作確認込み)

## ライセンス

LICENSE 参照。
