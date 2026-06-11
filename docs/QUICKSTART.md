# TLVB Quickstart — 自分で試してみる

このドキュメントは「TLVB を実際に動かしてみたい」人向けの手順書です。
SIFT Workstation を主な前提にしていますが、Linux + Claude Code CLI が
入っていればどこでも動きます。

すべてのコマンドは **このリポジトリのクローン先で(リポジトリのルート)** 実行する前提で書いています。
本文中のパスはすべてリポジトリルート相対表記です。

所要時間の目安:

| 項目 | 時間 | LLM 呼び出し |
|---|---|---|
| 0a. ビルド + ヘルプ確認 | 2 分 | なし |
| 0b. サンプル EVTX を取得 | 1 分 | なし |
| 1. MCP サーバ経由で覗く | 5 分 | なし |
| 2. Review Gate 1 を体験する | 5 分 | なし(Step 4 か 5 完了が前提) |
| 3. 小さい新規ケースで `analyze --tier 1a` (任意で 1b) | 5–10 分 | Tier 1A なし / 1B 1 回 |
| 4. 小さい新規ケースで全パイプライン (`run`) | 35 分 | あり (11 回) |

---

## 前提

```bash
which claude && claude --version    # Claude Code CLI(--engine claude-code 用、推奨)
which go && go version              # Go 1.25.5+(apt install golang-go で OK)
which python3 && python3 --version  # 3.11+
which dotnet && dotnet --version    # 9.x(EZ Tools 実行用)
ls /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll   # 必須パーサ(SIFT 標準パス)
```

`ANTHROPIC_API_KEY` は **不要** です。Claude Code CLI のセッション認証を
そのまま使うので、別途キーをセットしなくても LLM 呼び出しが走ります
(API モードで動かしたい場合は `--engine anthropic-api` + `export ANTHROPIC_API_KEY=...`)。

---

## 0a. ビルド (初回のみ)

```bash
# リポジトリのクローン直後、ルートに居る前提
./scripts/setup.sh           # 依存検証 + .venv 作成 + go build
./bin/tlvb version
# → tlvb 0.1.0-dev
```

> Ubuntu 24.04 等で `python3-venv` 未導入のため `.venv` 作成に失敗する場合は
> `./scripts/setup.sh --auto-install-deps` を渡すと sudo apt 越しに自動導入します
> (それ以外のフラグなしの場合は手動導入を促すメッセージのみ)。

> `--engine anthropic-api` を常用する場合は、リポジトリルートに `.env.local`
> を置いて `ANTHROPIC_API_KEY=...` を書き、`tlvb serve --env-file .env.local`
> で起動するとブラウザ UI からも自動的に API 経由で動きます。

### 0a-bis. altpf (Prefetch primary engine) について

Prefetch のパースは **altpf** (Linux ネイティブ Go、PECmd 互換 CSV、LastRun + PreviousRun0..6 完備、~1000x Plaso) が primary、Plaso `psteal.py` が fallback です。

**`./scripts/setup.sh` を実行した時点で `/opt/altpf/altpf` に v0.5.1 が自動 install されています** (gh / curl で fetch → SHA-256 二段検証 → 設置、idempotent)。追加の手作業は不要です。

特殊ケースだけ手動操作が必要です:

```bash
./scripts/install_altpf.sh --check          # 既設の verify だけ (download なし)
./scripts/install_altpf.sh --force          # 再 install (バージョン更新したい時)
./scripts/install_altpf.sh                  # setup でスキップされた時の手動再 install
```

altpf が無くてもパース自体は走ります (Plaso fallback / LastRun のみ)。どの経路で動いたかは **UI の Audit タブの parse コマンドで判別**できます: `command` 列が `/opt/altpf/altpf -d ...` なら altpf、`psteal.py --source ... --parsers prefetch` なら Plaso fallback です。

ヘルプ:

```bash
./bin/tlvb help
```

サブコマンド一覧が出ます。各サブコマンドは `-h` で詳細フラグが出ます:

```bash
./bin/tlvb analyze -h
./bin/tlvb synthesize -h
./bin/tlvb run -h
```

## 0b. サンプル EVTX データを取得

検証用には **公開コレクション** の
[**EVTX-ATTACK-SAMPLES**](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
(MITRE ATT&CK Tactic 別に整理された約 200 evtx)を使うのが最短です。

```bash
# 任意の場所に clone(SIFT 慣習なら /cases/、$HOME 配下でも OK)
EVTX_DIR=./evtx-samples       # ← お好きなパスで
sudo mkdir -p "$(dirname $EVTX_DIR)" && sudo chown $USER "$(dirname $EVTX_DIR)" 2>/dev/null
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git "$EVTX_DIR"

# 確認
ls "$EVTX_DIR/Persistence/" | head -3
```

> **注**: 以後の手順で `$EVTX_DIR` と書いた箇所は、上で設定した変数を指します。
> 別のシェルで作業する場合は再度 `export EVTX_DIR=...` してください。
> 任意の `.evtx` ファイルが入った任意のディレクトリで動くので、Windows 機の
> `C:\Windows\System32\winevt\Logs\` から取ってきた evtx でも構いません。

---

## 1. MCP サーバ経由でケースを覗く (LLM 呼び出しなし)

TLVB の Tier 0 MCP サーバは、Claude Code / Cursor / 任意の MCP
クライアントから繋げて、ケースの中身を read-only で問い合わせるのに
使えます。

```bash
# 起動 (stdio モード — クライアントから接続して使う)
./bin/tlvb mcp-serve --log-level info
```

サーバ単体で「JSON-RPC を 1 ターン送る」スモークテストを以下のように
書けます(初回はケースが空なので `list_cases` の結果も空です):

```bash
{
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"smoke","version":"0"},"capabilities":{}}}'
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_cases","arguments":{}}}'
  sleep 0.3
} | ./bin/tlvb mcp-serve --log-level error 2>/dev/null | python3 -m json.tool
```

公開ツール (全 19 — 主要 10 個を抜粋。全リストは上の `tools/list` 出力で確認):

| Tool | 用途 |
|---|---|
| `list_artifacts` | サポートしているアーティファクト種別 |
| `get_artifact_definition` | 1 アーティファクトの詳細定義 (caveats 含む) |
| `list_cases` | 登録済みケース一覧 |
| `get_case_status` | 1 ケースの詳細 + parse 結果 |
| `list_evidence` | ケースの evidence 登録情報 |
| `get_unified_events` | 解析済みイベントを SQL like フィルタで取得 |
| `get_parse_result` | 個別パーサの実行コマンド・成否・stderr |
| `list_findings` | ケース内の AI 発見事項を tactic / state でフィルタ |
| `get_finding` | 1 finding の詳細(evidence 配列・confidence 等) |
| `health` | サーバ生存確認 |

**全部 read-only**。MCP 経由で `parse` / `analyze` を引き起こすことは
構造的にできません (CLAUDE.md「`execute_shell` は MCP に絶対公開しない」)。

---

## 2. Review Gate を体験する (LLM 呼び出しなし)

> **主経路は Web UI の Review Gate 1A (署名 findings) / 1B (異常 findings)** です
> (`tlvb serve` → Findings タブ)。これらは Tier 1A の `findings/by-rule/` と
> Tier 1B の `findings/by-skill/` を読み、重要度ベースの自動承認やクラスタ単位の
> 一括承認に対応します。
>
> 以下の CLI `tlvb review` は **legacy (TacticReport 形式) 専用**のデモで、
> 新パイプライン (tier1a/1b) の findings は読めません。`tlvb analyze --legacy`
> 系の tactic-agent findings がある場合のみ動きます。
> (以下の例では `MY-TEST-001` を使います。)

```bash
CASE=MY-TEST-001    # Step 3 / 4 で作ったケース ID に置き換える

# 一部の findings ファイルだけコピーしてレビュー操作の対象にする
TEST=/tmp/tlvb-review-test
mkdir -p $TEST/findings
cp outputs/cases/$CASE/findings/persistence.json $TEST/findings/

# レビューセッション開始 (10 finding ほど出てくる)
./bin/tlvb review $CASE \
    --findings-dir $TEST/findings \
    --examiner "$USER"
```

操作キー:

| キー | 動作 |
|---|---|
| `a` | 承認 (`approved=true` を付与) |
| `r` | 拒否 (`rejected=true` + reason 入力) |
| `s` | スキップ (状態未変更) |
| `S` | 残り全スキップ (状態未変更) |
| `q` | 中断 (これまでの状態は保存) |

セッション終了後、ファイルにフラグが書かれているのを確認:

```bash
python3 -c "
import json
r = json.load(open('$TEST/findings/persistence.json'))
for f in r['findings']:
    state = 'unreviewed'
    if f.get('approved'): state = 'APPROVED by ' + f.get('reviewed_by','')
    elif f.get('rejected'): state = 'REJECTED: ' + f.get('reject_reason','')
    print(f'  {f[\"finding_id\"]}: {state}')
"
```

承認済みのみで HTML を再生成 (`--only-approved`):

```bash
./bin/tlvb synthesize $CASE \
    --findings-dir $TEST/findings \
    --out $TEST/synthesis.json
./bin/tlvb report $CASE \
    --synthesis $TEST/synthesis.json \
    --out-dir $TEST/reports \
    --only-approved \
    --format html
```

`$TEST/reports/report.html` を任意のブラウザ(`xdg-open` / `firefox` / `chromium-browser`)
で開くと、§5 Findings by Tactic は承認済みだけになります。

---

## 3. 小さい新規ケースで Tier 1A を試す (LLM 呼び出しなし、任意で Tier 1B)

EVTX サンプル `Other` (~8 ファイル / 750 events) で Persistence Agent
だけ走らせます。

```bash
# 0b で設定した EVTX_DIR を引き継ぎ
EVTX_DIR=${EVTX_DIR:-./evtx-samples}

# 3-1: ケース登録
./bin/tlvb case init \
    --case-id MY-TEST-001 \
    --name "first-test" \
    --examiner "$USER"

# 3-2: Tier 0 — 8 EVTX をパースして DB に投入 (~3 秒)
./bin/tlvb parse \
    --case-id MY-TEST-001 \
    --evidence-id EV-OTHER-001 \
    --input "$EVTX_DIR/Other" \
    --only evtx

# 3-2-bis: 複数 Evidence を一発で登録したい場合は --inputs(★v0.3 #1)
# ./bin/tlvb parse \
#     --case-id MY-TEST-001 \
#     --inputs "$EVTX_DIR/Other,$EVTX_DIR/Persistence" \
#     --only evtx

# 3-3: Tier 1A — キャッシュ済み署名 SQL を実行 (LLM 不要・数秒〜数十秒)
./bin/tlvb analyze MY-TEST-001 --tier 1a

# 任意: Tier 1B — 異常ハンター (LLM、~数分)。API key 不要の claude CLI を使用
./bin/tlvb analyze MY-TEST-001 --tier 1b --skill anomaly_hunter

# 3-4: 出力を見る (Tier 1A は by-rule/、Tier 1B は by-skill/)
ls -R outputs/cases/MY-TEST-001/findings/
cat outputs/cases/MY-TEST-001/findings/by-rule/sigma/*.json | python3 -m json.tool | head -50
```

Tier 1A は LLM を呼ばないので API key も claude CLI も不要です。Tier 1B のみ
LLM を使い、`claude` CLI があれば API key 無しで動きます。

---

## 4. 全パイプラインを試す (Tier 1A は LLM ゼロ / Tier 1B + Tier 2 で LLM 数回・〜$1・約 10 分)

```bash
EVTX_DIR=${EVTX_DIR:-./evtx-samples}

./bin/tlvb run MY-FULL-001 \
    --tier all \
    --evidence "$EVTX_DIR/Other" \
    --name "first-full-run" \
    --examiner "$USER"
```

これ 1 コマンドで Tier 0→1A→1B→2→3 が走ります:

```
[run] case-init  ok  (new case)
[run] tier0      ok  in 3.2s    (parser → unified_events)
[run] tier1a     ok  in ~10s    (cached signature SQL + Hayabusa, LLM=0)
[run] tier1b     ok  in ~4min   (anomaly_hunter skill, LLM)
[run] tier2      ok  in ~3min   (Timeline Analysis, LLM)
[run] tier3      ok  in 0.5s    (HTML/CSV/JSON DFIR report, LLM=0)
[run] DONE  case=MY-FULL-001  total=~8min
```

1 段が失敗してもケース全体は止まりません — `[FAIL]` でログされて次へ進みます。

途中段階だけスキップしたい時 (`--skip-1a` / `--skip-1b` / `--skip-2` / `--skip-report`):

```bash
# Tier 0 (parse) はもう済んでる、Tier 1A からやり直し
./bin/tlvb run MY-FULL-001 --tier all --skip-parse

# Tier 1A/1B までは終わった、Tier 2 から
./bin/tlvb run MY-FULL-001 --tier all --skip-parse --skip-1a --skip-1b

# Tier 2 の能動探索を有効化 (広域 SQL)
./bin/tlvb run MY-FULL-001 --tier all --skip-parse --active-search
```

完了後:

```bash
# レポートを開く(GUI セッションのある端末から)
xdg-open outputs/cases/MY-FULL-001/reports/report.html
# 上が動かなければブラウザを直接呼ぶ:
#   firefox outputs/cases/MY-FULL-001/reports/report.html
#   chromium-browser outputs/cases/MY-FULL-001/reports/report.html

# DB の中身を確認
python3 -c "
import duckdb
con = duckdb.connect('outputs/cases.duckdb', read_only=True)
print(con.execute('SELECT * FROM cases').fetchall())
print(con.execute('SELECT artifact_id, COUNT(*) FROM unified_events WHERE case_id=? GROUP BY 1', ['MY-FULL-001']).fetchall())
"
```

レポートの解説は `outputs/cases/MY-FULL-001/reports/HANDOFF.md` を併読
してください。チームに HTML を配布する際もそのファイルを同梱します。

---

## 5. 自分の Evidence で動かす

`$EVTX_DIR/Other` の代わりに、自分の調査対象を渡します。
入力は **ディレクトリ または .zip** です(例: Washizukami-Collector や
CDIR-Collector の出力 zip もそのまま渡せます — collector.log など
auxiliary ファイルがあれば自動で拾います)。

```bash
# (例) 隔離済みのインシデント zip
./bin/tlvb run INC-2026-9001 \
    --evidence /path/to/triage_collector.zip \
    --evidence-id EV-COLL-001 \
    --name "ACME-Corp-IR-Sep" \
    --examiner alice \
    --engine claude-code
```

zip は `outputs/cases/<id>/extractions/extracted/` に展開されます (元
ファイルは無変更)。

検出可能アーティファクト(主要・抜粋):

| 種別 | 検出パターン | 必要ファイル |
|---|---|---|
| EVTX | `**/*.evtx` | Windows Event Logs |
| Amcache | `**/Amcache.hve` | レジストリハイブ |
| Prefetch | `**/Prefetch/*.pf` | %SystemRoot%\Prefetch |
| Registry | parent dir of `SOFTWARE`/`SYSTEM`/`NTUSER.DAT` 等 | レジストリハイブ群 |
| Scheduled Tasks | `**/System32/Tasks/**` | XML タスクファイル |
| Shimcache | `**/SYSTEM` (hive) | SYSTEM ハイブ |
| MFT | `**/$MFT` | $MFT |
| LNK / Jumplists / Recycle Bin | 各種パターン | Windows shell artifact 群 |
| Browser History | `**/User Data/*/History`、`**/Profiles/*/places.sqlite` | Chrome/Edge/Firefox |
| Washizukami audit log | `**/collection.log` | Washizukami-Collector の出力 |

含まれない種別は MVP 範囲外として無視されます (ログでスキップ表示)。
全パーサ一覧は `config/artifacts.yaml` 参照。

---

## 6. 既存ケースを再解析する

ルールコーパスを再 build した / 新しいスキルを追加した、というケースで使えます:

```bash
CASE=MY-FULL-001    # 自分のケース ID

# Tier 1A を回し直す (キャッシュ署名 SQL、LLM 不要)
./bin/tlvb analyze $CASE --tier 1a

# 既存ケースに Tier 1B (anomaly_hunter) を追加で走らせる
./bin/tlvb analyze $CASE --tier 1b --skill anomaly_hunter

# Tier 2 で統合し直し (既定。--active-search で広域探索)
./bin/tlvb synthesize $CASE

# レポート再生成 (既定で Tier 3)
./bin/tlvb report $CASE --format html,csv,json
```

特定の Tier 1B スキル (lens) だけ再走:

```bash
./bin/tlvb analyze $CASE --tier 1b --skill credential_access
./bin/tlvb synthesize $CASE
./bin/tlvb report $CASE --format html
```

---

## 7. Web UI で全部やる

CLI ではなく WebUI を使う場合:

```bash
./bin/tlvb serve --port 8080
# → ブラウザで http://localhost:8080/
# → リモート(VM 外)からアクセスする場合は http://<VM-IP>:8080/
```

WebUI 側では:
- 新規ケース作成 → Parse → Analyze All → Synthesize → Generate Report が
  4 ボタンで一直線(各ボタンの右に進捗バー + ETA)
- Findings タブで Approve / Reject(= Review Gate 1)
- Events タブで Review Gate 0(parse 結果の承認)
- 浮動 💬 ボタンで TLVB Assistant チャット

詳細は `docs/USER_GUIDE.md` 参照。

---

## 8. うまく動かない時 (Troubleshooting)

### `claude: command not found`
Claude Code CLI が PATH に無い。`/usr/bin/claude` か `~/.local/bin/claude`
にあるか確認。なければ `npm install -g @anthropic-ai/claude-code` で導入。
代替として `--engine anthropic-api` + `ANTHROPIC_API_KEY` 環境変数。

### `engine=anthropic-api requires ANTHROPIC_API_KEY`
`--engine claude-code` を明示するか、`export ANTHROPIC_API_KEY=sk-ant-...`
してから実行。

### `claude CLI failed (...): Not logged in · Please run /login`
Claude Code に `--bare` を渡している、または初回起動。`claude` を
インタラクティブに 1 回起動して `/login` するとセッションが生まれる。

### `xdg-open: no method available`
ヘッドレスシェル(Claude Code 経由など)からブラウザを起動できない。
GUI 端末から `chromium-browser <path>` か `firefox <path>` を実行する、
または `! chromium-browser <path>` を Claude Code プロンプトに打つ
(`!` プレフィックス指示)。

### `dotnet: command not found`
EZ Tools が動かない。`apt install -y dotnet-runtime-9.0` または
SIFT 標準の `/usr/bin/dotnet` パスを確認。

### `error: externally-managed-environment` (PEP 668)
Ubuntu 24.04+ で system pip が拒否される。`scripts/setup.sh` が
`./.venv/` を作って `duckdb` をそこに入れます。venv モジュールが無ければ
`sudo apt install python3-venv python3-full` を先に。

### `case has no registered evidence`
`tlvb parse` を先に走らせる(または WebUI から Parse ボタン)。

### Tier 1B (anomaly_hunter) が `status=partial` で終わる
LLM が evidence 不足を保守的にマークした正常動作。`partial` 自体は
失敗ではなく、Examiner レビューを促すサイン。

### Corrector が `retried_no_change` ばかり返す
LLM が一貫した所見を持っているということ — 健全。整合性矛盾は
Examiner の手調査が必要なケースとして残ります。

### DuckDB lock エラー
複数の `tlvb` プロセスが書き込みで開いている。`pkill tlvb`
してから再実行。MCP サーバ + parse の同時実行で出ます。

### Web UI Analyze All が 409 で弾かれる
Review Gate 0 が未承認。Events タブで各 parse 結果を Approve するか、
「Skip Review Gate 0」をチェック、または `?force=true` を URL に付ける。

### Parse Results に mft / usn_journal / shellbags / browser_history が出ない (Wave 15 で解消)
**Wave 15 以降は自動で対応済**。`Web/Chrome/Tanaka_Default_History` のような collector が prefix を付けた flatten 命名 (TANAKA / KAPE-NTFS bundled / FastIR 系) を、`parsers/_collector_prefix.py` の basename regex で吸収します。**それでも UI で見当たらない artifact** は次の 4 つのどれかです:

- **🟢 OK**: バッジが緑なら parse 成功 (row_count > 0)
- **🟡 EMPTY**: parse 成功したが 0 行 (collector がファイルだけ収集して中身が空、等)
- **⚪ NOT_PRESENT**: 入力にそのアーティファクトが含まれていない (例: triage zip が `Users/*/AppData/` を収集していない → `jumplists` `lnk` `recyclebin` `win10timeline` は全部 NOT_PRESENT)。**バグではなく仕様**
- **🔴 FAIL**: parser はインストールされていて入力にもファイルがあるが、parse 中にエラー (ファイル破損 / ツール無し等)

Wave 15 以前のバージョンでは検出漏れすると UI に「行が出ない」だけで判別できませんでしたが、現在は実装済 17 種すべてが必ず Parse Results に行を持ちます。

### Prefetch のパースコマンドが `psteal.py` になっている / Events タブで engine=plaso
**設計通りの fallback 経路です**。Prefetch primary は altpf (`/opt/altpf/altpf`)、altpf が未配置だと Plaso `psteal.py` に自動 fallback します (graceful degradation)。altpf を入れたい場合は:

```bash
./scripts/install_altpf.sh --check     # 現状確認
./scripts/install_altpf.sh             # /opt/altpf/altpf を v0.5.1 で配置
```

altpf 配置後に再 parse すると Audit タブの command 列が `/opt/altpf/altpf -d ...` に変わり、Events の `payload.engine` が `altpf` になります。altpf は LastRun + PreviousRun0..6 を独立した unified_event 行 (`run_kind` フィールドで識別) として展開するため、Plaso fallback (LastRun のみ) よりも実行履歴の解像度が高くなります。

---

## 9. 主要パスの目印(リポジトリルート相対)

```
./
├── bin/tlvb                       # ビルドした CLI
├── outputs/
│   ├── cases.duckdb                   # 全ケース横断 DB (read-only mostly)
│   ├── rules.duckdb                    # Tier 1A ルール SQL キャッシュ
│   └── cases/<case_id>/
│       ├── findings/
│       │   ├── by-rule/<source>/<id>.json  # Tier 1A 署名 findings
│       │   └── by-skill/<skill>.json       # Tier 1B 異常 findings
│       ├── extractions/               # パーサ中間データ
│       ├── synthesis.json             # Tier 2 CaseSynthesis
│       ├── parse_review.json          # Review Gate 0 のステート
│       ├── timeline_gate.json         # Review Gate 2 のステート
│       ├── actions.jsonl              # 監査トレイル
│       └── reports/
│           ├── report.html            # メイン成果物 (Tier 3)
│           ├── report.json            # 機械可読版
│           ├── findings.csv           # Excel 取り込み用
│           ├── mitre.csv  clusters.csv
│           ├── timeline.csv  ioc.csv
│           └── HANDOFF.md             # 配布用説明
├── skills/<skill>.md                  # Tier 1B スキル (既定 anomaly_hunter)
├── config/artifacts.yaml              # アーティファクト定義
├── parsers/                           # Tier 0 (Python)
├── internal/                          # Tier 1〜3 + web (Go)
└── docs/
    ├── DESIGN.md                      # 設計書 v0.3
    ├── STATUS.md                      # 実装ステータストラッカー
    ├── USER_GUIDE.md                  # 初心者向け完全ガイド + 用語集
    ├── tool_inventory.md              # SIFT ツール検証結果
    ├── valhuntir_analysis.md          # 参考リポジトリ分析
    └── QUICKSTART.md                  # 本ファイル
```

evidence(`$EVTX_DIR` や自分の調査対象 zip)は **read-only**。書き込まれる
場所は **すべて `outputs/`** に集約されています(CLAUDE.md「証拠は read-only」)。

---

## 10. 次のステップ

- 自分の調査ケースで `tlvb run` を 1 度通す
- HTML レポートをチームに配布(zip + SHA-256 確認 — `HANDOFF.md` 参照)
- `skills/<skill>.md` (Tier 1B のレンズ) を自社の TTPs に合わせてカスタマイズ
  (新しい観点のクエリ意図を足す)
- `rules/custom/` に自社ルールを足して `tlvb rules build` で Tier 1A に反映
- `config/artifacts.yaml` に独自パーサを追加(Linux syslog 等)
- `internal/synthesizer/consistency.go` に独自ルール R5+ を追加

困ったら `docs/DESIGN.md`(システム設計書 v0.3)、`docs/STATUS.md`
(実装トラッカー)、`docs/USER_GUIDE.md`(初心者向け完全ガイド)を併読してください。
