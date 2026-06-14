# TLVB ユーザーガイド (はじめての方向け)

このドキュメントは、セキュリティの専門知識がない方でも TLVB を
使えるようにするための手引きです。

専門用語は本文中ではできるだけ避け、必要に応じて補足を入れています。
詳しい用語の定義は **巻末の Appendix A: 用語集** にまとめてあります。
本文中の **太字の用語** は用語集で説明しています。

---

## 目次

- [1. TLVB って何？](#1-tlvb-って何)
- [2. 何ができるの？](#2-何ができるの)
- [3. 5分でさわってみる](#3-5分でさわってみる)
- [4. Web UI 完全ガイド](#4-web-ui-完全ガイド)
  - [4.1 起動とアクセス](#41-起動とアクセス)
  - [4.2 ダッシュボード画面](#42-ダッシュボード画面)
  - [4.3 ケース詳細画面](#43-ケース詳細画面)
  - [4.4 パイプライン (4 つのステップ)](#44-パイプライン-4-つのステップ)
  - [4.5 Findings タブ — 何が起きたかの一覧](#45-findings-タブ--何が起きたかの一覧)
  - [4.6 Timeline タブ — 時系列で見る](#46-timeline-タブ--時系列で見る)
  - [4.7 IOC タブ — 指標の一覧](#47-ioc-タブ--指標の一覧)
  - [4.8 MITRE Map タブ — 攻撃手口の地図](#48-mitre-map-タブ--攻撃手口の地図)
  - [4.9 Report タブ — レポート閲覧とダウンロード](#49-report-タブ--レポート閲覧とダウンロード)
  - [4.10 Audit タブ — 操作履歴](#410-audit-タブ--操作履歴)
- [5. CLI でも同じことができる](#5-cli-でも同じことができる)
- [6. よくあるトラブル](#6-よくあるトラブル)
- [Appendix A: 用語集](#appendix-a-用語集)
- [Appendix B: 全体像の図](#appendix-b-全体像の図)

---

## 1. TLVB って何？

「**サイバー攻撃にあったかもしれないパソコンの中身**を、自動で調べてくれる
道具」です。

たとえば、会社のパソコンが誰かに侵入されたかもしれないと疑われたとき、
専門家(**フォレンジック**の技術者)はそのパソコンの中身を取り出して、
ログファイルや設定ファイルなどを一つひとつ調べていきます。

これは時間がかかる作業で、ベテランでも 1 件あたり 数日 〜 数週間 かかる
ことが普通です。

TLVB は、その**最初の絞り込み**を **AIエージェント** に任せて
自動化し、人間は「重要そうな発見」だけを確認すればよくする道具です。

> **スコープ**: TLVB が扱うのは **Windows のインシデント対応におけるディスク
> フォレンジック**です。PC から triage ZIP やディスクイメージとして収集した
> **ディスク常駐**のアーティファクト(イベントログ・レジストリ・ファイルシステム・
> 実行痕跡・ブラウザ履歴 など)を対象にします。ライブの**メモリフォレンジック**や
> **ネットワーク / パケット(PCAP)フォレンジック**は対象外です。

```
[攻撃された疑いのあるPCのデータ] → [TLVB] → [疑わしい点の一覧]
                                       ↓
                                  人間が確認 (承認/却下)
                                       ↓
                                  [調査レポート (HTML/CSV/JSON)]
```

> **重要な原則**:
> TLVB は元の証拠データを **絶対に書き換えません**。
> すべての出力は別の場所(`outputs/cases/<ケースID>/`)に書き出されます。
> これは法的な場面で証拠として使える状態を保つためです。

---

## 2. 何ができるの？

### 入力

- パソコンから取り出した**証拠データ**
  (ZIPファイル、または抽出後のディレクトリ)

### 出力

| 出力物 | 説明 |
|---|---|
| **Findings (発見事項)** | 「ここに怪しい挙動があります」というリスト |
| **Timeline (タイムライン)** | 何時何分にどんなイベントが起きたか、時系列で並べたもの |
| **IOC (侵害指標)** | 攻撃の痕跡となる具体的な値(怪しいIPアドレス、ファイルのハッシュ値など) |
| **MITRE Map** | 「攻撃の手口」を業界標準の分類(**MITRE ATT&CK**)に当てはめた地図 |
| **HTML レポート** | 上記を全部まとめた人間向けの報告書 |
| **CSV / JSON** | Excel や他のツールで再利用するためのデータ |

### 自動化される作業

10 種類の調査(専門用語で「**Tactic** = 戦術」と呼びます。攻撃者がやる
ことのカテゴリのこと)を並行して行います。

| 番号 | 戦術 | 「攻撃者は何をしようとしていたか」 |
|---|---|---|
| TA0001 | **Initial Access** | どうやって入ってきたか |
| TA0002 | **Execution** | 何のプログラムを動かしたか |
| TA0003 | **Persistence** | 再起動後も居座る仕掛けを作ったか |
| TA0004 | Privilege Escalation | より強い権限を奪ったか |
| TA0005 | Defense Evasion | 痕跡を消そうとしたか |
| TA0006 | Credential Access | パスワード等を盗んだか |
| TA0007 | Discovery | 社内ネットワークを偵察したか |
| TA0008 | Lateral Movement | 別のパソコンに移動したか |
| TA0009 | Collection | データを集めたか |
| TA0040 | Impact | データを暗号化・破壊したか |

加えて **Anomaly Hunter (異常ハンター)** が、上記の枠に収まらない
「何かおかしい挙動」を探します。

---

## 3. 5分でさわってみる

すでにサンプルケース `INC-2026-0003` が用意されているので、すぐに
画面を眺められます。

### ステップ 1 — Web サーバを起動

```bash
cd tlvb            # git clone したリポジトリのルート
go build -o /tmp/tlvb ./cmd/tlvb
/tmp/tlvb serve --port 8080
```

> 起動したターミナルはそのまま開いたままにしておきます。
> 止めたいときは `Ctrl-C` を押します。

### ステップ 2 — ブラウザで開く

VM 上で起動した場合、**同じVM** のブラウザからアクセス:

```
http://localhost:8080/
```

**ホストPC** からアクセスしたい場合は、VMのIPアドレスを使います:

```bash
# VM上で IP を確認
hostname -I
# 例: 192.168.44.129
```

ホストPCのブラウザで `http://192.168.44.129:8080/` を開きます。
(数字は環境によって違います)

### ステップ 3 — サンプルケースを開く

ダッシュボード画面に `INC-2026-0003` のカードが表示されているので
**クリック**します。

ケース詳細画面が開いたら、

1. **Findings タブ**: 50件の発見事項が戦術別にグループ化されて並んでいます
2. **Timeline タブ**: 時系列で何が起きたか並んでいます
3. **MITRE Map タブ**: 攻撃の手口を地図状に俯瞰できます
4. **Report タブ**: 完成したHTMLレポートを iframe 内で見られます

これで雰囲気がつかめます。

---

## 4. Web UI 完全ガイド

### 4.1 起動とアクセス

```bash
/tmp/tlvb serve --port 8080 [--db PATH] [--outputs DIR]
```

| オプション | デフォルト | 説明 |
|---|---|---|
| `--port` | `8080` | リッスンするポート番号 |
| `--db` | `outputs/cases.duckdb` | ケース情報を保存するデータベースファイル |
| `--outputs` | `outputs/cases` | ケースごとの作業ディレクトリ |
| `--addr` | (空) | バインドアドレスを直接指定(例: `127.0.0.1:8080` でローカルのみに制限) |

> セキュリティ上の注意: デフォルトでは **すべてのネットワークインター
> フェース** で待ち受けます。社内ネットワークなど信頼できる環境でのみ
> 動かしてください。インターネット直結のサーバーで動かすのは推奨しません。

### 4.2 ダッシュボード画面

URL: `http://<host>:8080/`

最初に開く画面です。2 つのセクションがあります。

#### 新規ケース作成フォーム (上段)

| フィールド | 例 | 説明 |
|---|---|---|
| Case ID | `INC-2026-0042` | ケースを識別する名前。社内のチケット番号などに合わせると整理しやすい |
| Name | `Workstation alert from SOC` | このケースの簡単な説明 |
| Examiner | `tanaka` | 調査者の名前(あとで「誰が承認したか」の記録に使われます) |
| Timezone | `UTC` | タイムスタンプを表示するタイムゾーン |
| Language | `ja` | レポートの言語(`ja` = 日本語、`en` = 英語) |

「**Create case**」を押すと新しいケースが作られます。

#### ケース一覧 (下段)

各ケースがカードとして並びます。カードに表示されるバッジ:

| バッジ | 意味 |
|---|---|
| `N evidence` | 登録された証拠データの数 |
| `N events` | 解析済みのイベント数 |
| `N findings` | 発見事項の数 |
| `synth` | **Tier 2**(タイムライン統合)が完了済み |
| `report` | レポート生成済み |
| `no parse yet` | まだ何も処理していない |

カードをクリックするとそのケースの詳細画面に飛びます。

### 4.3 ケース詳細画面

URL: `http://<host>:8080/#/cases/<ケースID>`

画面の構成:

1. **ヘッダー**: ケースID・名前・調査者・作成日時。右上に「Delete case」ボタン
2. **パイプライン操作バー**: **🤖 Autopilot** ボタン (ワンクリック一気通貫実行) と、その後に各ステージのボタン (`Parse` → `Analyze All` → `Synthesize` → `Generate Report`)
3. **タブバー**: 8 つのタブ (`Status` / `Events` / `Findings` / `Timeline` / `IOC` / `MITRE Map` / `Report` / `Audit`)

> **削除について**: 「Delete case」を押すとデータベース上のケース情報と
> 作業ディレクトリ(`outputs/cases/<id>/`)が消えます。
> ただし元の証拠データ(別の場所)は触りません。

### 4.4 パイプライン (4 つのステップ)

> **2026-05 追加機能**:
> - **複数 Evidence 同時パース** (Issue #1 / v0.3 #1) — Parse モーダルで `+ Add evidence` ボタンで何件でも追加可能
> - **Review Gate 0 スキップ チェックボックス** (Issue #11/#12) — Parse / Analyze モーダルにあり、ON で parse 結果を自動承認して手動レビューを飛ばす(全パイプラインを走らせる下記の **🤖 Autopilot** ボタンとは別物)
> - **キャンセルボタン** (Issue #8) — 各ステップ実行中、進捗ブロックの下に **`✕ cancel`** ボタンが表示。誤実行や暴走時に途中中断可能(進捗バーが灰色イタリックの `canceled` 表示に切替)
> - **LLM アクセス事前警告** — Analyze モーダルを開いた時点で `.env.local` に LLM トランスポート(Anthropic API または Vertex AI)が未設定なら赤色警告が出ます(以前は実行後に発覚した)

#### 最短ルート: 🤖 Autopilot (ワンクリック)

操作バーの左端に **🤖 Autopilot** ボタンがあります。これは全パイプライン —
Parse → Analyze All → Synthesize → Generate Report — をワンクリックで一気通貫
実行し(両 Review Gate を自動スキップ)、findings・タイムライン・完成レポートまで
仕上げます。証拠を指定して開始し、進捗は **Status** タブで追えます。手早く全体を
見たいときはこれ、各段を人間が確認したいときは下の個別ボタンを使います。

#### 段階実行 (Review Gate を挟む)

下の各ステージボタンは同じパイプラインを 1 段ずつ、間に Review Gate を挟んで
実行します。順番に実行する必要があります。

```
[Parse]  →  [Analyze All]      →  [Synthesize]   →  [Generate Report]
証拠を       Tier 1A 署名SQL      Tier 2 が         Tier 3 が
分解する     (+任意で Tier 1B)    タイムライン統合   報告書化
```

各ボタンを押すと、確認用のモーダルが開いて細かいオプションを指定できます。
ボタンの右側にステータス(`idle` / `running...` / `ok` / `FAIL`)が
リアルタイムに表示されます(2秒ごとに自動更新)。

#### Step 1: Parse (パース)

証拠データの中に入っているログファイルや設定ファイルを、それぞれの
専用ツールで分解して、データベースに格納します。

入力モーダル:

| フィールド | 例 |
|---|---|
| Evidence path | `./evtx-samples` (証拠データのフォルダかZIP) |
| Evidence ID | `EV-001` (省略時は自動採番) |

処理時間: 証拠データの量によりますが、通常 5〜30 分。

> Parse が終わると、パースされたアーティファクトが **Events** タブに表示され、
> 解析の前にそこで承認/却下します(**Review Gate 0**)。「Review Gate 0 をスキップ」
> をチェックすれば自動承認も可能。**Status** タブは全ステージの進捗をライブ表示します。

#### Step 2: Analyze All (解析 — Tier 1A + 任意で Tier 1B)

**Tier 1A (シグネチャ)** が常に走ります: ルールコーパス (Sigma / Hayabusa /
STIX / custom / LOLBAS) を build 時に SQL 化したものをこのケースに対して
実行し、ヒットを finding 化します。**LLM を呼ばないので無料・数秒〜数十秒**で
完了します。任意で **Tier 1B (anomaly_hunter)** の LLM パスも有効化できます。

入力モーダル:

| フィールド | 説明 |
|---|---|
| Also run Tier 1B (anomaly_hunter, LLM) | チェックすると Tier 1B 異常ハンターも実行 (LLM 課金あり)。既定は OFF |
| Tier 1B model | 空欄でデフォルトモデル |

> **注意**: Tier 1A は LLM 不要・無料です。Tier 1B を有効にした場合のみ
> AI モデルを呼ぶのでトークン使用料 (1 ケース 〜$1 程度) がかかります。

処理時間: Tier 1A ≈ 数秒〜数十秒、Tier 1B (有効時) ≈ 数分。

#### Step 3: Synthesize (統合 — Tier 2)

**Tier 2 (タイムライン解析エージェント)** が Tier 1A / 1B の findings を
時間的にクラスタ化し、各クラスタ周辺の生タイムラインを LLM が解析して
**Kill Chain**(攻撃の流れ)・全体ストーリー・MITRE マッピングを推定します。
出力は `synthesis.json`。

入力モーダル:

| フィールド | 説明 |
|---|---|
| Active search | チェックすると各クラスタの未解明点について仮説駆動の広域 SQL を追加実行する (より網羅的・低速) |

> **注意**: Tier 2 は LLM を呼ぶのでトークン使用料がかかります (1 ケース 〜$1 程度)。
> 整合性チェック (R1-R4) や Corrector を伴う旧 Synthesizer を使いたい場合は
> CLI で `tlvb synthesize CASE_ID --legacy [--correct]` を使います。

処理時間: クラスタ数によりますが数分程度 (active search 有効時はさらに増加)。

#### Step 4: Generate Report (レポート生成)

統合結果を人間向けに整形します。

入力モーダル:

| フィールド | 説明 |
|---|---|
| Language | `日本語` または `English` |
| Only approved | チェックすると、Findings タブで承認した発見事項のみをレポートに含める |

処理時間: 数秒。

### 4.5 Findings タブ — 何が起きたかの一覧

このタブで「TLVB が見つけた疑わしい点」を一つずつ確認します。
これが **Examiner (調査者) の主な作業画面** です。

#### 表示

戦術ごとにグループ化され、各発見事項は次の情報を持ちます:

```
[high] T1543.003 — Create or Modify System Process: Windows Service
                                          F-persistence-001  [pending]

不審なWindowsサービスが複数のホストで作成された (spoolfool, msdhch, ...)

[展開] reasoning: なぜそう判断したかの根拠
[▸ N evidence rows] (クリックで展開)

[Approve] [Reject]
```

| 要素 | 説明 |
|---|---|
| **赤バッジ `high`** | 信頼度が高い(MUSTレビュー) |
| **黄バッジ `medium`** | 信頼度が中(できれば確認) |
| **緑バッジ `low`** | 信頼度が低い(誤検知の可能性あり) |
| **technique_id** | MITRE ATT&CK の **テクニックID**(調べる手がかり) |
| **summary** | 何が起きたかの要約 |
| **reasoning** | AIがそう判断した根拠 |
| **evidence rows** | クリックで展開すると、根拠となる元のログが見える |
| **finding_id** | この発見事項のID(`F-<戦術>-<連番>`) |

#### 承認 (Approve) と 却下 (Reject) — Review Gate

各発見事項には 2 つのボタンがあります:

- **Approve**: 「これは本物の侵害です」と判断 → 緑色の枠で表示される
- **Reject**: 「これは誤検知/問題なし」と判断 → 赤色の枠で表示される
  - 押すと**理由を入力するモーダル**が開きます(あとで監査用に残ります)

> **Review Gate**(レビュー・ゲート)とは:
> AI が出した結果を **人間が確認してから次の段階に進む仕組み** です。
> AI を信頼しすぎず、最終判断は必ず人間が行うことで、誤検知が
> 報告書に紛れ込むのを防ぎます。

承認状態は元の `findings/by-rule/<rule_source>/*.json` (Tier 1A) および `findings/by-skill/*.json` (Tier 1B) ファイルに書き戻されます。
レポート生成時に「Only approved」をチェックすれば、承認したものだけが
最終レポートに出ます。

#### 一括選択モード(2026-05 追加 — Issue #5/#10)

50 件以上の findings を 1 件ずつ Approve するのは大変なので、**チェックボックスによる一括操作** が使えます:

- 各 finding 行の左に **チェックボックス** があり、複数選択可能
- 戦術グループのヘッダーにも **「全選択」チェックボックス** があり、その戦術だけ一括選択可能
- 選択後、上部ツールバーの **`Approve selected` / `Reject selected` / `Reset selected`** で一括変更
- **`Approve all visible (N)`** ボタンで、現在表示中の(フィルタ後)全件を一括承認

#### フィルタ(Issue #4)

ツールバーの **`all` / `pending` / `reviewed`** ボタンで:
- **all**: 全 findings 表示
- **pending**: 未レビューのみ表示
- **reviewed**: 承認/却下済みのみ表示

選択状態とスクロール位置は維持されたままフィルタ切替できます。

#### 取り消し(Issue #7)

承認/却下した finding は、その行の右側に **`Reset` ボタン** が出ます。クリックすると pending 状態に戻り、再度 Approve/Reject ボタンが表示されます(誤って承認してしまった場合の救済策)。

#### 戦術グループの折りたたみ(Issue #6)

各戦術(Initial Access / Execution / Persistence 等)はデフォルトで **折りたたみ** 状態で表示されます。ヘッダーをクリックで展開/折りたたみ。長い findings リストでスクロール量を抑えるための変更です。

### 4.6 Timeline タブ — 時系列で見る

「いつ・どこで・何が起きたか」を時系列のテーブルで表示します。
攻撃の流れを追うのに使います。

#### Kill Chain ダイアグラム (上部)

`Initial Access → Execution → Persistence → ... → Impact` の流れで、
各段階の最も早いイベントを矢印付きで並べたものです。
攻撃者が **どういう順序で何をしたか** を一目で把握できます。

#### Timeline テーブル (下部)

| カラム | 内容 |
|---|---|
| Timestamp | 発生時刻 (UTC) |
| Tactic | どの戦術に分類されるか |
| Technique | より具体的な手口のID |
| Computer | どのパソコンで起きたか |
| Summary | 何が起きたかの一文 |

行は時刻順に並んでいます。

### 4.7 IOC タブ — 指標の一覧

**IOC (Indicator of Compromise = 侵害指標)** は、攻撃の痕跡となる
「具体的な値」のことです。例:

- 怪しいIPアドレス: `203.0.113.45`
- 怪しいドメイン: `evil-c2.example.com`
- 怪しいファイルのハッシュ値: `sha256:abc123...`
- 怪しいファイルパス: `C:\Users\Public\malware.exe`

IOC は「他のパソコンも同じ攻撃を受けていないか」を調べるときに使います。
社内の別のパソコンや、**SIEM**(セキュリティ監視システム)に
これらの値を流し込んでスキャンする、という使い方が一般的です。

#### 表示

種類別にグループ化されます。種類の例:

- `domain` (ドメイン)
- `ipv4` (IPアドレス)
- `sha256` / `sha1` / `md5` (ファイルのハッシュ値)
- `file_path` (ファイルのパス)
- `registry_key` (Windowsのレジストリキー)
- `service_name` (Windowsのサービス名)

#### CSV ダウンロード

「Download CSV」ボタンを押すと、すべての IOC が CSV ファイル
(`iocs.csv`) としてダウンロードできます。

### 4.8 MITRE Map タブ — 攻撃手口の地図

**MITRE ATT&CK** とは、世界中の攻撃事例から「攻撃者がよくやる手口」を
カタログ化した知識ベースです。業界の事実上の標準です。

このタブでは、見つかった発見事項を ATT&CK の地図上にマッピングして
表示します。

#### 表示

```
TA0001 (Initial Access)    │ [T1133 (External Remote)] [T1190 (Public-Facing App)]
TA0002 (Execution)         │ [T1059.001 (PowerShell)] [T1204.002 (User Execution)]
TA0003 (Persistence)       │ [T1543.003 (Service)] [T1547.001 (Run Key)] ...
...
```

各セル(マス)には:

- **Technique ID**: T1543.003 などの番号
- **Technique Name**: 手口の名前
- **件数**: 発見事項の数と証拠の数
- **色**: 信頼度に応じて 赤(high) / 黄(medium) / 緑(low)

セルをクリックすると Findings タブに飛びます。

### 4.9 Report タブ — レポート閲覧とダウンロード

「Generate Report」を実行すると、このタブで結果を閲覧できます。

#### ボタン

| ボタン | 用途 |
|---|---|
| Open HTML | 別タブで HTMLレポートを開く |
| Findings CSV | 発見事項のCSV (Excelで開ける) |
| Timeline CSV | タイムラインのCSV |
| IOC CSV | IOCのCSV |
| JSON | 機械処理用のJSON全データ |

#### iframe プレビュー

下部に HTML レポートが埋め込み表示されます。
レポートの中身は次のセクションを含みます:

1. エグゼクティブサマリ
2. 影響範囲
3. 侵入経路 (Kill Chain)
4. 攻撃タイムライン
5. Finding 一覧 (Tier 1A は rule_source 別、Tier 1B は skill 別)
6. 未解決事項・整合性チェック
7. 推奨対応
8. IOC サマリ
9. MITRE ATT&CK マッピング
10. 監査トレイル
11. 付録: Evidence 詳細

### 4.10 Audit タブ — 操作履歴

TLVB が実行したすべての処理(パース・解析など)が時系列で残ります。

| 列 | 内容 |
|---|---|
| Timestamp | いつ実行されたか |
| Actor | 誰(または何)が実行したか (例: `tier0-orchestrator`) |
| Kind | 何の処理か (例: `parse`, `analyze`) |
| Body | 詳細(コマンド・行数・所要時間など) |

「Tier filter」で `tier0` (パース) / `tier1` (解析) / `tier2` (統合) /
`tier3` (レポート) で絞り込めます。

> 監査ログは法的な場面で「いつ・誰が・何をしたか」を証明する
> ために重要な記録です。元の `outputs/cases/<id>/actions.jsonl` が
> 1行=1イベントの形式で保存されています。

---

## 5. CLI でも同じことができる

Web UI はバックエンドの REST API のラッパーです。コマンドラインから
直接同じ処理を実行することもできます(自動化したい場合に便利)。

```bash
# ケース作成
tlvb case init --case-id INC-2026-0042 --name "test case" --examiner tanaka

# Step 1: パース
tlvb parse --case-id INC-2026-0042 --evidence-id EV-001 --input ./evtx-samples

# Step 2: 解析 — Tier 1A (署名 SQL, LLM 無し)
tlvb analyze INC-2026-0042 --tier 1a
# 任意: Tier 1B 異常ハンター (LLM)
tlvb analyze INC-2026-0042 --tier 1b --skill anomaly_hunter

# Step 3: 統合 — Tier 2 (LLM)。--active-search で広域探索も
tlvb synthesize INC-2026-0042

# Step 4: レポート — Tier 3
tlvb report INC-2026-0042 --format html,csv,json --language ja

# 全ステップを一括で (Tier 0→1A→1B→2→3)
tlvb run INC-2026-0042 --tier all --evidence ./evtx-samples --name "auto"

# 対話的に Approve/Reject を行う
tlvb review INC-2026-0042 --gate 1a --examiner tanaka
```

ヘルプ: `tlvb --help`

---

## 6. よくあるトラブル

### Q. ホストPCのブラウザから VM の Web UI にアクセスできない

- VM の IP を確認: `hostname -I`
- そのIPでホストPCから ping が通るか確認
- ホストPCの `http://<VMのIP>:8080/` にアクセス
- 通らない場合は VMware の「Virtual Network Editor」で VMnet8 (NAT) の
  ポートフォワーディングを設定 (`Host port 8080 → VM IP:8080`)

### Q. Parse ボタンがエラーになる

- 証拠データのパスが正しいか
- パスがVM上から見えるディレクトリか(ホスト側のパスは指定不可)
- パス先のフォルダの中に解析できるファイルがあるか
  (Windowsイベントログ `.evtx`、レジストリハイブ、Amcache 等)

### Q. Analyze がすぐ失敗する

- 先に Parse が完了している必要があります
- LLM ステージ(Tier 1B / Tier 2)はリポジトリルートの `.env.local` に LLM
  トランスポートの設定が必要です:**Anthropic API**
  (`ANTHROPIC_API_KEY=sk-ant-...`)または **Vertex AI**(サービスアカウント
  キー — 下の FAQ を参照)。Tier 1A は影響を受けません(LLM を呼ばない)。

### Q. Synthesize に findings が見つからないと言われる

- Analyze が一つも成功していません。Analyze を再実行してください

### Q. Findings タブで何も表示されない

- まだ Analyze が完了していません
- パイプラインバーで `Analyze All` のステータスを確認

### Q. データを最初からやり直したい

- ダッシュボードでケースカード → 詳細 → 「Delete case」
- 作業ディレクトリ (`outputs/cases/<id>/`) も削除されます
- 元の証拠データは触りません

### Q. AIが間違っているっぽい

- それが Review Gate (Findings タブの Approve/Reject) を設けている理由です
- 「これは違う」と判断したら **Reject + 理由** を記録してください
- 最終レポート生成時に「Only approved」を有効にすれば、却下したものは
  レポートに含まれません
- 一度 Approve した finding を取り消したい場合は、その行の **Reset** ボタンで pending に戻せます(2026-05 追加)

### Q. パイプライン途中で止めたい

- 各ステップの進捗ブロック下に **`✕ cancel`** ボタンが出ます(2026-05 追加)
- クリック → 確認 → ジョブが中断され `canceled` 状態に
- DuckDB / 部分出力は残ったままなので、次回 Parse / Analyze で再開できます

### Q. 毎回 LLM トランスポートを設定するのが面倒

- リポジトリのルートに `.env.local` ファイルを作り、トランスポートを一度だけ
  設定してください。TLVB は **すべての** サブコマンド(`tlvb serve` / `analyze`
  / `synthesize` / `run` ...)の起動時にこれを読み込みます。パスは
  `TLVB_ENV_FILE` で上書きできます。
- **Anthropic API** なら `ANTHROPIC_API_KEY=sk-ant-...` と書きます。
- **Vertex AI**(Google Cloud 上の Anthropic)なら
  `GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json`(または
  `GOOGLE_APPLICATION_CREDENTIALS_JSON={...}` でキーをインライン)と書き、
  任意で `ANTHROPIC_VERTEX_PROJECT_ID` / `CLOUD_ML_REGION`(既定 `us-east5`)/
  `TLVB_VERTEX_MODEL` を添えます。
- 両方ある場合は Anthropic API キーが優先されます。シェルで明示的に `export`
  した値はファイルより優先されるので、一時的な上書きも可能です。

---

## Appendix A: 用語集

セキュリティ・フォレンジック分野の専門用語を、本ドキュメントで
登場した順に並べています。

### 基本概念

| 用語 | 説明 |
|---|---|
| **インシデント** | サイバー攻撃が疑われる出来事の単位。TLVB の「ケース」1つ = 1インシデント |
| **インシデントレスポンス (IR)** | インシデントが起きたときの対応活動全般。「事故対応」 |
| **フォレンジック (Digital Forensics, DFIR)** | コンピューター上に残った証拠を法的に通用する形で収集・分析する技術。直訳すると「デジタル鑑識」 |
| **証拠 (Evidence)** | 攻撃の有無を判断する材料となるデータ。ハードディスクのコピー、ログファイル、メモリダンプなど |
| **チェーン・オブ・カストディ (Chain of Custody)** | 「証拠が誰の手に渡り、誰がいつ何をしたか」の記録。法廷で証拠が認められるために必須 |
| **読み取り専用 (Read-Only)** | 元の証拠ファイルを **絶対に書き換えない** という運用原則。TLVB もこれを守ります |

### 攻撃のしくみと対策

| 用語 | 説明 |
|---|---|
| **MITRE ATT&CK** | 米国 MITRE 社が公開している、攻撃者の手口のカタログ。業界標準の分類体系 |
| **Tactic (戦術)** | ATT&CK の最上位カテゴリ。「攻撃者の目的」(例: 侵入する、居座る、情報を盗む)。TLVB では 10 種類を扱う |
| **Technique (テクニック)** | Tactic を達成する具体的な手段。例: T1543.003 は「Windows サービスを作って居座る」テクニック |
| **Initial Access** | 最初にシステムに侵入する手口(フィッシングメール、脆弱性悪用など) |
| **Execution** | 侵入後に悪意あるプログラムを実行すること |
| **Persistence** | 再起動後も居座る仕掛けを作ること(自動起動レジストリ、サービス登録、スケジュールタスクなど) |
| **Privilege Escalation** | 一般ユーザーから管理者権限へ昇格すること |
| **Defense Evasion** | ログを消す、検知を回避する、痕跡を隠すなどの行為 |
| **Credential Access** | パスワードや認証トークンを盗むこと |
| **Discovery** | 「ここはどんな環境だろう?」と調べる行為(ユーザー一覧取得、ネットワーク偵察など) |
| **Lateral Movement** | 1台のパソコンから別のパソコンへ移動すること |
| **Collection** | 盗み出すデータを集める行為 |
| **Impact** | データを暗号化(ランサムウェア)、削除、破壊する最終行為 |
| **Kill Chain** | 攻撃が「侵入 → 居座り → 権限昇格 → 横移動 → データ窃取」のように段階を踏むという考え方。元はロッキード・マーチン社が提唱 |

### 証拠の種類

| 用語 | 説明 |
|---|---|
| **EVTX** | Windows のイベントログのファイル形式。`.evtx` 拡張子。ログオン履歴・サービス起動・PowerShell実行などが記録されている |
| **EventID** | EVTX 内のイベントの種類番号。例: `4624` = 成功ログオン、`7045` = 新サービスインストール |
| **Sysmon** | Microsoft が出している詳細ログ取得ツール。プロセス起動・ネットワーク接続・ファイル変更などを細かく記録 |
| **レジストリ (Registry)** | Windows の設定データベース。マルウェアが自動起動を仕込む場所として悪用されやすい |
| **Amcache** | Windows が「過去にこのPCで実行されたことのある実行ファイル」を記録するファイル。攻撃者が消したマルウェアの痕跡が残ることがある |
| **Prefetch** | Windows が起動高速化のために「最近実行したプログラム」をキャッシュするファイル。同じく事後追跡に有用 |
| **Shimcache (AppCompatCache)** | Windows のアプリ互換性データベース。実行された .exe の痕跡が残る |
| **MFT (Master File Table)** | NTFS ファイルシステムの目次。削除されたファイルの情報も部分的に残る |
| **USN Journal** | NTFS のファイル変更履歴。「いつ何のファイルが作られた/消された」が分かる |

### 解析関連

| 用語 | 説明 |
|---|---|
| **IOC (Indicator of Compromise)** | 「侵害指標」。攻撃を識別する具体的な値(IPアドレス、ドメイン、ハッシュ値、ファイルパスなど) |
| **ハッシュ値** | ファイルから計算される短い文字列(SHA-256, MD5など)。同じファイルかどうかの判定に使う |
| **C2 / C&C (Command and Control)** | 攻撃者が侵入先を遠隔操作するためのサーバ。IOC として C2 のドメイン/IPが共有される |
| **TTP (Tactics, Techniques, Procedures)** | 「戦術・テクニック・手順」。攻撃者の行動パターンを表す ATT&CK の3階層 |
| **シグマ (Sigma)** | ログから攻撃を検出するルールの汎用的な記述形式 |
| **YARA** | マルウェアのファイルパターンを記述するルール形式。バイナリ中の特定文字列・バイト列を探す |
| **タイムライン (Timeline)** | 「いつ何が起きたか」を時系列で並べたデータ。複数の証拠を時刻でマージして作る |
| **Plaso / log2timeline** | 多種類の証拠をまとめて1つのタイムラインにする標準ツール |

### 監視・検知関連

| 用語 | 説明 |
|---|---|
| **SIEM (Security Information and Event Management)** | 社内のさまざまな機器のログを集めて相関分析する監視システム。Splunk, Elastic SIEM, QRadar など |
| **EDR (Endpoint Detection and Response)** | 各PCに常駐して挙動を監視するソフトウェア。CrowdStrike, SentinelOne, Defender for Endpoint など |
| **SOC (Security Operations Center)** | セキュリティ監視を行うチーム/部門 |
| **検知ルール** | 「この条件に当てはまるログが出たらアラートを出す」というルール |
| **誤検知 (False Positive, FP)** | 攻撃ではないのに攻撃と判定してしまうこと |
| **見逃し (False Negative, FN)** | 攻撃なのに見逃してしまうこと。TLVB は AI + Review Gate でこれを減らすのが狙い |

### TLVB 特有の用語

| 用語 | 説明 |
|---|---|
| **Tier 1A (シグネチャ)** | ルールコーパス (Sigma / Hayabusa / ATT&CK STIX / custom / LOLBAS) を **build 時**に SQL へコンパイルし (`tlvb rules build`)、**実行時**はキャッシュ済み SQL を回すだけ (LLM ゼロ)。ヒット = finding |
| **Tier 1B (異常ハンター)** | `skills/*.md` のスキルが SQL を実行 → LLM が Tier 1A findings と併せて抽象的な異常を推論し、必要なら新クエリを考案 (キャッシュが成長)。既定スキル = anomaly_hunter (tactic スキルは `--skill` で opt-in) |
| **Anomaly Hunter** | Tier 1B の既定スキル。既存ルールに当てはまらない「何かおかしい」挙動を探す |
| **finding (発見事項)** | Tier 1A は `findings/by-rule/<rule_source>/<rule_id>.json`、Tier 1B は `findings/by-skill/<skill>.json` に保存 |
| **rule_source** | Tier 1A ルールの出所: `sigma` / `hayabusa` / `stix` / `custom` / `lolbas`。主キーは `(rule_id, rule_source)` で rule_id は上流の原 ID を保持 |
| **Tier 2 (タイムライン解析)** | Tier 1 findings をクラスタ化し、各クラスタの ±N 分の生タイムラインを LLM が解析。`--active-search` で仮説駆動の広域 SQL も実行。出力 = `synthesis.json` (クラスタ + overall_story + mitre_mapping + open_questions) |
| **Tier 3 (レポーター)** | `synthesis.json` + findings から HTML / CSV / JSON の DFIR レポートを生成 (LLM ゼロ) |
| **Review Gate** | 各 Tier の合間の人間レビュー。Gate 0 (parse) / **1A** (署名 findings、重要度で自動承認) / **1B** (異常 findings) / 2 (タイムライン) |
| **Examiner** | 調査者(ユーザー自身)。承認/却下の操作は Examiner 名で記録される |
| **Tier 0/1/2/3** | TLVB の処理層。**Tier 0**=パーサ / **Tier 1A**=署名 SQL (LLM=0) / **Tier 1B**=スキル異常 (LLM) / **Tier 2**=タイムライン解析+統合 (LLM) / **Tier 3**=レポート (LLM=0) |
| **legacy (moai)** | 旧実装の Tactic Agent / TacticReport / Synthesizer / Corrector。現在は `tlvb synthesize --legacy` / `report --legacy` で opt-in (既定は tier2/tier3) |
| **audit_id** | 個々のログイベントのID(ハッシュ値)。finding が「どのログを根拠にしているか」を一意に指せる |

### ツール・ファイル関連

| 用語 | 説明 |
|---|---|
| **MCP (Model Context Protocol)** | AI エージェントが外部ツールを呼び出すための標準プロトコル。TLVB 内部で使用 |
| **EZ Tools** | フォレンジック界で広く使われている Eric Zimmerman 氏の解析ツール群。EvtxECmd, AmcacheParser, RECmd など |
| **SIFT Workstation** | SANS Institute が提供しているフォレンジック専用 Linux 環境(Ubuntu ベース)。TLVB の動作前提環境 |
| **DuckDB** | TLVB がイベントデータの保管に使う組み込みデータベース(SQLite に似て、分析向け) |

---

## Appendix B: 全体像の図

### 処理の流れ

```
┌────────────────────────────────────────────────────────────────────┐
│                     ユーザー                                         │
│  ┌────────┐                                                         │
│  │ ブラウザ │ ⇄ http://localhost:8080/                                │
│  └────────┘                                                         │
└────────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────────────┐
│  tlvb serve  (Go バイナリ — UI も埋め込み済み)                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ REST API     │  │ JobsManager  │  │ Embedded UI (HTML/CSS/JS)│  │
│  │ /api/cases   │  │ (goroutine)  │  │ /static/app.js etc.      │  │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────────────┐
│  Tier 0:  Parser orchestrator (Python + EZ Tools)                  │
│           ↓ 証拠ファイルを構造化データに変換 (unified_events)         │
│  Tier 1A: Signature SQL (cached rules → DuckDB, LLM ゼロ)            │
│           ↓ ヒットを findings/by-rule/ に出力                        │
│  Tier 1B: Anomaly Hunter skill (Claude, LLM, 任意) → by-skill/       │
│  Tier 2:  Timeline Analysis Agent (Claude) → 統合・タイムライン・KC   │
│  Tier 3:  Reporter (Go) → HTML/CSV/JSON DFIR レポート (LLM ゼロ)     │
└────────────────────────────────────────────────────────────────────┘
                            │
                            ▼
        outputs/cases/<ケースID>/                     outputs/cases.duckdb
        ├── findings/*.json   ← 戦術別の発見事項        (イベント全件のDB)
        ├── synthesis.json    ← 統合結果
        ├── reports/          ← HTML/CSV/JSON レポート
        └── actions.jsonl     ← 監査ログ
```

### Web UI のページ階層

```
/  (ダッシュボード)
└─ #/cases/<id>  (ケース詳細)
   ├─ ?tab=status     (パイプライン進捗のライブ表示)
   ├─ ?tab=events     (パース済みイベント + Review Gate 0)
   ├─ ?tab=findings   (発見事項 + Approve/Reject = Review Gate 1A)
   ├─ ?tab=timeline   (時系列 + Kill Chain + Review Gate 2)
   ├─ ?tab=iocs       (侵害指標)
   ├─ ?tab=mitre      (MITRE ATT&CK マップ)
   ├─ ?tab=report     (HTML/CSV/JSON レポート)
   └─ ?tab=audit      (操作履歴)
```

### Review Gate (人間の介入点)

```
Tier 0 ─→ [Gate 0] ─→ Tier 1A/1B ─→ [Gate 1A/1B] ─→ Tier 2 ─→ [Gate 2] ─→ Tier 3
            ↑                       ↑                       ↑
            パーサ結果の              発見事項の               タイムラインの
            確認                     Approve/Reject          確認
                                    (Findings タブ)
```

現在の Web UI は **Gate 0**(Events タブで parse 結果を承認)・**Gate 1A/1B**
(Findings タブで findings を Approve/Reject)・**Gate 2**(Timeline タブで
タイムラインエントリを承認/却下)を実装しています。🤖 Autopilot ボタンは
Gate 0 と Gate 2 を自動スキップして全自動で走ります。

---

**ご質問・改善要望は GitHub Issue または `examiner@example.com` まで。**
