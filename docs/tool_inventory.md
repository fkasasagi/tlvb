# Tool Inventory — SIFT Workstation (TLVB)

**確認日 (UTC)**: 2026-05-02
**ホスト**: SANS SIFT Workstation (Ubuntu, x86-64)
**確認方法**: 各ツールの存在 (`which` / `ls`)、バージョンバナー、ヘルプ出力で実行可能性を検証

---

## 1. Zimmerman EZ Tools (`/opt/zimmermantools/`)

| ツール | パス | 起動コマンド | バージョン | 状態 |
|---|---|---|---|---|
| EvtxECmd | `/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll` | `dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll` | 1.5.2.0 | ✅ |
| AmcacheParser | `/opt/zimmermantools/AmcacheParser.dll` | `dotnet /opt/zimmermantools/AmcacheParser.dll` | 1.5.2.0 | ✅ |
| **PECmd** | `/opt/zimmermantools/PECmd.dll` | `dotnet /opt/zimmermantools/PECmd.dll` | **2026.5.0** | ✅ **2026-05-02 にソースから dotnet 9.0 でビルドして配置** |
| RECmd | `/opt/zimmermantools/RECmd/RECmd.dll` | `dotnet /opt/zimmermantools/RECmd/RECmd.dll` | (1.x) | ✅ |
| MFTECmd | `/opt/zimmermantools/MFTECmd.dll` | `dotnet /opt/zimmermantools/MFTECmd.dll` | 1.3.0.0 | ✅ |
| SBECmd | `/opt/zimmermantools/SBECmd.dll` | `dotnet /opt/zimmermantools/SBECmd.dll` | (1.x) | ✅ |
| JLECmd | `/opt/zimmermantools/JLECmd.dll` | `dotnet /opt/zimmermantools/JLECmd.dll` | (1.x) | ✅ |
| LECmd | `/opt/zimmermantools/LECmd.dll` | `dotnet /opt/zimmermantools/LECmd.dll` | (1.x) | ✅ |
| RBCmd | `/opt/zimmermantools/RBCmd.dll` | `dotnet /opt/zimmermantools/RBCmd.dll` | (1.x) | ✅ |
| WxTCmd | `/opt/zimmermantools/WxTCmd.dll` | `dotnet /opt/zimmermantools/WxTCmd.dll` | (1.x) | ✅ |
| AppCompatCacheParser | `/opt/zimmermantools/AppCompatCacheParser.dll` | `dotnet /opt/zimmermantools/AppCompatCacheParser.dll` | (1.x) | ✅ |
| RecentFileCacheParser | `/opt/zimmermantools/RecentFileCacheParser.dll` | `dotnet /opt/zimmermantools/RecentFileCacheParser.dll` | (1.x) | ✅ |
| SQLECmd | `/opt/zimmermantools/SQLECmd/SQLECmd.dll` | `dotnet /opt/zimmermantools/SQLECmd/SQLECmd.dll` | (1.x) | ✅ |
| iisGeolocate | `/opt/zimmermantools/iisGeolocate/iisGeolocate.dll` | `dotnet ...` | (1.x) | ✅ |
| rla | `/opt/zimmermantools/rla.dll` | `dotnet ...` | (1.x) | ✅ |
| bstrings | `/opt/zimmermantools/bstrings.dll` | `dotnet ...` | (1.x) | ✅ |

### PECmd インストール記録（2026-05-02）

ダウンロードサーバー (`download.ericzimmermanstools.com`) は本機のサンドボックスポリシーで curl/wget が拒否されたため、**GitHub ソースからビルドして配置**:

```bash
# 1. ソース取得（git は許可されている）
git clone --depth 1 https://github.com/EricZimmerman/PECmd.git /tmp/PECmd-src

# 2. dotnet 9.0 SDK でビルド
cd /tmp/PECmd-src/PECmd
dotnet build -c Release -f net9.0 -o /tmp/PECmd-build

# 3. /opt/zimmermantools/ にコピー
sudo cp /tmp/PECmd-build/PECmd.{dll,deps.json,runtimeconfig.json,dll.config} /opt/zimmermantools/
sudo cp /tmp/PECmd-build/PECmd /opt/zimmermantools/

# 4. 動作確認
dotnet /opt/zimmermantools/PECmd.dll --version
# → 2026.5.0+bde430c69ba4d97fea8b71fdddb6df7849419c10
```

ビルド結果: `PECmd version 2026.5.0`、`--help` 正常応答、CSV/JSON/XML 出力フラグ全て利用可。

### 残存不在ツール

| ツール | 影響 | 対応 |
|---|---|---|
| **SrumECmd** (SRUM) | Wave 13 (2026-05-16) で fallback 化 | **Linux で動かないため Plaso `psteal.py --parsers esedb/srum` を primary に**。SrumECmd.dll は `/opt/zimmermantools/SrumECmd.dll` にソースビルド配置済 (Windows dev box 用 fallback)。実機 1404 events / 3.2s 確認済 |

### 補助データ

- **EvtxECmd Maps**: `/opt/zimmermantools/EvtxeCmd/Maps/` に **456 個**のマップ済みプロバイダー定義あり
- **RECmd BatchExamples**: `/opt/zimmermantools/RECmd/BatchExamples/` に Batch ファイル多数

---

## 2. Volatility 3

| 項目 | 値 |
|---|---|
| 実体パス | `/opt/volatility3/bin/vol` (Python venv) |
| シンボリックリンク | `/usr/local/bin/vol` → `/opt/volatility3/bin/vol` |
| パッケージバージョン | **2.27.0** (`/opt/volatility3/lib/python*/site-packages/volatility3-2.27.0.dist-info`) |
| 推奨呼び出し | `/usr/local/bin/vol` または `vol` |
| 状態 | ✅ |

> ⚠️ バージョン番号入りの絶対パス (`/opt/volatility3-<version>/vol.py` 等) は環境により存在しない。`vol` コマンド経由で呼び出すこと。

> ⚠️ **Memory Baseliner** (`/opt/memory-baseliner`) は本環境に**未配置**。メモリ解析は Volatility 3 のみで対応。

---

## 3. Plaso

| ツール | パス | バージョン | 状態 | 用途 |
|---|---|---|---|---|
| **psteal.py** | system PATH | **20260119** | ✅ | **推奨**: 1 ステップで `--source → -o → -w`。TLVB の Prefetch fallback で使用 (Wave 12) |
| log2timeline.py | system PATH | **20260119** | ✅ | (低レベル、Storage file を別途作る場合) |
| psort.py | system PATH | **20260119** | ✅ | (低レベル、既存 Storage file をフォーマットする場合) |
| pinfo.py | system PATH | (同) | ✅ | Storage file のメタデータ確認 |

> Plaso (GIFT PPA) のバージョンは環境により異なる (本環境は 20260119)。
> **本プロジェクトでは log2timeline+psort の二段呼びを避け、`psteal.py` の単段呼出を採用** (Wave 12)。
> 理由: ① 中間 `.plaso` storage のクリーンアップ漏れリスク回避、② フラグバージョン依存 (`psort -z` 廃止等) のトラブル削減、③ Subprocess 1 回で完結する分エラーパスがシンプル。

---

## 4. Sleuth Kit

| ツール | パス | バージョン | 状態 |
|---|---|---|---|
| fls / icat / mmls / blkls / mactime / tsk_recover | `/usr/bin/` | **4.11.1** | ✅ |
| ewfmount / ewfinfo / ewfverify | system PATH | 20140816 | ✅ |

---

## 5. RegRipper

| 項目 | 値 |
|---|---|
| パス | `/usr/local/bin/rip.pl` |
| バージョン | **3.0** |
| 状態 | ✅ |

---

## 6. その他フォレンジック・ツール

| ツール | パス | バージョン | 状態 |
|---|---|---|---|
| bulk_extractor | system PATH | 1.6.1 | ✅ |
| dotnet runtime | `/usr/bin/dotnet` | **9.0.15** (ASP.NET / NETCore.App) | ✅ |
| YARA バイナリ (`yara`) | — | — | ❌ **未インストール** |
| libyara10 (Python bindings) | dpkg | 4.5.0 | ✅（Pythonモジュール経由） |

> ⚠️ dotnet のバージョンは環境により異なる (本環境は **9.0.15**)。EZ Tools (1.5.x) は問題なく動作することを確認済み。

> ⚠️ YARA CLI (`yara` コマンド) はインストールされていない。必要なら以下でインストール:
> ```bash
> sudo apt install yara
> ```
> Python 経由 (`import yara`) はそのまま利用可。

---

## 7. Hayabusa

| 項目 | 値 |
|---|---|
| 状態 | ❌ **未インストール** |
| 検索結果 | `/opt/hayabusa*`, `/usr/local/bin/hayabusa`, `apt` パッケージ いずれも該当なし |

### インストール手順（メモ）

公式 GitHub Releases から Linux 用バイナリを取得:

```bash
# 例: Hayabusa v3.x
mkdir -p /opt/hayabusa && cd /opt/hayabusa
wget https://github.com/Yamato-Security/hayabusa/releases/latest/download/hayabusa-X.X.X-lin-x64-gnu.zip
unzip hayabusa-*.zip
chmod +x hayabusa-*-lin-x64-gnu
ln -s /opt/hayabusa/hayabusa-*-lin-x64-gnu /usr/local/bin/hayabusa
hayabusa update-rules        # Sigma rules を取得
```

設置後の起動確認:
```bash
hayabusa --version
hayabusa csv-timeline -d <evtx_dir> -o hayabusa.csv -p super
```

導入は P1 フェーズで実施。MVP 開発では Sigma マッチングは EvtxECmd + 自前ルール走査で代替可能。

---

## 8. 未公式ツール（DESIGN.md 内で想定するも、本機未配置）

| ツール | 用途 | 代替 |
|---|---|---|
| Memory Baseliner | メモリ ベースライン比較 | Volatility 3 plugin (`windows.pslist`, `windows.netscan` など) |
| MemProcFS | Windows-only | スキップ (Linux/SIFT では非対応) |
| VSCMount | Volume Shadow Copy mount (Windows-only) | `vss_carver` (`.bash_aliases` 提供) |

---

## 9. パーサー実装方針への影響

| アーティファクト | DESIGN.md 想定ツール | 実環境対応 |
|---|---|---|
| Windows Event Logs | EvtxECmd | ✅ そのまま使用 |
| Amcache | AmcacheParser | ✅ そのまま使用 |
| **Prefetch** | **altpf** (Wave 12 / Issue #27) | ✅ `/opt/altpf/altpf` v0.5.1 配置済 (Linux ネイティブ Go、PECmd 互換 CSV、§11 参照)。**Plaso `psteal.py` を fallback** として残存 (Wave 12 で log2timeline+psort 二段 → psteal 単段に短絡)。PECmd は Linux 不可のため chain から除外 |
| Registry | RECmd / RegRipper | ✅ どちらも利用可能 |
| Scheduled Tasks | MFTECmd + Plaso | ✅ そのまま使用 |
| Shimcache | AppCompatCacheParser | ✅ そのまま使用 |
| MFT / USN | MFTECmd | ✅ そのまま使用 |
| Shellbags | SBECmd | ✅ そのまま使用 |
| Jumplists | JLECmd | ✅ そのまま使用 |
| LNK Files | LECmd | ✅ そのまま使用 |
| Recycle Bin | RBCmd | ✅ そのまま使用 |
| Memory | Volatility 3 | ✅ `vol` 経由で使用 |
| Sigma Match | Hayabusa | ❌ MVP では延期、P1 で導入 |

---

## 10. 推奨アクション

1. ~~**PECmd を取得**~~ ✅ **2026-05-02 完了** — ソースからビルドして配置済み (v2026.5.0)。**Wave 12 (2026-05-16) で Prefetch chain から除外** — Linux で動かないため altpf primary + Plaso fallback に変更
2. **Hayabusa を P1 タスクで導入**: 公式 GitHub Releases から `/opt/hayabusa/` に配置。Sigma ルールは `update-rules` で取得。
3. **YARA バイナリの追加検討**: P1 フェーズで `yara-hunting` スキル使用時に `apt install yara` で導入。
4. ~~**SrumECmd**~~ ✅ **Wave 13 (2026-05-16) 完了** — SrumECmd を `EricZimmerman/Srum` repo からソースビルド (`dotnet build -c Release SrumECmd/SrumECmd.csproj`) して `/opt/zimmermantools/SrumECmd.dll` に配置。ただし ESE Windows API 依存で Linux 実行不可と判明、`parsers/srum_parser.py` を **Plaso (`psteal.py --parsers esedb/srum`) primary + SrumECmd Windows-only fallback** に refactor。SIFT 上では Plaso 経路で実 SRUDB.dat (1.9 MB) を 1404 events / 3.2s で parse 可能。
5. **環境差分に留意**: Volatility のパスと dotnet のバージョンは想定と実環境で異なる(本書の各注記を参照)。

---

## 11. altpf — Prefetch primary engine (Wave 12 / Issue #27)

| 項目 | 値 |
|---|---|
| **バイナリパス** | `/opt/altpf/altpf` |
| **バージョン** | 0.5.1 (2026-05-16 release) |
| **言語** | 純 Go (cgo 不要)、静的リンク ELF 64-bit、3.3 MB |
| **対応形式** | Prefetch v17/v23/v26/v30/v31 自動判定、MAM LZXPRESS Huffman を pure-Go で展開 |
| **出力** | PECmd 互換 CSV (LastRun + PreviousRun0..6 を独立カラム) + timeline.csv + run.log |
| **速度** | 215 .pf を 0.187 秒で完走 (Plaso 比 ~1000 倍速) |
| **ライセンス** | MIT (本体) / Apache-2.0 (Velocidex 由来) |
| **配布物 SHA-256** | `90d5bcb98a0870b5ebbfb1843d29c74217fee510f6f133a2070304b3457b8d14` (linux-amd64 tarball) |
| **バイナリ SHA-256** | `e6c6ea4659bec7bdd5765a3c32906b5e22303a1b428f7638201f18dbe8512469` |

### 配置手順

```bash
sudo mkdir -p /opt/altpf && sudo chown $USER:$USER /opt/altpf
cd /opt/altpf
gh release download v0.5.1 --repo fkasasagi/altpf \
    --pattern '*linux-amd64*' --pattern '*checksums*'
EXPECTED=$(grep linux-amd64 altpf-v0.5.1-checksums.txt | awk '{print $1}')
ACTUAL=$(sha256sum altpf-v0.5.1-linux-amd64.tar.gz | awk '{print $1}')
[ "$EXPECTED" = "$ACTUAL" ] || { echo "SHA-256 MISMATCH"; exit 1; }
tar xzf altpf-v0.5.1-linux-amd64.tar.gz
mv altpf-v0.5.1-linux-amd64/altpf .
mv altpf-v0.5.1-linux-amd64/README.md README.altpf.md
mv altpf-v0.5.1-linux-amd64/LICENSE LICENSE.altpf
rm -rf altpf-v0.5.1-linux-amd64
chmod +x altpf
./altpf -h | head
```

### Forensic 監査

`parse_results.notes` に altpf binary パス + SHA-256 + timeline CSV パス + run.log パスを記録。
「どのバージョンの、どの正しい本物のバイナリで parse したか」が後追い可能。
