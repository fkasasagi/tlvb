# 精度自己評価レポート — Case: `winrm_spray_case`

> **ハッカソン提出物（FIND EVIL!）:** 本書は TLVB の検出精度に関するケース別自己評価であり、`docs/ACCURACY.md`（全体精度レポート）の **WinRM-spray データセット**の詳細版です。元の解析実行成果物は（リポジトリには含めない）`outputs/cases/winrm_spray_case/` 配下にあり、本書はそれを正解キーと突合した評価結果です。

**評価対象:** TLVB 解析成果物（`synthesis.json` / `reports/` 一式、生成 2026-06-15）
**正解キー:** `DISTRIB_winrm_spray/ANSWER_KEY/winrm_spray_groundtruth.md`
**シナリオ:** `DISTRIB_winrm_spray/EVIDENCE_README.md`
**評価日:** 2026-06-15
**評価者観点:** 検査結果の精度に関する自己評価（誤検出 / 見落とし / 虚偽の主張の洗い出し）

---

## 対象証拠とシナリオの概要

### 解析対象イメージ（E01）

| 項目 | 値 |
|---|---|
| イメージファイル | `dc03.E01` 〜 `dc03.E06`（6 分割 EWF/E01。`dc03.E01` 指定で E02〜E06 を自動連結） |
| チェーン・オブ・カストディ | `dc03.E01.txt`（FTK 取得ログ） |
| 投入コマンド | `./bin/tlvb run winrm_spray_case --evidence "<path>/image/dc03.E01"` |
| 対象ホスト | Windows Server 2022 Standard（スタンドアロン）、ホスト名 `WIN-J1N4BSVU5O7` |
| イメージ種別 / サイズ | 物理ディスク E01（EWF）、20,480 MB / 41,943,040 sectors（512 B/sector） |
| 取得ツール / 日時 | AccessData FTK Imager 4.7.1.2 / 2026-06-12 20:11〜20:13（JST） |
| 内容ハッシュ | MD5 `3c4b5761c2513e8e36ea30a40d5a212e` / SHA1 `161ebfd7b7296cfbd6f579096a8be86444179657` |

### 想定インシデント（シナリオ）

> 検証用に構築中のサーバーで、**設定作業の途中にアンチウイルス（Defender）がマルウェアのアラートを発報**。担当者は侵害を疑い、サーバーを**即時シャットダウンして保全**し、フォレンジック解析を依頼した。

ブラインド評価タスクは「このホストで実際に何が起きたか（**誰が・どこから・何を行い、それが成功したのか阻止されたのか**）」をディスクイメージから解明すること。本シナリオの正体は **WinRM 経由の弱パスワード侵入**で、攻撃者は侵入・偵察・永続化登録には成功したが、**認証情報窃取は Defender(AMSI) に遮断されて「失敗」**している。最大の評価ポイントは、ツールが**「資格情報が盗まれた」と過剰主張しないか**（＝失敗を失敗と言えるか）にある。

なお `Original Install Date` が実活動日より未来を指すのは、ラボ構築時に未来クロックで OS をインストール後に `Set-Date` で補正したことに由来する**良性のアーティファクト**であり、攻撃者による時刻改ざんではない（誤読防止のため正解キー/README が明示）。

---

## 0. 総評（先出し）

> **本シナリオの最大の評価軸である「窃取の失敗を失敗と言えるか（過剰主張の抑止）」に、TLVB は明確に合格した。**

攻撃チェーンの中核（WS01 からの単一アカウント総当たり → WinRM リモート実行 → 偵察バースト → LSASS ダンプ**試行** → WMI 永続化）をすべて検出し、かつ **「認証情報窃取は Defender(AMSI) に遮断され成立していない」と正しく判定**した。前シナリオ tamu2_3 で問題化した「窃取成功への踏み込み過剰主張」は再発していない。時刻アーティファクト（未来日付インストール / Set-Date 補正 / W32Time）も**攻撃者の改ざんと誤認せず**、キッティング由来の良性と結論している。

一方で精度上の弱点として、**(a) ノイズクラスタに混入した過剰解釈の finding（anomaly A5 の「データ収集ステージング」）**、**(b) MITRE マップへのプロビジョニング由来テクニックの混入**、**(c) 構造化 IOC からの最重要識別子 `WS01` の欠落**、**(d) 細部アーティファクトの掘り下げ不足** がある。いずれも overall_story / exec_brief の結論を誤らせるレベルには至っていないが、レポートの「精度（precision）」を下げている。

### スコアサマリ

| 評価ブロック（正解キー §5） | 配点項目数 | 合格 | 判定 |
|---|---|---|---|
| 検出できるべき | 5 | 5 | ✅ 満点 |
| 過剰主張してはいけない | 4 | 4 | ✅ 満点 |
| ノイズとして扱うべき（誤検知の罠） | 4 | 3.5 | 🟡 概ね良好（WMI 5861 SCM の明示区別が不足） |
| 用語の区別（加点）| spray vs 単一アカウント辞書 | ○ | ✅ 加点（本体は T1110.001 で正答、一部 open_question に "spray" 残存） |

**結論レーティング:** **A−**（主眼は完全合格。誤検出と細部欠落で満点には届かず）

---

## 1. 正しく検出できた項目（正解キー §5「検出できるべき」）

| # | 期待される検出 | TLVB の対応 | 判定 |
|---|---|---|---|
| 1 | 単一アカウントへの辞書/総当たり（4625 連続→成功）を侵入起点に特定 | `TLVB-BRUTEFORCE-4625`（heuristic, high）「20 failed logons against administrator then a successful logon」。overall_story が侵入起点として明記。技術は **T1110.001 Password Guessing** で正答 | ✅ |
| 2 | WinRM 経由リモート実行（wsmprovhost.exe）を横展開/実行として認識 | `Remote PowerShell Session Host Process (WinRM)` / `Suspicious Processes Spawned by WinRM`(high) / `Uncommon PowerShell Hosts` 検出、**T1021.006** マッピング。overall_story が「遠隔セッションが初期アクセス経路」と結論 | ✅ |
| 3 | LSASS ダンプの**試行**を窃取の試みとして検出 | `Antivirus Password Dumper Detection`(critical) / `Antivirus Hacktool Detection` / `Windows Defender AMSI Trigger Detected` / `Windows Defender Threat Detected`。IOC に検知プロセス `wsmprovhost.exe` を抽出 | ✅ |
| 4 | Defender が AMSI で検知・Quarantine＝**窃取は不成立**と判定。rundll32 4688 や lsass.dmp の「不在」を「成功」と誤読しない | narrative/exec_brief とも「**ダンプ自体が成功した証拠はない**」「情報を実際に盗み出せた裏付けはない」と明言。不在を成功と誤読していない | ✅（**本シナリオの主眼を達成**） |
| 5 | WMI Event Subscription による永続化（5861）を検出 | `WMI Persistence` / `WMI Filter To Consumer Binding_Command Execution` / `Suspicious Scripting in a WMI Consumer`(high)、**T1546.003** マッピング | ✅ |

**用語の区別（加点項目）:** 正解キーは「パスワードスプレーではなく**単一アカウント辞書攻撃**」と区別できれば加点としている。TLVB の中核 finding は「20 failed logons against `administrator`（単一アカウント）」+ **T1110.001 Password Guessing** で正しく単一アカウント総当たりとして表現しており**加点に値する**。ただしクラスタ3の open_question に「本ケースは WinRM パスワードスプレー想定であり」という表現が残っており、内部的な用語の揺れがある（ケース名 `winrm_spray_case` に引きずられた痕跡）。

---

## 2. 過剰主張の抑止（正解キー §5「過剰主張してはいけない」）

| # | 禁止された過剰主張 | TLVB の対応 | 判定 |
|---|---|---|---|
| 1 | 「認証情報が盗まれた/外部流出した」と断定 | 断定せず。exec_brief で「盗み出せた裏付けはない」、open_questions(critical) に「窃取の成否は本データだけでは確定できない」 | ✅ 回避 |
| 2 | ポートスキャン段階を E01 から「検出した」とでっち上げ | ポートスキャンの主張なし（Security ログに載らない段階を捏造していない） | ✅ 回避 |
| 3 | 環境ベースライン設定（監査有効化等）を攻撃と誤認 | ファイアウォール構成 / AppX 配置 / Defender 定義更新を **cluster 1・3（"noise"）** に分類し「正規のキッティング/プロビジョニング」と結論 | ✅ 回避（※MITRE 漏出は §3-C 参照） |
| 4 | 攻撃者による時刻改変があると誤認 | `timeline_reliability=unreliable` + timeline_notes で「キッティング由来の Set-Date 補正を第一仮説とし、攻撃者の T1070.006 と断定しない」と明記。Original Install Date の食い違いを攻撃帰属していない | ✅ 回避 |

---

## 3. 誤検出（False Positives）— 検査中に特定された誤検出

結論を誤らせてはいないが、精度を下げている誤検出・過剰解釈を以下に列挙する。

### A. anomaly_hunter A5「データ収集ステージング」— 最も明確な過剰解釈
- **内容:** `findings/by-skill/anomaly_hunter.json` の lens A5。Administrator の Explorer jumplist が同一秒に Pictures/Documents/Desktop/Downloads を開いた痕跡を「**scripted collection/discovery staging by the compromised Administrator**（侵害された管理者によるスクリプト化された収集/偵察ステージング, T1083）」と解釈。
- **正解キーとの矛盾:** 本シナリオに**データ収集/ステージング段階は存在しない**。さらに正解キー §1 は「**作業者の対話コンソールログオンはイメージ内に一切存在しない**…これらを攻撃として報告したら誤検知」と明記しており、jumplist 由来の「対話的な管理者活動」を攻撃と読むこと自体がトラップ。
- **影響:** severity=medium・auto-approve。**noise クラスタ(3) に収容**され overall_story / exec_brief には昇格していないため最終結論は汚染していないが、**finding 単体のテキストは虚偽寄りの過剰主張**（後述 §5 とも関連）。

### B.「External Remote RDP Logon from Public IP」— Hayabusa 由来の誤検知
- **内容:** cluster 3 の finding（hayabusa, medium）。
- **正解キーとの矛盾:** 本シナリオに RDP（LogonType 10）は存在しない。攻撃は WinRM(5985) のネットワークログオン(Type 3)のみ。
- **TLVB の自己防衛:** open_questions で「対応する 4624 Type 10 のログオンレコードが生ログに見当たらない。誤検知/クロックステップで再アンカーされた別イベントの可能性」と**自ら疑義を呈し**、攻撃ストーリーに採用していない点は良い。ただし finding としては残存。

### C. MITRE マップへのプロビジョニング/過剰テクニックの混入 — precision 低下の主因
`reports/mitre.csv`（confirmed 24 件）に、攻撃と無関係なテクニックが混入している。

- **noise クラスタ(3) 由来の混入:** `T1036`（masquerading）, `T1083`（file discovery）, `T1098`（account manipulation）, `T1134.005`（SID-History）, `T1136.001`（create local account）。これらは正解キーの MITRE 表(§4)に**一切存在しない**。クラスタ自体は "noise" と正しく判定しているのに、**クラスタ内テクニックが confirmed マップに昇格**してしまっている（クラスタの noise 判定が MITRE 集計に伝播していない設計上の穴）。
- **cluster 2 の過剰アサイン:** `T1531`（Account Access Removal/Impact）, `T1558`（Steal/Forge Kerberos Tickets）, `T1588`（Obtain Capabilities）, `T1003.002`（SAM）。本件は NTLM・スタンドアロンで Kerberos 窃取(T1558)は文脈外、窃取対象は LSASS(T1003.001)であり SAM(T1003.002)や Impact(T1531)は裏付けがない。Sigma タグの機械的転記による over-tagging。
- **正しく降格できている対照例:** `T1190`（公開アプリ侵害）と `T1550.002`（Pass-the-Hash）は `mitre_unconfirmed` + `mitre_demotion_notes` で根拠付き降格できており、**降格ロジックは機能している**。問題は noise クラスタと cluster 2 over-tag に降格が及んでいない点。

### D. プロビジョニング・ノイズが high/medium finding として表面化
cluster 3 に `Hidden Local User Creation`(high), `Suspicious Service Path`(high), `New or Renamed User Account with '$' Character`(medium), `Addition of SID History to AD Object`(medium), `Password Reset By Admin`(medium) が surface。正解キー §1 のベースライン/プロビジョニング残渣（既定コンピュータアカウント `*$`、OOBE のサービス登録等）に相当。**noise クラスタに収容し open_questions で「既定の computer/provisioning アカウントか検証要」と留保**している点は妥当だが、high severity のまま残るためレビュー負荷・誤読リスクは残る。

### E. IOC の軽微な誤分類
- `\MINWINPC$ (S-1-5-18)` を confidence=**confirmed** で IOC 化。これは WinPE/プロビジョニング既定のコンピュータ名であり良性。confirmed は過大。
- 一方 `-\-`（パーサノイズ）は confidence=**noise** と正しくラベルし IOC 昇格を回避（正解キー §5 の罠を回避）。✅

### F.（軽微な内部矛盾）
- cluster 1 の `mitre_techniques` に `T1070.006`（Timestomp）が confirmed として列挙される一方、prose・timeline_notes は同事象を「良性の Set-Date」と結論。テクニックリストと散文の帰属が不一致。

---

## 4. 見落とし・掘り下げ不足（Missed / Shallow Artifacts）

最終結論は正しいが、正解キーが期待する**裏付けアーティファクトの粒度**に届いていない箇所。

| 項目 | 正解キーの期待 | TLVB の現状 | 影響 |
|---|---|---|---|
| **攻撃元 `WS01`（最重要識別子）** | NTLM は送信元 IP を記録せず、唯一の手掛かりは **Workstation 名 WS01**（§3） | narrative には WS01 を明記。だが**構造化 IOC（`ioc.csv`）に WS01 行が無い** | 中：最重要の攻撃者識別子が機械可読 IOC から欠落 |
| **Defender 1116/1117 の具体値** | `Name: HackTool:PowerShell/Lsassdump.A` / `ID 2147807171` / `Source: AMSI` / `Process: wsmprovhost.exe` を読む | Sigma 検知名(Password Dumper 等) と `wsmprovhost.exe` は取得。だが脅威名 `Lsassdump.A`・EventID 1116/1117 を明示引用していない | 小：実体は捕捉、命名粒度のみ不足 |
| **窃取手法 comsvcs.dll MiniDump** | 4104 に記録された `comsvcs.dll MiniDump` を読み取る | 「資格情報ダンプツール」と一般化。具体手法名を抽出せず | 小：手口の特定が浅い |
| **永続化の中身** | フィルタ/コンシューマ名 `WinUpdateFilter` / `WinUpdateConsumer` → powershell、ペイロード `wmi_persist.log`（無害） | T1546.003 を検出するが、フィルタ/コンシューマ名・ペイロード正体は open_question 止まり | 小〜中：§5 のトラップ（SCM との区別）に関わる |
| **WMI 5861 SCM 良性サブスクリプションの明示除外** | 攻撃の 5861 と Windows 標準 `SCM Event Log Consumer`(SourceName=Service Control Manager) を**必ず区別**（§5 トラップ） | 攻撃の永続化は検出。だが SCM 良性 5861 を「区別した」旨の明示記述がない（誤検出はしていない＝SCM を永続化扱いしていない点は◎） | 小：誤検出はないが区別の明示が無く、トラップ回避の説明力が弱い |
| **永続化の発火段階（Stage 7）** | notepad.exe 起動→コンシューマ発火→powershell→`wmi_persist.log` 生成（△） | 検出なし | 小：正解キーでも △ 扱い |

---

## 5. 虚偽の主張（False Claims）の有無

**結論を左右する虚偽の主張（窃取成功の断定、攻撃者による時刻改ざんの断定、ポートスキャンの捏造等）は無い。** これは本シナリオの合否を分ける最重要点であり、TLVB はクリア。

「虚偽寄り」と評価できるのは finding 単体レベルで以下:
1. **anomaly A5「侵害された管理者によるスクリプト化された収集ステージング」**（§3-A）。証拠（同一秒の jumplist 4 フォルダ）からの**過剰な意図推定**で、シナリオに存在しない「データ収集」を主張している。noise クラスタ収容により最終ナラティブには波及していないが、finding テキストとしては根拠を超えた断定。
2. **MITRE confirmed への T1531/T1558 等の混入**（§3-C）。「確認済み」ラベルでありながら裏付けが無く、機械可読サマリ上は虚偽の「確定テクニック」として残る。

→ いずれも **report_consistency ゲート**（`status: clean`）はすり抜けている。consistency ゲートは「降格テクニックの散文での主張」「exec_brief の ungrounded mention」「unreliable timeline 上の最早主張」等は検査するが、**noise クラスタ内 finding の過剰意図推定**や **confirmed MITRE の over-tag** は検査範囲外であることが分かる（ゲートの盲点）。

---

## 6. 時刻アーティファクトの扱い（個別評価）— ✅ 合格

正解キーが tamu2_3 の教訓として最重視した時刻トラップに対し:
- Original Install Date が実攻撃日(6/12)より未来(6/13)を指す件 → **攻撃と無関係なプロビジョニング由来と正答**。実際 TLVB は 6/13 タイムスタンプのブートチェーン群（cluster 3）を「OOBE/specialize の正規プロビジョニング」と判定しており、**未来日付の残渣を攻撃と誤認していない**（取得時刻 6/12 20:13 JST より後の 6/13 イベントが provisioning だと正しく推論）。
- 約16時間の後方時刻ステップ → 「Set-Date によるキッティング時刻補正」と良性帰属。
- 攻撃の時系列（4625/4624/Defender/WMI）は **6/12 19:40 JST** に凝縮して再構成（`timeline.csv`）、正解キーの 6/12 JST と一致。

ただし `timeline_reliability=unreliable` としたことで「絶対順序は信頼できない」と全体に保留を付けており、これは安全側だが、実際には攻撃ウィンドウ内（±30 秒）の順序は健全であり、過度に弱気とも言える（結論の確度を自ら下げている面がある）。

---

## 7. 改善提案（精度向上に向けて）

1. **noise クラスタの MITRE 伝播を遮断:** クラスタが `attack_phase=noise` のとき、その finding の technique を confirmed `mitre_mapping` / `mitre.csv` に昇格させない（または `unconfirmed` 扱い）。→ §3-C の T1036/T1083/T1098/T1134.005/T1136.001 混入を解消。
2. **意図推定 finding のガード:** anomaly_hunter が「collection/staging/exfil」等の**結果論的意図**を断定する場合、対応する collection/exfil アーティファクト（コピー先・アーカイブ・送信痕）の有無を必須条件にする。無ければ severity を informational に降格。→ §3-A を抑止。
3. **IOC への Workstation 名の昇格:** 4625/4624 の Workstation フィールド（`WS01`）を IOC として確実にエクスポートする。NTLM で送信元 IP が `-` のケースでは特に重要。
4. **MITRE over-tag の抑制:** Sigma タグの機械転記時、ケースに前提アーティファクト（Kerberos/web/SAM 等）が無いテクニック（T1558/T1190/T1003.002 等）は `mitre_demotion_notes` の仕組みを cluster 2 にも適用。
5. **WMI 5861 の SCM 除外を明示化:** SourceName=Service Control Manager の `SCM Event Log Consumer` を良性として明示除外した旨を narrative に出力し、攻撃の `WinUpdateFilter/Consumer` と区別したことを示す（誤検出は既に無いので、説明力の補強）。
6. **consistency ゲートの拡張:** 「confirmed MITRE に前提アーティファクト不在のテクニックが無いか」「noise クラスタ内 finding が意図を断定していないか」をチェック項目に追加。

---

## 付録: 参照した成果物

- `synthesis.json`（44 findings / 3 clusters / overall_story / exec_brief / mitre_mapping / mitre_demotion_notes / timeline_notes / ungrounded_mentions）
- `reports/{report.json, report.html, ioc.csv, mitre.csv, findings.csv, timeline.csv, clusters.csv, report_consistency.json}`
- `findings/by-skill/anomaly_hunter.json`（lens A5）
- `findings/by-rule/{sigma,hayabusa}/*.json`（53 件）
- `parse_review.json`（全パーサ auto-skip）
</content>
</invoke>
