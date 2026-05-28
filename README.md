# TLVB

**TLVB** — *Timeline Longa, Vita Brevis*
(タイムラインは長く、人生は短い。だから自動化で攻撃の痕跡を炙り出す)

ATT&CK rules / Sigma rules / Skills-driven anomaly detection を組み合わせて、Windows フォレンジック・アーティファクトから攻撃の痕跡を抽出する自律型 IR エージェントシステム。**シグネチャ駆動 SQL + skills 駆動の抽象検出 + タイムライン解析** の 3 層構成。

## 設計コンセプト (TLVB 固有)

```
INPUT (collector zip / disk image / live triage)
  ↓
Tier 0   Parser ×N (Python) → 正規化 UnifiedEvent → DuckDB
  ↓        ※ findevil から継承。Hayabusa / EZ Tools / Plaso をラップ
Tier 1A  Signature-driven SQL Agent
           ATT&CK STIX + Sigma + 著名ルールを RAG で参照
           Agent が SQL を生成 → findings/<rule_id>.json
  ↓
Tier 1B  Skills-driven Abstract Anomaly Agent
           skills/<lens>.md の手順に従って、シグネチャでは
           引っかけられない攻撃パターンを timeline 全体から抽出
  ↓
Tier 2   Timeline Analysis Agent
           findings の前後 ±N 分を再度 LLM で読み、
           攻撃チェーンを再構成 + 矛盾を解消
  ↓
Tier 3   Reporter (HTML / CSV / JSON)
```

## 設計のポイント

- **Tier 1 が 2 段構成** — シグネチャ系 (1A) と抽象パターン系 (1B) を明示分離
- **Sigma / STIX 駆動の SQL Agent** — ルール集合から動的に SQL を生成する agent
- **Timeline-first** — Tier 2 を「findings 周辺の時間窓を読む」役割に特化

## 現在の状態

🚧 **WIP (初期化フェーズ)** 🚧
プロジェクト雛形のみ作成済み。Tier 1A/1B の設計と実装はこれから。

- [x] Go module / CLI 雛形
- [ ] Tier 0: パーサーの整備
- [ ] Tier 1A: signature-driven SQL agent の設計と実装
- [ ] Tier 1B: skills-driven anomaly agent の設計と実装
- [ ] Tier 2: timeline-around-findings の設計と実装
- [ ] Tier 3: Reporter
- [ ] Sigma / STIX ルール集の取り込み

## クイックスタート

```bash
# ビルド
make build           # → ./bin/tlvb

# Web UI 起動
make run             # → http://localhost:8080

# CLI run (Tier 0 → Tier 1 → Tier 2 → Tier 3)
./bin/tlvb run CASE_ID --evidence /path/to/collector.zip
```

詳細な前提条件 (SIFT Workstation 上のツール群、EZ Tools のパス、Hayabusa 等) は `docs/` 配下を参照。

## ライセンス

LICENSE 参照。
