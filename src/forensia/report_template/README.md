# Report Templates

`forensia report-write` が読み込むセクションテンプレート群。

## ファイル構成

```
1_overview.md        調査概要・FEC
2_timeline.md        攻撃タイムライン
3_hosts.md           侵害ホスト詳細
4_accounts.md        侵害アカウント・認証
5_persistence.md     永続化・実行（サービス・タスク・PowerShell）
6_ioc.md             侵害指標 (IOC)
7_gaps.md            調査不足・次のPDCA仮説
8_recommendations.md 推奨対策
```

## フォーマット

各ファイルの先頭にある YAML フロントマターが `report-write` の動作を制御する。

```yaml
---
section: 1_overview          # セクションID（一意）
title: "調査概要"             # レポートに表示されるタイトル
prompt: |                    # LLMへの指示。何を書くか・何を含めるか
  ...
evidence_queries:            # セクション生成前にDuckDBで実行するSQL
  - "SELECT ..."
---
```

本文の `<!-- 記入 -->` がLLMによって埋められる箇所。

## カスタマイズ

`forensia init` でケースディレクトリにテンプレートがコピーされる（予定）。
ケース固有の調査観点はコピー先を直接編集する。

## 調査不足の連携

LLMが記入できない箇所は `【調査不足: 理由】` と書くよう指示してある。
`7_gaps.md` が全セクションの不足箇所を集約し、次の PDCA サイクルの仮説として使われる。
