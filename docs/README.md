# docs

forensia の現在の実装を客観的に記述する設計書群。コードを変更したら同じ PR でここも更新する。

## 全体像

| ドキュメント | 内容 |
|---|---|
| [architecture.md](architecture.md) | パイプライン全体像。ステージ別データフロー、レポート生成、API スナップショット、ディレクトリ構造、設定 |
| [design-principles.md](design-principles.md) | 設計原則。状態 3 層分離、LLM 出力の扱い、traceability、ロール粒度、SQL 安全性、概念モデル境界 |

## 詳細

| ドキュメント | 内容 |
|---|---|
| [data-model.md](data-model.md) | DuckDB テーブル、`memory/*.md` 永続記憶、API DTO の定義 |
| [code-map.md](code-map.md) | `src/forensia/**` 各ファイルの責務 |
| [llm-roles.md](llm-roles.md) | LLM ロール (11 種) の呼び出しタイミング、入力、出力スキーマ |
| [report-pipeline.md](report-pipeline.md) | レポートセクション充填の詳細。テンプレート契約、品質ゲート、仮説検証ループの内部 |
| [rules-and-profiles.md](rules-and-profiles.md) | Rulepack / Profile / Allowlist の仕様。宣言層 (`_schema/`) のファイル一覧 |

## 開発

| ドキュメント | 内容 |
|---|---|
| [development.md](development.md) | 開発環境セットアップ、テスト方針、補助スクリプト、CLI フラグ、UI 詳細 |
