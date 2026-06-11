# Contributing to forensia

forensia への貢献に興味を持っていただきありがとうございます。
このドキュメントは「何を・どこに・どう書くか」の最短ガイドです。実装の詳細は [docs/](docs/) を、開発環境のセットアップ・テストコマンド・CLI フラグは [docs/development.md](docs/development.md) を参照してください。

## セットアップ

```bash
git clone https://github.com/sumeshi/forensia
cd forensia
uv sync
```

LLM 接続 (`.env`) や Web UI のセットアップは [docs/development.md](docs/development.md) を参照してください。

## 変更を入れる前に知っておくべき設計原則

詳細は [docs/design-principles.md](docs/design-principles.md)。レビューで最も問われるのは以下です。

### 1. 宣言層ファースト

Event ID の解説、検知ルール、フォールバック手順、QuestionSpec、構造化回答の解釈文 (`interpretation_template`)、verdict 語彙などの **DFIR 知識は `src/forensia/rulepacks/` 配下の YAML に置きます**。Python 側に rule_id / event_id / ホスト名などのハードコード分岐を増やす PR は原則受け付けません。

- 新しい検知観点 → `rulepacks/<pack>/*.yaml`([docs/rules-and-profiles.md](docs/rules-and-profiles.md))
- 新しい定型質問 → `rulepacks/_schema/question_routing.yaml`
- 新しいテーブル → `rulepacks/_schema/<table>.yaml` の schema card

### 2. 決定的処理を LLM に渡さない

ルーティング、リトライ、SQL 検証、重複判定、集計、整形、値の検証はコードで行います。LLM ロールを追加するときは「`<TASK>` を 1 文で書けるか」を確認してください。

逆方向も同じく重要です: **LLM の出力を無検証で永続状態にしない**。verdict はコード側の整合ゲート(主張された Event ID・必須エンティティと結果行の照合、フォールバック行からの confirmed 禁止)を通り、memory への書き込みは観測された evidence_id・エンティティ名のみが受理されます。これらのゲートを弱める変更には、相応の根拠とテストが必要です。

### 3. verdict / status は列挙であり自由文字列ではない

許可値と層間マッピングは `rulepacks/_schema/verdict_taxonomy.yaml` が正本です。新しい値(例: `untestable`)を増やすときは taxonomy を編集し、Python 側の Literal / validator を追随させます。validator の回避はバグ扱いです。

なお `refuted`(証拠により反証)と `untestable`(必要なテレメトリがケースに存在せず検証不能)は意味が異なります。「証拠が無い」ことを反証として記録しないでください。

### 4. スキーマ変更にはマイグレーションが必須

`db/schema.py` の `CREATE TABLE IF NOT EXISTS` を変更しても**既存ケース DB には適用されません**。既存テーブルへ列を追加する場合は、`db/database.py` の `_apply_migration_once("<key>", ...)` にマイグレーションを必ず追加してください(`ALTER TABLE ... ADD COLUMN IF NOT EXISTS` パターン)。mutable なテーブルを追加した場合は `_reset_case_tables()` と対応するテストも更新します。

### 5. 証拠への traceability を保つ

durable な結論(findings / claims / memory facts)は必ず evidence_id まで辿れるようにします。証拠を要約・ランキングする抽象を追加するときも、元証拠への参照経路を切らないでください。

### 6. ベンチマークを最適化対象にしない

`./templates/` + BENCHMARK.md の CFReDS ベンチマークは**測定器であり、最適化対象ではありません**。特定の設問・ホスト名・ファイル名・日時に紐づくコードパスやプロンプトの追加は禁止です。ベンチマークで欠落を見つけたら「どの汎用 DFIR 能力が欠けているか」に翻訳してから実装してください(CLAUDE.md Rule 16)。

## テスト

```bash
# 全テスト(秒単位で完了すること)
UV_CACHE_DIR=/tmp/uv-cache PYTHONPATH=src uv run python -m pytest tests/ -q

# 宣言層・ドキュメントの整合性監査
forensia doctor
```

- **実 LLM 呼び出し・実 LLM サーバを叩くテストは書かない**(理由は [docs/development.md](docs/development.md) の「テスト方針」)。
- 決定論ゲートを変更した場合は対応する回帰テストを更新してください:
  `tests/test_checker_gates.py`(verdict 整合ゲート・フォールバック降格・memory フィルタ・finding 検証)、
  `tests/test_untestable_resolution.py`(untestable 早期解決)。
- ルール YAML や `question_routing.yaml` を変更したら `scripts/audit_schema_coverage.py --strict`(`forensia doctor` に含まれる)が通ることを確認してください。

## ドキュメント

コードを変更したら**同じ PR で** [docs/](docs/) の該当ページと、ユーザー向け挙動が変わる場合は README.md を更新してください(docs/architecture.md 冒頭の規約)。

## PR の出し方

1. ブランチを切り、変更は小さく焦点を絞る(無関係なリファクタを混ぜない)。
2. `pytest` と `forensia doctor` を全て通す。スキップ・失敗を残したまま「完了」としない。
3. コード・コメント・コミットメッセージは英語で書く。
4. PR 説明には「何を・なぜ・どう検証したか」を書く。LLM プロンプトの変更は before/after の挙動差を添えると速くレビューできます。

## バグ報告・提案

Issue には再現手順(可能なら `ai_logs/` の該当エントリや `hypothesis_reasoning` の抜粋)と、期待した挙動・実際の挙動を添えてください。機微な調査データはそのまま貼らず、サニタイズしてください。
