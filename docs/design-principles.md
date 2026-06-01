# Design Principles

forensia がコード変更を超えて守る設計原則。新機能を入れるときの判断材料。

---

## 1. 状態の 3 層分離

forensia は信頼度と寿命が異なる 3 種の状態を分離して扱う。

| 種類 | 場所 | 役割 |
|---|---|---|
| Case State | `db/case.duckdb` | 取り込んだアーティファクトを正規化した証拠と、それから導かれる永続調査オブジェクト。証拠行は immutable 寄りだが、findings / hypotheses / report_sections などの workflow state は更新される |
| Trace State | `db/trace.duckdb` | 調査セッションのライフサイクル、ステップ I/O、進捗履歴。原則 append-only |
| Structured Memory | `memory/**/*.md` | Case と Trace から LLM 向けに再構成した文脈。regeneratable |

権威の階層:
- Case State は「ケースが現状何を含んでいるか」を答える正本
- Trace State は「どうやって現在状態に達したか」を答える正本
- Memory は **projection** であり、authority ではない

新機能が永続状態を要するなら、Markdown やログだけでなく DuckDB のテーブルに表現する。

---

## 2. LLM 出力は正本ではない

実装は LLM の活動を記録するが、生の出力を永続状態としては扱わない。

- LLM のリクエスト / レスポンスは `ai_logs/<session_id>/` に保存
- 各ステップの `input_json` / `output_json` は `trace.investigation_steps` に保存
- findings / hypotheses / claims / report_sections は DuckDB に永続化
- Memory Markdown は derived state であり、再生成可能

---

## 3. 証拠への traceability を保つ

durable な結論は evidence_id まで辿れる。

- 証拠テーブルは正規化された原本レコードを持つ
- findings は構造化された evidence 参照を持つ
- memory の facts / timeline には evidence 参照を含める
- claims は `finding_ids` / `hypothesis_ids` / `evidence_ids` をリンクとして持つ

新たに証拠を要約・ランキングする抽象を追加するときは、必ず元証拠への参照経路を保つ。

---

## 4. 1 LLM ロール = 1 文で書ける目的

`<TASK>You are a sql_composer. Write a DuckDB SQL query that satisfies the given intent.</TASK>` のように、ビルダー冒頭が複文になったら粒度が崩れているサイン。

- **ルーティング・テンプレマッチング・整形は LLM に渡さない**。`validate_select_sql` / `HypothesisProgressTracker` / `_dedup_new_hypotheses` / `_format_structured_answer` / `execute_fallback_search` はすべてコード側で決定論的に動く
- 新ロールを足すときは `<TASK>` を 1 文で書けるか確認

LLM ロールの一覧と入出力スキーマは [llm-roles.md](llm-roles.md) を参照。

---

## 5. ノブはルール宣言層に置く

新しい AI 駆動の振る舞いを追加するときは「これを 1 文の `<TASK>` で書けるか」「コード側で表せないか」を先に問い、答えが No / Yes ならルール宣言ノブで表現できないかを確認する。Python に rule_id や event_id のハードコード分岐を増やす前に、必ず宣言層 (`src/forensia/rulepacks/_schema/`) を検討する。

ルール経由で挙動を変えられる主なノブ:

| ノブ | 宣言場所 | 効果 |
|---|---|---|
| `correlate_with` | rule | planner プロンプトに「これらの event id も見ろ」ヒント |
| `confirm_when.co_observed_event_ids` | `hypotheses[]` | tracker の auto-confirm 基準 |
| `refute_when.zero_rows` | `hypotheses[]` | checker のデフォルト refutation |
| `fallback_search` | rule | LLM 不在の 0-row リカバリ |
| `follow_up_questions` | `hypotheses[]` | confirmed 時に次の調査を自動派生 |
| `report_sections` | `hypotheses[]` | 解決時に stale 化するセクション |

---

## 6. 仮説単位の文脈隔離

検証中の暫定 facts / timeline / tasks は `memory/scratch/<hypothesis_id>/` に閉じ込め、confirmed 時に共有記憶へ昇格、refuted 時に archive へ退避する。他仮説の暫定情報を流入させない。

`_apply_memory_updates` ([investigator.py:737](../src/forensia/ai/investigator.py#L737)) は `hypothesis_id` と `verdict` を見て書き込み先を振り分ける。仮説起源の memory write には必ず `hypothesis_id` を持たせる (落とすと共有記憶に無条件書き込みされ、このライフサイクルを壊す)。

レポートセクション間の汚染防止も同様:
- `_summarize_context_sections`: 過去セクション本文はタイトル + 先頭 120 字のみで渡す
- `current_section_outline`: 同一セクション内の先行ブロックは見出し + 120 字サマリの list で渡す
- `_filter_prior_runs_by_heading`: 現在の `block_heading` に一致する prior_runs のみ採用
- `_load_reusable_section_evidence` / `_load_reusable_section_facts`: `section_key = ?` 完全一致のみで scope

---

## 7. verdict 値は列挙であり自由文字列ではない

verdict 文字列は許可リスト。許可値は `src/forensia/rulepacks/_schema/verdict_taxonomy.yaml` で宣言され、3 箇所の書き込み境界で `forensia.core.verdicts.assert_valid_verdict` により強制される。

| レイヤー | 強制サイト |
|---|---|
| `hypothesis_verdict` | `hypothesis_manager.py:_upsert_hypothesis()` + `Hypothesis.verdict` field validator |
| `section_verdict` | `section_agent.py:_store_section_run()` |
| `structured_status` | `report/writer.py:_normalize_structured_answer()` |

新しい verdict 値を増やすなら `verdict_taxonomy.yaml` を編集する。validator を Python から回避するのはバグ扱い。

層間マッピング (`hypothesis_to_section`, `section_to_benchmark`, `benchmark_to_claim`) も taxonomy ファイルが宣言するので、層間変換が必要なら `map_verdict()` を呼び、独自テーブルを作らない。

---

## 8. SQL 安全性

LLM が出した SQL は読み取り専用の証拠アクセスとして扱う。

- `SELECT` と `WITH` のみ許可
- 複文は拒否
- 破壊的 SQL は拒否
- テーブルは allowlist で制限 (`get_allowed_tables(db)` + `_LEGACY_ALLOWED_TABLES`)

LLM は証拠アクセスを「提案」できても、生成 SQL で DB を mutate することはできない。

---

## 9. LLM 呼び出し総数は opt-in hard cap

`audit.LLMCallLogger` がすべての呼び出しを記録する。

- `investigator.investigate(max_llm_calls=...)` (CLI: `--max-llm-calls`) は opt-in の hard cap
- 既定値は `0` (無制限)。ローカル LLM ではコスト懸念がないため既定では無効
- クラウド API 利用時は明示的に正の値を指定 (超過で `RuntimeError`、soft warning ではなくループ終了)

プロンプト組み立てには別途トークン予算ガードがあり、`_assemble_messages_with_budget()` が system メッセージを保護したまま user/dynamic 側のみ trim する。

---

## 10. トークン予算は hard cap、しかし system は保護

- system プロンプトはトークン予算の trim 対象外
- user / dynamic content から先に削る
- system に直接連結することで予算ガードを回避しない

---

## 11. 概念モデルの境界

| 用語 | 意味 |
|---|---|
| Evidence | EVTX / MFT 行のような正規化済み生レコード |
| Finding | 証拠から導かれた観測条件・信号 |
| Hypothesis | 検証・反証する解釈 |
| Claim | レポートで読者に提示する記述 |
| Gap | confidence を阻む未知 |

これらの境界を混ぜると推論の監査と安全な再開が困難になる。Evidence と Finding は証拠近傍、Hypothesis は解釈、Claim はレポート向け、Gap は未知。

`suppressed` finding は削除ではない:
- suppressed な finding は durable なケース記録の一部として残る
- suppression は表示とワークフロー意味論を変えるだけで、証拠の存在は変えない
- finding が suppressed でも evidence リンクは残す

---

## 12. 構造化記憶は再構成可能

構造化記憶は DB と先行する evidence-backed 出力からの projection に留める。

- 排他的なビジネスロジックを memory Markdown だけに置かない
- 直近のプロンプト文脈からしか復元できない状態を作らない
- ファイル名と索引項目には安定 id を使う
- 明示的に要約されたファイル (`overview.md` など) を除き、追記履歴を in-place な書き換えより優先する

structured / benchmark / appendix ブロックが narrative memory を見ると既に形成された結論にブロック回答が引き寄せられるため、`core.memory.EvidenceOnlyMemory` wrapper で `facts` / `keypoints` / `entities` のみを露出する仕組みがある。切り替えは `core.memory.memory_for_section(memory, structured_mode=...)` の 1 箇所で行う。
