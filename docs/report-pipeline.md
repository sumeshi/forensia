# Report Pipeline

レポートセクション充填の詳細仕様。

---

## 1. レポートセクションの状態

`report_sections.status` は 4 値:

| 値 | 意味 |
|---|---|
| `draft` | 証拠 gap がある / 弱い support |
| `stable` | AI ワークフロー上で既知の gap なし |
| `ai_exhausted` | AI ワークフローがこれ以上の有意な手がかりを生成しなくなった |
| `human_reviewed` | 人間が明示的にレビュー済み |

これらは workflow state であり、evidence state ではない。

---

## 2. レポートテンプレート契約

テンプレートはコントリビュータが定義する section の契約であり、durable なレポート状態ではない。

### 2.1 所有境界

- テンプレートファイルは `src/forensia/report_template/` 配下
- 新規ケース作成時には case-local の `report_template/` がパッケージ既定からコピーされる
- CLI のレポート生成は case-local テンプレが存在するときはそれを優先
- `report --write --template-dir` で明示的に外部テンプレを指定可能

テンプレートは入力であり、生成されたセクション本文は `report_sections` に永続化される。

### 2.2 Frontmatter フィールド

各テンプレートはオプションの YAML frontmatter を持つ Markdown ファイル。

| フィールド | 役割 |
|---|---|
| `behaviors` | quality gate / 振る舞いフラグの list (例: `require_chronological_table`) |

`behaviors` を増やしたいときは [writer.py](../src/forensia/report/writer.py) 側の `_GateCtx.behaviors` 判定を 1 箇所だけ伸ばし、section_key にハードコードしない。

現行 writer が frontmatter から読む契約フィールドは `behaviors` だけ。`section` / `title` / `prompt` / `evidence_queries` を置いても durable key や evidence access には使われない。section title は本文見出しから抽出され、block ごとの要求は `##` heading と HTML comment hints (`evidence_keypoints` / `mode` / `answer_id` / `answer_spec` / `question`、旧評価テンプレート互換の `benchmark_id`) で表現する。

### 2.3 Section の同一性と順序

- ファイル名パターン `[0-9]*_*.md` でテンプレを発見
- 再充填順はファイル名の lexical 順
- durable な `section_key` はファイル stem
- レポート出力は `section_key` で並び替え

section key は **stable な識別子** として扱う。ファイル名のリネームより key 変更のほうが影響が大きい。

### 2.4 テンプレートで宣言すること / しないこと

宣言する:
- レポート構造
- セクション固有の執筆要求 (`##` block と comment hints)
- block ごとの keypoint / structured answer hints
- 証拠不十分時のプレースホルダ

宣言しない:
- durable なワークフロー状態
- mutable なレポート status
- provenance 保存ルール
- セクション本文の正本 (これは `report_sections` テーブル)

テンプレ著作は英語で揃える。scaffold の見出し、表頭、コメント、プレースホルダはすべて英語。出力言語は runtime の `LLM_OUTPUT_LANGUAGE` で制御される。

### 2.5 DB 連携

- 充填済みセクション本文は `report_sections` に UPSERT
- confidence は本文の初期スコア、quality gate、evidence_id validation、claim support、extra gaps を合わせて決まる
- claims は本文から抽出して `claims` に書き込み
- claim の provenance は本文中の finding_id / hypothesis_id / evidence_id と検証結果から計算
- gap は明示的な insufficient-evidence マーカー、section agent の extra gaps、quality gate、claim/evidence validation から集約され、次サイクルの仮説候補になる
- block が `question` / `answer_spec` / `mode: structured` を持つ場合、`questions.py` が `question_routing.yaml` の QuestionSpec に解決し、結果を `section_questions` に保存。case-wide probe は `section_key='__case_probe__'` として保存
- structured answer は `reports/structured/answers.json` と CSV に永続化し、section ごとの解決結果は `reports/debug/<section>_questions.json` に dump

### 2.6 内蔵テンプレートと評価用テンプレートの分離

| 場所 | 用途 |
|---|---|
| `src/forensia/report_template/` | パッケージ同梱の汎用インシデントレポート。新規ケース作成時に各ケースの `report_template/` としてコピーされる |
| `./templates/` (リポジトリルート) | このソフトウェアの推論精度を計測するためのベンチマーク専用テンプレート。BENCHMARK.md / BENCHMARK-ANSWERS.md と対応し、6_appendix で 12 個の Scored Question を block として展開する |

ベンチマーク評価時は `forensia investigate ... --template-dir ./templates` で指定して使う。ベンチマーク以外の通常運用ではこの templates/ は使わない。

---

## 3. レポート品質ゲート

各セクション本文充填後、`_quality_gate_section` ([report/writer.py](../src/forensia/report/writer.py)) が静的チェックを走らせ、検出ごとに gap を追加して confidence を上限値まで下げる。検査はテンプレ非依存で全セクションに適用される。

セクション固有の挙動は `behaviors:` frontmatter で宣言。例: `require_chronological_table` / `require_recommendations_strength` / `canonical_evidence_scope`。`_GateCtx.behaviors` を見て発火条件を分岐する。section_key を Python 側でハードコードしない。

### 3.1 検査一覧

| 検査 | 発火条件 | confidence 上限 |
|---|---|---|
| Placeholder entity | `PLACEHOLDER_ENTITY_PATTERN` 一致 | 0.5 |
| Template marker leak | `HTML_FILL_PATTERN` 一致 | 0.3 |
| Heading / title mismatch | 本文先頭の `#` 見出しが `report_sections.title` と乖離 | 0.65 |
| Timeline ordering | `require_chronological_table` 持ちセクションで date 列が非単調 | 0.6 |
| Recommendations strength | `require_recommendations_strength` 持ちセクションで `confirmed` / `may indicate` / verification 関連語が欠落 | 0.65 |
| Verdict inflation | source verdict に `confirmed` がないのに本文が強い断定語を使う | 0.6 |
| Raw evidence dump | NULL / None だらけの raw evidence 表が混入 | 0.55 |
| Output language drift | 本文の言語が `LLM_OUTPUT_LANGUAGE` と乖離 | 0.4 |
| Open-question markers | `?` / `？` / `TBD` / `要確認` / `未調査` / `XXX` | 0.55 |
| Empty body | 表 / 見出し / 引用を除いた実質本文が 80 字未満 | 0.3 |
| Bullet-only | bullet 行のみで narrative なし | 0.6 |
| Hedge without citation | `may` / `could` / `思われる` 等があるのに timestamp も finding_id も引用なし | 0.5 |
| Citation token without finding_id | `evidence` / `根拠` 等を含むのに finding_id がない | 0.75 |
| Duplicate paragraph | 長さ 40 以上の同一段落が 2 つ | 0.5 |
| Out-of-range timestamp | 本文の `YYYY-MM-DD` が今日 + 1 を超えるか 1990 未満 | 0.4 |
| Overused evidence id | 同一 evidence_id が 3 以上のセクションで引用 | 0.7 |
| JSON object leak | raw LLM response らしい JSON object が本文に漏れた | 0.3 |
| Failure marker spam | `Section block failed` / `Block skipped` が本文に混入 | 0.15 |

gap notes は `report_sections.gaps` に積まれ、次サイクルでは追加仮説として扱われる。新規ゲートを追加するときは 1 関数 + 1 note 文字列に閉じ込め、テンプレ固有ロジックを書かない。

---

## 4. プロンプトの組み立て

LLM 入力は固定文字列ではなく、フェーズと文脈に応じて段階的に組み立てる。

1. **DFIR プレイブック注入 (phase-aware)**: `_dfir_playbook(phase)` が `_schema/playbook/<phase>.md` を読む。planning 系 (`broad_plan`, `hypothesis_plan`) では Application Catalog / Artifact-to-Application Inference / FP Reduction を意図的に省略 (これらは evidence 解釈用)。interpretation 系 (`check`, `report_section`, `section_agent_check`) では全部入り
2. **schema_card + SQL クックブック注入**: planner / checker に対象 table の `<SCHEMA_CARDS>` と 6 種の `<SQL_COOKBOOK>` を渡し、ゼロから SQL を書かせない。SQL validator の許可 table は `get_allowed_tables(db)` と live schema に従う
3. **動的コンテキスト**: case の `time_range`、`uncovered_keypoints`、active / resolved hypotheses、recent history、observed_keypoints を役割ごとの builder で挿入。hypothesis は `_slim_hypothesis_dump` で null / 空フィールドを落として serialize、findings は `_slim_findings` が同一 rule パターンを `count` 付き 1 行に集約
4. **report_brief のセクション別スリム化**: `_slim_report_brief_for_section` がセクション key を見て、`1_overview` 以外は `time_range` / `source_timezone` / `investigation_objective` のみに削る。top_findings や全仮説の丸ごとダンプは行わない (2/3/4/5 系統には scoped `top_findings` / `confirmed_hypotheses` / `active_hypotheses` を選択的に戻す)
5. **トークン予算ガード**: `_assemble_messages_with_budget()` が system を保護したまま user / dynamic 側のみ trim

---

## 5. 仮説検証ループの詳細

### 5.1 1 サイクル (`plan_cycle`) の流れ

```
broad_plan → for each active hypothesis: plan → exec(+fallback) → check → track → resolve → refresh_report(stale-first) → inject_gaps_as_new_hypotheses
```

- `plan_cycle` は `--max-iter` で上限
- 仮説あたりのクエリ試行は `--max-queries-per-hypothesis` で上限
- レポート再充填は `--report-every-n-cycles` ごとに走る

### 5.2 仮説の入り口

`state.active_hypotheses` に入る仮説は 3 経路ある。

1. `rule.hypotheses`: ルール発火時にテンプレから生成。`source_rule_ids` が埋まる
2. `gap_identifier` + `hypothesis_drafter`: gap 領域から起案。`source_rule_ids` は空
3. `follow_up_questions`: confirmed になった `source_rule_ids` 付き仮説から自動派生

レポート writer から出る gap 仮説は `_inject_gap_hypotheses` を通り、`GapHypothesisOutput` の Pydantic バリデーションで形を整え、LLM が `required_entities` / `confirm_when` を落とした場合はヒューリスティックなセーフティネットで補完する。

### 5.3 Planner

`build_query_intent_messages` → `build_sql_composer_messages` の 2 段呼び。

- **schema cards** (`<SCHEMA_CARDS>`): `rulepacks/_schema/*.yaml` の `core_columns` (planner に見せる短いリスト、5〜13 列) + `column_descriptions` (1 行説明) + `columns` (SQL validator 用フルリスト)。intent planner の `target_table` は主に `evtx_events` / `mft_entries` / `mft_timeline` / `prefetch_executions` から選び、composer は対象 table の schema_card と live schema を見る。validator の allowlist は `get_allowed_tables(db)` が live DB から組み立て、`findings` / `prefetch_timeline` / `report_*` / `section_*` などの派生テーブルも必要に応じて許可する
- **SQL クックブック** (`<SQL_COOKBOOK>`): event_id 列挙 / 時間範囲 / GROUP BY / COALESCE / MFT path LIKE / Prefetch という 6 種の SELECT テンプレ。弱い LLM はゼロから合成せず、これをコピー編集することを想定
- **SQL リトライ**: `validate_select_sql` で弾かれたら `_retry_query_once` が最大 `_PLANNER_SQL_MAX_RETRIES = 3` 回まで `sql_composer` のみを再呼び出し。intent 段階は再実行しない
- **フォールバック**: リトライしても valid SQL にならなければ、`_fallback_planned_query_from_hypothesis` が `hypothesis.confirm_when.co_observed_event_ids` から `SELECT … FROM evtx_events WHERE event_id IN (…) ORDER BY timestamp LIMIT 500` を deterministic に生成。check フェーズは必ず走る

### 5.4 Executor とフォールバック

executor は計画された SQL を実行する。0 行で、かつ仮説に `source_rule_ids` + `fallback_search` 宣言があれば、宣言順にフォールバックフェーズを試行する。fallback SQL は `engine.execute_fallback_search` がコードで組み、LLM は介在しない。

フォールバックがヒットしたら `fallback_info = {phase, source_rule_id}` を checker プロンプトに渡し、verdict にフォールバック由来であることを反映させる。

### 5.5 Checker

`build_verdict_review_messages` が verdict / rationale / confidence の 3 フィールドのみ返す。default 基準は相関ベース:

- `confirmed`: `required_entities` が同じ rows で共起
- `refuted`: 0 行または矛盾 entity
- `inconclusive`: 一部の `required_entities` のみ観測 → rationale で欠落 entity を名指しすること

「直接的因果は証明されていない」「さらなる調査が必要」のような名指しなしの hedge は禁止語として明示。

verdict は LLM 出力のまま採用されず、コード側の整合ゲート (`_verify_verdict_consistency`) を通る: confirmed が主張する Event ID (confirm_when + rationale 中の event 表現) が結果行の event_id 集合に存在しない場合、または `required_entities` 列が全行 NULL の場合は inconclusive に降格。フォールバック検索由来の行からの confirmed は `_guardrail_check_payload` が newlead に降格する。

verdict==confirmed のときだけ `build_finding_extractor_messages` が呼ばれ、structured findings を抽出して検証後に `findings` テーブル (`rule_id='hypothesis-extraction'`) へ永続化。`build_memory_updater_messages` は verdict 確定後に durable memory updates を提案する (結果行サンプルと observed evidence_ids がプロンプトに渡され、行に実在しないエンティティ名・evidence_id はコード側で破棄)。

### 5.6 Progress Tracker

`HypothesisProgressTracker` は仮説単位の dataclass で、各クエリの `(query_fingerprint, verdict, row_count)` を記録。check のたびに次の決定論的判定を行う。

| メソッド | 条件 | 効果 |
|---|---|---|
| `should_auto_confirm(rule_context, rows, hypothesis)` | `_co_observation_satisfied` ([checker.py:218](../src/forensia/ai/checker.py#L218)) が `same_host` で rows をグループ化し、`within_minutes` の時間窓内ですべての `co_observed_event_ids` が共起 | LLM verdict を無視して confirmed に強制。時刻/ホスト列がない行は未充足。`co_observed_event_ids` 未宣言の hypothesis は auto-confirm しない |
| `should_auto_refute(threshold=3)` | 3 連続 0-row inconclusive (かつ partial 信号なし) | rule が `refute_when.zero_rows` を宣言していれば refuted、そうでなければ untestable に強制 |
| `should_pivot(fp)` | 同じ query fingerprint が 2 回以上出現 | planner に pivot 指示 |
| `_unavailable_missing_event_ids` | inconclusive の `missing_questions` が、ケースに存在しない Event ID のみを参照 (mft/prefetch の代替経路なし) | 初回 check で即 untestable |
| `_investigate_one_hypothesis` short-circuit | 初回 plan で SQL / template / `confirm_when` フォールバックのいずれも組めない | 即 refuted (`no executable evidence path`) |

`refuted` (証拠による反証) と `untestable` (必要なテレメトリ不在で検証不能) は区別され、untestable はレポートの Gap セクションに不足テレメトリ付きで列挙される。

`query_fingerprint` は sqlglot AST を canonicalize して event_id / computer マーカーと合わせてハッシュ化したもの。空白や別名違いを吸収する。sqlglot 不在時は文字列正規化に fallback。

`_merge_active_hypotheses` は `MAX_ACTIVE_HYPOTHESES = 8` を強制。既存仮説の更新はカウント対象外で、上限超過分の新規だけが drop される (`[CAP]` ログ)。

### 5.7 仮説 dedup

仮説の同一性判定はコード側で完結する。

- `_hypothesis_similarity` (`hypothesis_manager.py`): triple (actor / action / target) ベースの類似度
- `_dedup_new_hypotheses` (`investigator.py`): drafter 出力後、active との類似度 > 0.85 で drop
- `_best_hypothesis_match` (`hypothesis_manager.py`): `_merge_active_hypotheses` 内で同一の閾値判定により upsert 先を決める

### 5.8 Resolver

仮説が確定すると `_resolve_hypothesis` が次を行う。

1. `state.resolved_hypotheses` に移動し、DB の `status` を `confirmed` / `refuted` に upsert
2. 各 `source_rule_id` についてキャッシュされた `load_rule_by_id` でルールを引き、id 一致する `HypothesisDeclaration` を探す
3. 宣言から:
   - `stale_sections` に `decl.report_sections` を追加
   - confirmed のときは `decl.follow_up_questions` を新たな active 仮説に追加 (description で dedup)
4. 該当 section について `UPDATE report_sections SET stale = TRUE WHERE section_key = ?` を発行

### 5.9 Termination

サイクルが終了する条件は次のいずれか:

- すべての active 仮説が解決し、broad_plan が `stop` を出し、レポート gap が空
- 3 サイクル連続で進捗なし (`--no-progress-limit`)
- `--max-iter` サイクル完了

「進捗なし」は仮説解決も新規 gap 仮説追加もレポート status カウンタ変動もないサイクルを指す。
