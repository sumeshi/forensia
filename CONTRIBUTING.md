# Contributing to forensia

このドキュメントは forensia の実装に手を入れる開発者向けの内部仕様書です。コードを変更しても保たれるべき不変条件、責務の境界、状態の所有関係をまとめています。ユーザ向けの概要は [README.md](README.md) を参照してください。

## 仮説からレポートまでの分業ループ

forensia は「賢い 1 体の調査員 LLM」ではなく、**1 文で目的を言える小さなロールを連続稼働させ、その出力を機械が裁定する**設計です。1 個の役割は読み取る context も出力するフィールドも狭く、決定論的に処理できるところはコード側で完結させます。これは `gemma3-4b` / `qwen3-8b` クラスのローカル LLM でも壊れにくいパイプラインを組むための必須要件です。

調査は `plan_cycle` 単位で進み、1 サイクル内で「仮説の起案 → SQL 検証 → finding 抽出 → 仮説確定 → レポート充填 → 新しい gap を仮説に投入」を 1 周します。サイクルは「全仮説が解決し、broad_plan が `stop` を出し、レポート gap が空」になるか、`--max-iter` / `--no-progress-limit` / `--max-llm-calls` の上限に達するまで繰り返します。

```mermaid
flowchart TB
    A["Artifacts (EVTX / MFT / Prefetch)"] -->|ingest + normalize| C[("Case State<br/>(case.duckdb)")]
    C -->|rule engine<br/>(deterministic)| F[("Findings + KeyPoints")]

    subgraph CYCLE["1 plan_cycle"]
        direction TB

        subgraph BP["broad_plan"]
            direction TB
            GI[/"gap_identifier<br/><i>観測 keypoint と未カバー領域から gap_areas を出す</i>"/]
            HD[/"hypothesis_drafter<br/><i>1 gap_area につき 1 仮説を起案</i>"/]
            GI --> HD
        end
        F --> BP

        subgraph HL["per-hypothesis loop (max_queries_per_hypothesis)"]
            direction TB
            QI[/"query_intent_planner<br/><i>取りに行く列・期間・対象テーブルを JSON で宣言</i>"/]
            SCK[/"sql_self_check<br/><i>intent の列が schema に存在するか検証</i>"/]
            SC[/"sql_composer<br/><i>SELECT 文を組む or template_id を選ぶ</i>"/]
            EX["executor (DuckDB)<br/><i>0 行なら rule.fallback_search を決定論的に発火</i>"]
            VR[/"verdict_reviewer<br/><i>rows と仮説から confirmed/refuted/inconclusive を出す</i>"/]
            FE[/"finding_extractor<br/><i>confirmed のときだけ structured finding を抽出</i>"/]
            MU[/"memory_updater<br/><i>verdict 確定後の memory diff を提案</i>"/]
            QI --> SCK --> SC --> EX --> VR
            VR -->|confirmed| FE
            VR --> MU
        end
        BP --> HL

        TR["HypothesisProgressTracker<br/>(deterministic: auto-confirm / auto-refute / pivot)"]
        HL --> TR
        TR -->|active| HL
        TR -->|resolved| RES["Resolver<br/>stale_sections + follow_up_questions"]

        subgraph RW["report writer"]
            direction TB
            SAP[/"section_agent_plan<br/><i>次のアクション(query/facts/write)を選ぶ</i>"/]
            SAC[/"section_agent_check<br/><i>集めた証拠が write 可能か判断</i>"/]
            SO[/"section_outliner<br/><i>段落割り当てを JSON で決める</i>"/]
            PN[/"paragraph_narrator<br/><i>1 段落の Markdown を書く</i>"/]
            SAP --> SAC --> SO --> PN
        end
        RES --> RW
        RW -->|新規 gap| BP
    end

    HL --> T[("Trace State<br/>(trace.duckdb)<br/>steps / reasoning / progress")]
    RW --> RS[("report_sections + claims")]

    C -. derive .-> M[("Structured Memory<br/>(memory/*.md)")]
    T -. derive .-> M
    M -. context .-> QI
    M -. context .-> VR
    M -. context .-> SAP
```

各ロールの責務と境界は次のルールで保ってください。

- **1 ロール = 1 文で書ける目的**。`<TASK>You are a sql_composer. Write a DuckDB SQL query that satisfies the given intent.</TASK>` のように、ビルダー冒頭が複文になったら粒度が崩れているサイン。
- **ルーティング・テンプレマッチング・整形は LLM に渡さない**。`validate_select_sql` / `HypothesisProgressTracker` / `_dedup_new_hypotheses` / `format_benchmark_answer` / `execute_fallback_search` はすべてコード側で決定論的に動きます。
- **durable な結論はすべて DuckDB**。LLM の生出力は `ai_logs/<session_id>/` と `trace.investigation_steps` に audit ログとして残しますが、これは正本ではありません。findings / hypotheses / claims / report_sections は必ず DB に永続化し、memory Markdown はそれらからの projection に留めます。
- **仮説単位の文脈隔離**。検証中の暫定 facts / timeline / tasks は `memory/scratch/<hypothesis_id>/` に閉じ込め、confirmed 時に共有記憶へ昇格、refuted 時に archive へ退避します。他仮説の暫定情報を流入させないこと。
- **トークン予算は hard cap、LLM 呼び出し総数は opt-in cap**。`_assemble_messages_with_budget` が system プロンプトを保護したまま user/dynamic 側のみ trim。`audit.LLMCallLogger` の総数 cap は `--max-llm-calls`(既定 `0` = 無制限。ローカル LLM 前提のため)。クラウド API に切り替えるときは明示的に `--max-llm-calls 500` 等を渡してコスト暴走を防ぐこと。指定されたら超過時に soft warning ではなく `RuntimeError` でループ終了。

新しい AI 駆動の振る舞いを追加するときは「これを 1 文の `<TASK>` で書けるか」「コード側で表せないか」を先に問い、答えが No / Yes ならルール宣言ノブ(`confirm_when` / `fallback_search` / `follow_up_questions` 等)で表現できないかを確認してください。Python に rule_id や event_id のハードコード分岐を増やす前に、必ず宣言層 (`src/forensia/rulepacks/_schema/`) を検討すること。

## 開発環境

### Python

```bash
git clone https://github.com/sumeshi/forensia
cd forensia
uv sync
```

`.env` の例:

```dotenv
LLM_BASE_URL="http://127.0.0.1:1234"
LLM_MODEL="qwen/qwen3-8b"
LLM_MAX_TOKENS=4096
LLM_THINKING_LANGUAGE=en
LLM_OUTPUT_LANGUAGE=ja
LLM_MEMORY_MAX_BYTES=16384
```

| 変数 | 意味 |
|---|---|
| `LLM_BASE_URL` | LLM API のベース URL |
| `LLM_MODEL` | 仮説検証・レポート生成で使うモデル名 |
| `LLM_MAX_TOKENS` | 1 リクエストあたりの最大トークン数 |
| `LLM_THINKING_LANGUAGE` | 思考プロンプトの言語 |
| `LLM_OUTPUT_LANGUAGE` | 人間向け出力の言語 |
| `LLM_MEMORY_MAX_BYTES` | 記憶ファイルの圧縮トリガとなるしきい値 |
| `LLM_REASONING_RESERVE_TOKENS` | 推論モデル向けの追加トークンバッファ (思考モデル用) |
| `FORENSIA_API_BASE_URL` | UI 開発時の API ベース URL |
| `FORENSIA_UI_ORIGINS` | FastAPI の CORS 許可リスト(カンマ区切り) |

CLI で base URL を指定する場合は `--llm-base-url`。

### Web UI

```bash
cd web_ui
npx pnpm install
```

### よく使うコマンド

```bash
# バックエンドテスト
UV_CACHE_DIR=/tmp/uv-cache PYTHONPATH=src uv run python -m unittest discover -s tests

# フロントエンド
cd web_ui
npx svelte-check
npx pnpm test
npx pnpm build

# ローカル実行
forensia run ./sample/DESKTOP-001 --out ./dist/DESKTOP-001 --profile windows-basic --max-iter 20
forensia status ./dist/DESKTOP-001
forensia serve ./dist/DESKTOP-001
```

## リポジトリ構成

| レイヤー | 主な場所 | 責務 |
|---|---|---|
| Ingest | `src/forensia/ingest/` | アーティファクトを正規化前 JSONL に変換 |
| Normalize | `src/forensia/normalize/` | JSONL を DuckDB に取り込み |
| Rules | `src/forensia/rules/` + `src/forensia/rulepacks/` | YAML ルール実行と finding 生成 |
| Investigation | `src/forensia/ai/investigator.py` | 仮説検証ループのオーケストレーション |
| Planner / Checker | `src/forensia/ai/planner.py` / `checker.py` | SQL 計画と結果評価 |
| Memory | `src/forensia/core/memory.py` | 構造化作業記憶の管理 |
| Report | `src/forensia/report/` | レポートセクションの充填と書き出し |
| API | `src/forensia/api/` + `src/forensia/web.py` | FastAPI / DTO / SSE |
| UI | `web_ui/` | Svelte 5 UI |

### CLI

| コマンド | 役割 |
|---|---|
| `init` | 空のケースディレクトリを作成 |
| `add` | 既存ケースに追加アーティファクトを取り込み |
| `report` | 既存 `report_sections` から Markdown / HTML を書き出し |
| `report-write` | 現在の証拠からレポートセクションを再充填してから書き出し |
| `run` | ingest → normalize → analyze → investigate → report の一連を実行 |
| `investigate` | 既存ケースで仮説ループを継続 |
| `status` | ケース状態を読み取り専用で表示 |
| `serve` | FastAPI と Svelte UI を提供 |
| `doctor` | schema coverage / playbook drift / verdict taxonomy AST / pytest をまとめて実行 |

### ケースのレイアウト

```text
case001/
  manifest.yaml
  allowlist.yaml
  raw/
  db/
    case.duckdb
    trace.duckdb
  findings/
  report_template/
  ai_logs/
  memory/
    overview.md
    facts.md
    timeline.md
    tasks.md
    archive/
      refuted.md
      resolved_gaps.md
      timeline_archive.md
      scratch/
        H-001/
    scratch/
      global/
      H-002/
    entities/
      user/
      host/
      ip/
    hypotheses/
    keypoints/
    evidence/
      suspicious.md
    details/
      fact-001.md
  reports/
    report.html
    report.md
    api/
```

| パス | 責務 |
|---|---|
| `raw/` | 再処理可能な正規化前 JSONL |
| `db/case.duckdb` | 証拠とそれに紐づく永続調査結果 |
| `db/trace.duckdb` | セッション / ステップ / 進捗履歴 |
| `allowlist.yaml` | rule_id ベースの suppression 設定 |
| `memory/` | LLM 向けの再生成可能な作業文脈 |
| `ai_logs/` | LLM リクエスト / レスポンスの監査ログ |
| `reports/` | レポート出力と API スナップショット |

## 状態の 3 層分離

forensia は信頼度と寿命が異なる 3 種の状態を分離して扱います。

| 種類 | 場所 | 役割 |
|---|---|---|
| Case State | `db/case.duckdb` | 取り込んだアーティファクトを正規化した証拠と、それから導かれる永続調査オブジェクト。原則 immutable。 |
| Trace State | `db/trace.duckdb` | 調査セッションのライフサイクル、ステップ I/O、進捗履歴。原則 append-only。 |
| Structured Memory | `memory/**/*.md` | Case と Trace から LLM 向けに再構成した文脈。regeneratable。 |

これらの境界は壊さないこと。

- Case State は「ケースが現状何を含んでいるか」を答える正本。
- Trace State は「どうやって現在状態に達したか」を答える正本。
- Memory は **projection** であり、authority ではない。

## アーキテクチャ不変条件

### LLM 出力は正本ではない

実装は LLM の活動を記録しますが、生の出力を永続状態としては扱いません。

- LLM のリクエスト / レスポンスは `ai_logs/<session_id>/` に保存。
- 各ステップの `input_json` / `output_json` は `trace.investigation_steps` に保存。
- findings / hypotheses / claims / report_sections は DuckDB に永続化。
- Memory Markdown は derived state であり、再生成可能。

新機能が永続状態を要するなら、Markdown やログだけでなく DuckDB のテーブルに表現すること。

### 証拠への traceability を保つ

durable な結論は evidence_id まで辿れること。

- 証拠テーブルは正規化された原本レコードを持つ。
- findings は構造化された evidence 参照を持つ。
- memory の facts / timeline には evidence 参照を含める。
- claims は `finding_ids` / `hypothesis_ids` / `evidence_ids` をリンクとして持つ。

新たに証拠を要約・ランキングする抽象を追加するときは、必ず元証拠への参照経路を保つこと。

### verdict 値は列挙であり自由文字列ではない

verdict 文字列は許可リストです。許可値は `src/forensia/rulepacks/_schema/verdict_taxonomy.yaml` で宣言され、3 箇所の書き込み境界で `forensia.core.verdicts.assert_valid_verdict` により強制されます。

| レイヤー | 強制サイト |
|---|---|
| `hypothesis_verdict` | `hypothesis_manager.py:_upsert_hypothesis()` + `Hypothesis.verdict` field validator |
| `section_verdict` | `section_agent.py:_store_section_run()`(`sufficient`/`refuted` 等のエイリアスは normalize map で吸収) |
| `benchmark_status` | `report/writer.py:_normalize_benchmark_answer()` |

`HistoryEntry.verdict` にも Pydantic `@field_validator`。新しい verdict 値を増やすなら `verdict_taxonomy.yaml` を編集すること。validator を Python から回避するのはバグ扱い。

taxonomy ファイルは層間マッピング (`hypothesis_to_section`、`section_to_benchmark`、`benchmark_to_claim`) も宣言しているので、層間変換が必要なら `map_verdict()` を呼び、独自テーブルを作らないこと。

### LLM 呼び出し総数は hard cap

`audit.LLMCallLogger` がすべての呼び出しを記録します。`investigator.investigate(max_llm_calls=...)`(CLI: `--max-llm-calls`)は **opt-in の hard cap** で、既定値は `0`(無制限)。ローカル LLM ではコスト懸念がないため既定では無効です。クラウド API 利用時は明示的に正の値を指定すること(超過で `RuntimeError`、soft warning ではなくループ終了)。phase 別の集計は `LLMCallLogger.count_by_phase()` で取れます。

プロンプト組み立てには別途トークン予算ガードがあります。`_assemble_messages_with_budget()` は system メッセージを保護したまま、user / dynamic 側の content を先に trim します。これを迂回して system に直接連結しないこと。

## 仮説検証ループの内部

### 1 サイクル (`plan_cycle`) の流れ

```
broad_plan → for each active hypothesis: plan → exec(+fallback) → check → track → resolve → refresh_report(stale-first) → inject_gaps_as_new_hypotheses
```

- `plan_cycle` は `--max-iter` で上限。
- 仮説あたりのクエリ試行は `--max-queries-per-hypothesis` で上限。
- レポート再充填は `--report-every-n-cycles` ごとに走る。

### 仮説の入り口

`state.active_hypotheses` に入る仮説は 3 経路あります。

1. `rule.hypotheses`:ルール発火時にテンプレから生成。`source_rule_ids` が埋まる。
2. `gap_identifier` + `hypothesis_drafter`:gap 領域から起案。`source_rule_ids` は空。
3. `follow_up_questions`:confirmed になった `source_rule_ids` 付き仮説から自動派生。

レポート writer から出る gap 仮説は `_inject_gap_hypotheses` を通り、`GapHypothesisOutput` の Pydantic バリデーションで形を整え、LLM が `required_entities` / `confirm_when` を落とした場合はヒューリスティックなセーフティネットで補完します。

### LLM 役割分割の地図

`prompts.py` で定義されているプロンプトビルダーと役割の対応:

| Phase | ビルダー | 目的 |
|---|---|---|
| broad_plan | `build_gap_identifier_messages` | 観測 keypoint と未カバー keypoint から gap_areas を特定 |
| broad_plan | `build_hypothesis_drafter_messages` | 1 gap_area につき 1 仮説を起案 |
| plan | `build_query_intent_messages` | 何を取りに行くかを JSON で表現 |
| plan | `build_sql_composer_messages` | intent と schema_card から SELECT を組む |
| check | `build_verdict_review_messages` | rows と仮説から verdict を出す(3 フィールドのみ) |
| check | `build_finding_extractor_messages` | verdict==confirmed のときだけ findings を抽出 |
| check | `build_memory_updater_messages` | verdict 確定後に durable memory updates を提案 |
| section_agent | `build_section_agent_plan_messages` | 次のアクション(query / facts / write)を選択 |
| section_agent | `build_section_agent_check_messages` | 集めた証拠が write 可能か判断 |
| section_write | `build_section_outline_messages` | 段落割り当てを JSON で決める |
| section_write | `build_paragraph_narrate_messages` | 1 段落の Markdown を書く |
| benchmark | `build_benchmark_classify_messages` | status と採用 row を選ぶ(整形は code 側) |

LLM が「ルーティング」「テンプレマッチング」「決定論的フォーマット整形」を兼ねないよう、ビルダーの粒度を保ってください。新ロールを足すときは `<TASK>` を 1 文で書けるか確認すること。

### Planner

`build_query_intent_messages` → `build_sql_composer_messages` の 2 段呼びです。

- **schema cards** (`<SCHEMA_CARDS>`):`rulepacks/_schema/*.yaml` の `core_columns`(planner に見せる短いリスト、5〜13 列)+ `column_descriptions`(1 行説明)+ `columns`(SQL validator 用フルリスト)。surface するテーブルは `evtx_events` / `mft_entries` / `mft_timeline` / `prefetch_executions` / `findings`。
- **SQL クックブック** (`<SQL_COOKBOOK>`):event_id 列挙 / 時間範囲 / GROUP BY / COALESCE / MFT path LIKE / Prefetch という 6 種の SELECT テンプレ。弱い LLM はゼロから合成せず、これをコピー編集することを想定。
- **SQL リトライ**:`validate_select_sql` で弾かれたら `_retry_query_once` が最大 `_PLANNER_SQL_MAX_RETRIES = 3` 回まで `sql_composer` のみを再呼び出し。intent 段階は再実行しない。
- **フォールバック**:リトライしても valid SQL にならなければ、`_fallback_planned_query_from_hypothesis` が `hypothesis.confirm_when.co_observed_event_ids` から `SELECT … FROM evtx_events WHERE event_id IN (…) ORDER BY timestamp LIMIT 500` を deterministic に生成。check フェーズは必ず走る。

### Executor とフォールバック

executor は計画された SQL を実行します。0 行で、かつ仮説に `source_rule_ids` + `fallback_search` 宣言があれば、宣言順にフォールバックフェーズを試行します。fallback SQL は `engine.execute_fallback_search` がコードで組み、LLM は介在しません。

フォールバックがヒットしたら `fallback_info = {phase, source_rule_id}` を checker プロンプトに渡し、verdict にフォールバック由来であることを反映させます。

### Checker

`build_verdict_review_messages` が verdict / rationale / confidence の 3 フィールドのみ返します。default 基準は相関ベース:

- `confirmed`:`required_entities` が同じ rows で共起。
- `refuted`:0 行または矛盾 entity。
- `inconclusive`:一部の required_entities のみ観測 → rationale で欠落 entity を名指しすること。

「直接的因果は証明されていない」「さらなる調査が必要」のような名指しなしの hedge は禁止語として明示。

verdict==confirmed のときだけ `build_finding_extractor_messages` が呼ばれ、structured findings を抽出。`build_memory_updater_messages` は verdict 確定後に durable memory updates を提案します。

### Progress Tracker

`HypothesisProgressTracker` は仮説単位の dataclass で、各クエリの `(query_fingerprint, verdict, row_count)` を記録。check のたびに次の決定論的判定を行います。

| メソッド | 条件 | 効果 |
|---|---|---|
| `should_auto_confirm(rule_context, rows, hypothesis)` | `confirm_when.co_observed_event_ids` の 50% 以上が rows に存在。rule_context にあれば優先、なければ hypothesis 自身から取得。 | LLM verdict を無視して confirmed に強制 |
| `should_auto_refute(threshold=3)` | 3 連続 0-row inconclusive(かつ partial 信号なし) | refuted に強制 |
| `should_pivot(fp)` | 同じ query fingerprint が 2 回以上出現 | planner に pivot 指示 |
| `_investigate_one_hypothesis` short-circuit | 初回 plan で SQL / template / `confirm_when` フォールバックのいずれも組めない | 即 refuted (`no executable evidence path`) |

`query_fingerprint` は sqlglot AST を canonicalize して event_id / computer マーカーと合わせてハッシュ化したものです。空白や別名違いを吸収します。sqlglot 不在時は文字列正規化に fallback。

`_merge_active_hypotheses` は `MAX_ACTIVE_HYPOTHESES = 8` を強制。既存仮説の更新はカウント対象外で、上限超過分の新規だけが drop されます(`[CAP]` ログ)。

### 仮説 dedup

仮説の同一性判定はコード側で完結します(LLM 同一性判定 `_ask_same_hypothesis` は撤去済み)。

- `_hypothesis_similarity` (`hypothesis_manager.py`):triple (actor / action / target) ベースの類似度。
- `_dedup_new_hypotheses` (`investigator.py`):drafter 出力後、active との類似度 > 0.85 で drop。
- `_best_hypothesis_match` (`hypothesis_manager.py`):`_merge_active_hypotheses` 内で同一の閾値判定により upsert 先を決める。

### Resolver

仮説が確定すると `_resolve_hypothesis` が次を行います。

1. `state.resolved_hypotheses` に移動し、DB の `status` を `confirmed` / `refuted` に upsert。
2. 各 `source_rule_id` についてキャッシュされた `load_rule_by_id` でルールを引き、id 一致する `HypothesisDeclaration` を探す。
3. 宣言から:
   - `stale_sections` に `decl.report_sections` を追加。
   - confirmed のときは `decl.follow_up_questions` を新たな active 仮説に追加(description で dedup)。
4. 該当 section について `UPDATE report_sections SET stale = TRUE WHERE section_key = ?` を発行。

### Termination

サイクルが終了する条件は次のいずれか。

- すべての active 仮説が解決し、broad_plan が `stop` を出し、レポート gap が空。
- 3 サイクル連続で進捗なし (`--no-progress-limit`)。
- `--max-iter` サイクル完了。

「進捗なし」は仮説解決も新規 gap 仮説追加もレポート status カウンタ変動もないサイクルを指します。

### ルール経由で挙動を変えるノブ

| ノブ | 宣言場所 | 効果 |
|---|---|---|
| `correlate_with` | rule | planner プロンプトに「これらの event id も見ろ」ヒント |
| `confirm_when.co_observed_event_ids` | `hypotheses[]` | tracker の auto-confirm 基準 |
| `refute_when.zero_rows` | `hypotheses[]` | checker のデフォルト refutation |
| `fallback_search` | rule | LLM 不在の 0-row リカバリ |
| `follow_up_questions` | `hypotheses[]` | confirmed 時に次の調査を自動派生 |
| `report_sections` | `hypotheses[]` | 解決時に stale 化するセクション |

新しい agent 挙動を追加するときは「これはルール宣言ノブで表せないか?」を最初に問うこと。Python 側で rule_id や event_id に分岐するコードは避ける。

## プロンプトの組み立て

LLM 入力は固定文字列ではなく、フェーズと文脈に応じて段階的に組み立てます。

1. **DFIR プレイブック注入(phase-aware)**:`_dfir_playbook(phase)` が `_schema/playbook/<phase>.md` を読む。planning 系(`broad_plan`、`hypothesis_plan`)では Application Catalog / Artifact-to-Application Inference / FP Reduction を意図的に省略(これらは evidence 解釈用)。interpretation 系(`check`、`report_section`、`section_agent_check`)では全部入り。
2. **schema_card + SQL クックブック注入**:planner / checker に 5 テーブル分の `<SCHEMA_CARDS>` と 6 種の `<SQL_COOKBOOK>` を渡し、ゼロから SQL を書かせない。
3. **動的コンテキスト**:case の `time_range`、`uncovered_keypoints`、active / resolved hypotheses、recent history、observed_keypoints を役割ごとの builder で挿入。hypothesis は `_slim_hypothesis_dump` で null / 空フィールドを落として serialize、findings は `_slim_findings` が同一 rule パターンを `count` 付き 1 行に集約。
4. **report_brief のセクション別スリム化**:`_slim_report_brief_for_section` がセクション key を見て、`1_overview` 以外は `time_range` / `source_timezone` / `investigation_objective` のみに削る。top_findings や全仮説の丸ごとダンプは行わない。
5. **トークン予算ガード**:`_assemble_messages_with_budget()` が system を保護したまま user / dynamic 側のみ trim する。

### セクション間汚染の防止

レポート生成時の文脈隔離は次のルールで担保しています。

- `_summarize_context_sections`:過去セクション本文は **タイトル + 先頭 120 字** のみで渡す。フル本文は流さない。
- `current_section_outline`:同一セクション内の先行ブロックは **見出し + 120 字サマリの list** で渡す(本文は渡さない)。
- `_filter_prior_runs_by_heading`:現在の block_heading に一致する prior_runs のみを採用。fallback で「直近の別 heading」を流入させない。
- `_load_reusable_section_evidence` / `_load_reusable_section_facts`:`section_key = ?` 完全一致のみで scope。`block_heading` での横断マッチや family LIKE はしない。

## 構造化記憶モデル

構造化記憶は会話履歴ではなく、繰り返し LLM 呼び出し向けに最適化された bounded な作業集合です。

### 記憶ファイル一覧

| パス | 役割 | 寿命 |
|---|---|---|
| `memory/overview.md` | ケース全体の高水準サマリと方針 | regeneratable、LLM 圧縮あり |
| `memory/tasks.md` | アクティブな未解決タスク / gap | regeneratable、ローカル圧縮 |
| `memory/facts.md` | 文脈に乗せるべき確認済み事実 | regeneratable、generic 圧縮対象外 |
| `memory/timeline.md` | アクティブ推論用の重要時刻 | 長くなったら archive へローテーション |
| `memory/entities/{user,host,ip}/*.md` | 重要 entity のカード | LLM 圧縮あり |
| `memory/hypotheses/*.md` | 仮説ごとの状態カード | LLM 圧縮あり |
| `memory/keypoints/*.md` | 現在の findings snapshot から同期される注目点カード | regeneratable |
| `memory/evidence/suspicious.md` | check 中に LLM が指定した不審証拠の表 | ローカル圧縮 |
| `memory/details/fact-NNN.md` | facts.md の索引項目に対応する詳細本文 | regeneratable |
| `memory/archive/*.md` | アーカイブ済みの履歴フラグメント | regeneratable |
| `memory/scratch/H-NNN/*.md` | 仮説検証中の暫定 facts / timeline / tasks | confirm 時に共有記憶へ昇格、refute 時に archive へ退避 |
| `memory/scratch/global/*.md` | 仮説に紐づかない暫定メモ | regeneratable |
| `memory/archive/scratch/H-NNN/` | refuted 仮説の scratch | アーカイブ後は read-only |

### 更新ルール

記憶更新は append-only または upsert スタイルです。

- facts は正規化テキスト + evidence_ids で dedup して追加。
- `facts.md` に書かれた事実は索引化され、`memory/details/fact-NNN.md` として本文展開される。
- timeline anchor は追加され、活性リストが長くなれば `archive/timeline_archive.md` にローテーション。
- tasks は `internal_db_check` / `external_lookup` / `human_decision` のいずれかの種別で追加。
- refuted 仮説と resolved gap は削除せず archive。
- entity カードと hypothesis カードは安定 id で upsert。
- keypoint カードは findings snapshot と同期され、stale なものは削除。

### 圧縮ポリシー

durable state を壊さずに文脈を小さく保つことが目的です。

- `overview.md`:`LLM_MEMORY_MAX_BYTES` 超過時に LLM で要約圧縮。
- entity カード / hypothesis カード:LLM 圧縮。
- `tasks.md` / `evidence/suspicious.md`:古い行を trim。
- `facts.md` / `timeline.md` / `archive/refuted.md` / `archive/resolved_gaps.md`:generic ローカル圧縮の対象外。

これらは挙動が違うので、1 つのファイルの挙動を全 memory に一般化しないこと。

### 仮説単位の scratch ライフサイクル

`_apply_memory_updates` は `hypothesis_id` と `verdict` を見て書き込み先を振り分けます。

- 仮説が active な間、暫定 facts / timeline / tasks は `memory/scratch/<hypothesis_id>/` に隔離。
- `confirmed` の瞬間に `MemoryManager.promote_hypothesis_scratch(hypothesis_id)` が共有記憶へマージし、scratch ディレクトリを削除。
- `refuted` の瞬間に `MemoryManager.archive_hypothesis_scratch(hypothesis_id)` が `archive/scratch/<hypothesis_id>/` に移送。
- Investigation context loader は `include_scratch=True` + 対象 `hypothesis_id` をサポートし、現在検証中の仮説の scratch だけを LLM に戻す。他仮説の暫定情報は流入しない。

仮説起源の memory write には必ず `hypothesis_id` を持たせること。`hypothesis_id` を落とすヘルパは共有記憶に無条件書き込みしてしまい、このライフサイクルを壊します。

### benchmark 向けの限定ビュー (`EvidenceOnlyMemory`)

benchmark / appendix ブロックが仮説ループで作られた narrative memory(`H-NNN.md`、ラテラルムーブメント要約など)を見ると、既に形成された結論にブロック回答が引き寄せられます。`core.memory.EvidenceOnlyMemory` は wrapper として `facts` / `keypoints` / `entities` のみを露出し、それ以外を隠します。

切り替えは `core.memory.memory_for_section(memory, benchmark_mode=...)` の 1 箇所で行います。`section_refresher.py` / `report/writer.py` の section 充填経路は **必ず** このヘルパ経由で呼ぶこと。`grep EvidenceOnlyMemory(` で出るのはヘルパ本体のみであるべきです。

### 記憶は再構成可能であること

構造化記憶は DB と先行する evidence-backed 出力からの projection に留めます。

- 排他的なビジネスロジックを memory Markdown だけに置かない。
- 直近のプロンプト文脈からしか復元できない状態を作らない。
- ファイル名と索引項目には安定 id を使う。
- 明示的に要約されたファイル(`overview.md` など)を除き、追記履歴を in-place な書き換えより優先する。

## DuckDB のテーブル

### `case.duckdb`(Case State)

| テーブル | 責務 |
|---|---|
| `evtx_events` | 正規化された EVTX レコード |
| `mft_entries` | 正規化された MFT エントリ |
| `mft_timeline` | MFT タイムスタンプから派生したタイムライン行 |
| `findings` | 証拠に紐づいた findings とレビュー用メタデータ |
| `hypotheses` | 仮説レジストリと現在のステータス |
| `report_sections` | レポート本文 / confidence / status / gaps / 充填履歴 |
| `claims` | レポート記述と finding / hypothesis / evidence のリンク |
| `ingested_files` | 取り込み済みファイルの hash 帳簿 |

### `trace.duckdb`(Trace State)

| テーブル | 責務 |
|---|---|
| `trace.ai_reviews` | findings に紐づいた AI レビュー出力 |
| `trace.investigation_sessions` | 調査セッションの境界と終了 status |
| `trace.investigation_steps` | planner / checker のステップ I/O |
| `trace.hypothesis_reasoning` | 仮説単位の推論履歴 |
| `trace.progress_events` | UI 向け進捗イベント |

実行時に `trace.duckdb` は `trace` スキーマとしてアタッチされ、trace テーブルは一時 view 経由でも参照できます。読み取りは統一論理スキーマでありながら物理的には Case / Trace が分かれます。

### 分離を崩さない

- trace テーブルを durable な case オブジェクトの代わりにしない。
- 証拠に紐づく case 結論を trace 履歴だけに置かない。

圧縮、リプレイ、UI リフレッシュ後にも必要な情報は `case.duckdb` に置くこと。

## 概念モデルの境界

| 用語 | 意味 |
|---|---|
| Evidence | EVTX / MFT 行のような正規化済み生レコード |
| Finding | 証拠から導かれた観測条件・信号 |
| Hypothesis | 検証・反証する解釈 |
| Claim | レポートで読者に提示する記述 |
| Gap | confidence を阻む未知 |

これらの境界を混ぜると推論の監査と安全な再開が困難になります。Evidence と Finding は証拠近傍、Hypothesis は解釈、Claim はレポート向け、Gap は未知。

### Finding ライフサイクル

`suppressed` は削除ではありません。

- suppressed な finding は durable なケース記録の一部として残る。
- suppression は表示とワークフロー意味論を変えるだけで、証拠の存在は変えない。
- finding が suppressed でも evidence リンクは残す。

## レポートセクションの状態

`report_sections.status` は 4 値:

- `draft`:証拠 gap がある / 弱い support
- `stable`:AI ワークフロー上で既知の gap なし
- `ai_exhausted`:AI ワークフローがこれ以上の有意な手がかりを生成しなくなった
- `human_reviewed`:人間が明示的にレビュー済み

これらは workflow state であり、evidence state ではありません。

## レポート品質ゲート

各セクション本文充填後、`_quality_gate_section`(`report/writer.py`)が静的チェックを走らせ、検出ごとに gap を追加して confidence を上限値まで下げます。検査はテンプレ非依存で全セクションに適用されます。

セクション固有の挙動は `behaviors:` frontmatter で宣言します。例: `require_chronological_table` / `require_recommendations_strength` / `canonical_evidence_scope`。`_GateCtx.behaviors` を見て発火条件を分岐します。section_key を Python 側でハードコードしないこと。

現在の検査:

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
| Citation token without finding_id | `evidence` / `根拠` 等を含むのに finding_id がない | 0.6 |
| Duplicate paragraph | 長さ 40 以上の同一段落が 2 つ | 0.5 |
| Out-of-range timestamp | 本文の `YYYY-MM-DD` が今日 + 1 を超えるか 1990 未満 | 0.4 |
| Overused evidence id | 同一 evidence_id が 3 以上のセクションで引用 | 0.7 |

gap notes は `report_sections.gaps` に積まれ、次サイクルでは追加仮説として扱われます。新規ゲートを追加するときは 1 関数 + 1 note 文字列に閉じ込め、テンプレ固有ロジックを書かないこと。

## レポートテンプレート契約

テンプレートはコントリビュータが定義する section の契約であり、durable なレポート状態ではありません。

### 所有境界

- テンプレートファイルは `src/forensia/report_template/` 配下。
- 初期化済みケースには case-local の `report_template/` がパッケージ既定からコピーされる。
- CLI のレポート生成は case-local テンプレが存在するときはそれを優先。
- `report-write --template-dir` で明示的に外部テンプレを指定可能。

テンプレートは入力であり、生成されたセクション本文は `report_sections` に永続化されます。

### Frontmatter フィールド

各テンプレートはオプションの YAML frontmatter を持つ Markdown ファイルです。

| フィールド | 役割 |
|---|---|
| `section` | 安定した section key |
| `title` | 人間向けセクションタイトル |
| `prompt` | LLM へのセクション別執筆指示 |
| `evidence_queries` | 読み取り専用 SQL。結果が要約されて LLM に渡る |
| `behaviors` | quality gate / 振る舞いフラグの list(例: `require_chronological_table`) |

`behaviors` を増やしたいときは writer.py 側の `_GateCtx.behaviors` 判定を 1 箇所だけ伸ばし、section_key にハードコードしないこと。

### Section の同一性と順序

- ファイル名パターン `[0-9]*_*.md` でテンプレを発見。
- 再充填順はファイル名の lexical 順。
- durable な `section_key` は frontmatter `section` を優先し、無ければファイル stem。
- レポート出力は `section_key` で並び替え。

section key は **stable な識別子** として扱うこと。ファイル名のリネームより key 変更のほうが影響が大きい。

### テンプレートで宣言すること / しないこと

宣言する:

- レポート構造
- セクション固有の執筆要求
- `evidence_queries` 経由の証拠アクセス要求
- 証拠不十分時のプレースホルダ

宣言しない:

- durable なワークフロー状態
- mutable なレポート status
- provenance 保存ルール
- セクション本文の正本(これは `report_sections` テーブル)

テンプレ著作は英語で揃えること。frontmatter (`title`、`prompt`)、scaffold の見出し、表頭、コメント、プレースホルダはすべて英語。出力言語は runtime の `LLM_OUTPUT_LANGUAGE` で制御されます。

### DB 連携

- 充填済みセクション本文は `report_sections` に UPSERT。
- confidence は本文の gap マーカーから導出。
- claims は本文から抽出して `claims` に書き込み。
- claim の provenance は evidence_query summary から計算(自由文の引用テキストだけに頼らない)。
- gap は明示的な insufficient-evidence マーカーから parse され、次サイクルの仮説に投入。

### 内蔵テンプレートと評価用テンプレートの分離

| 場所 | 用途 |
|---|---|
| `src/forensia/report_template/` | パッケージ同梱の汎用インシデントレポート。`forensia init` で各ケースに `report_template/` としてコピーされる。 |
| `./templates/` (リポジトリルート) | このソフトウェアの推論精度を計測するためのベンチマーク専用テンプレート。BENCHMARK.md / BENCHMARK-ANSWERS.md と対応し、6_appendix で 12 個の Scored Question を block として展開する。 |

ベンチマーク評価時は `forensia run ... --template-dir ./templates` で指定して使う。ベンチマーク以外の通常運用ではこの templates/ は使わない。

## SQL 安全性

LLM が出した SQL は読み取り専用の証拠アクセスとして扱います。

- `SELECT` と `WITH` のみ許可。
- 複文は拒否。
- 破壊的 SQL は拒否。
- テーブルは allowlist で制限。

この境界は現行アーキテクチャの根幹です。LLM は証拠アクセスを「提案」できても、生成 SQL で DB を mutate することはできません。

## 宣言層 (`_schema/`)

`src/forensia/rulepacks/_schema/` はルールディレクトリではなく、ルールとプロンプトが共有するスキーマと DFIR 知識を置く場所です。ローダは enumerate 時にスキップします。

| ファイル | 消費側 | 役割 |
|---|---|---|
| `evtx_events.yaml` / `mft_entries.yaml` / `mft_timeline.yaml` / `prefetch_executions.yaml` / `findings.yaml` | `prompts._build_schema_guidance()` 経由 `_load_schema_hints()` | DB テーブルの schema card。`core_columns`(planner 向け短いサブセット)+ `column_descriptions`(1 行説明)+ `columns`(SQL validator 用)+ `json_field_extractors`(raw_json fallback)。5 テーブル分が `<SCHEMA_CARDS>` として一括注入される。 |
| `event_ids.yaml` / `logon_types.yaml` | `prompts._dfir_playbook()` | Event ID / Logon Type の DFIR 解説。 |
| `app_catalog.yaml` / `artifact_inference.yaml` | `prompts._dfir_playbook()` | Prefetch / MFT / Registry / File → アプリ推定。planning 系では意図的に省略、interpretation 系のみに注入。 |
| `false_positive_rules.yaml` | rule engine + `prompts._dfir_playbook()` | 既知 FP。interpretation 系プロンプトのみで参照。 |
| `dfir_ioc_catalog.yaml` | `prompts._dfir_playbook()` | アンチフォレンジック / クラウド同期 / メール / Recycle Bin 等の補助 IOC 辞書。 |
| `question_routing.yaml` | `section_agent.py` + `prompts.build_section_agent_*` + `prompts.build_benchmark_classify_messages` | question_type ごとの `expected_answer_shape`(コード側 `format_benchmark_answer` が消費)と `evidence_chain`(primary 0-row 時に `_execute_evidence_chain` が決定論的に試行)。 |
| `verdict_taxonomy.yaml` | `core/verdicts.py` | verdict 値の whitelist と層間マッピング。 |
| `playbook/*.md` | `prompts._dfir_playbook(phase)` | フェーズ別 (`broad_plan` / `hypothesis_plan` / `check` / `report_section` / `section_agent_plan` / `section_agent_check`) のプレイブック本文。`<CRITICAL_RULES>` / `<FORBIDDEN_PATTERNS>` / `<SCHEMA_CONSTRAINTS>` 等のタグ付き。 |

DB テーブル schema YAML は次を宣言すること。

- `table`:テーブル名(例: `evtx_events`)。
- `core_columns`:planner LLM が見る短いリスト。13 以下に保つ。
- `column_descriptions`:各 `core_columns` に対する 1 行説明。
- `columns`:全列リスト(`validate_select_sql` が undeclared 列の SELECT / WHERE を弾くのに使う)。
- `json_field_extractors`(任意):列が NULL のときに raw_json から拾う DuckDB JSON 抽出式。
- `notes`(任意):timestomp 注意点や Prefetch の `no_host_column` 等のヒント。

新しい investigable テーブルを追加するなら `_schema/<table>.yaml` を置き、`sql_schema.py` の `ALLOWED_TABLES` を更新します。YAML は `_load_schema_hints()` で自動消費されます。

`playbook/*.md` は `<!-- AUTO-FROM: <yaml-path> -->` ... `<!-- /AUTO-FROM -->` マーカー内を `scripts/regenerate_playbook.py` が再生成します。マーカー内は手編集せず、ソース YAML を編集して再生成すること。

### Allowlist

`kind: allowlist_services` のように `kind:` プレフィックスを持つファイルはルールではなく、ローダがスキップします。suppression ロジックが消費します(「Allowlist と suppression」節)。

## ルールパック / プロファイル契約

### Rulepack

ルールパックは `src/forensia/rulepacks/windows/`(または類似)配下の YAML 定義です。`src/forensia/rules/models.py` の Pydantic モデルが `extra="forbid"` でスキーマ強制するため、未知フィールドはロード時に弾かれます。

#### 検出部(必須)

- `id`:安定したルール識別子
- `title`:人間向けタイトル
- `severity`:findings の既定 severity
- `confidence`:findings の既定 confidence
- `query`:正規化済み証拠への読み取り専用 SQL
- `finding.title` / `finding.summary`:行フィールドから render するテンプレ
- `tags`:分類タグ
- `attack`:ATT&CK マッピング

ルールクエリの 1 行が 1 finding になります。元行は構造化 evidence として保存。

#### 投資宣言(任意、仮説ループを駆動)

ルールが LLM 駆動の仮説ループも seed するなら、次を宣言します。Python 側はこれを generic に消費します(kill-chain 知識は Python にハードコードしない)。

- `hypotheses[]`:ルール発火時に instantiate される仮説テンプレ。各エントリには:
  - `id`:ルール内安定 id
  - `segment`:kill-chain segment(`persistence`、`lateral-movement` 等)
  - `description`:`{field}` プレースホルダ付き仮説文(クエリ行カラムにバインドされる)
  - `required_entities`:confirm に必要な entity 名
  - `confirm_when`:`{co_observed_event_ids: [...], same_host: bool, within_minutes: int}` のような相関基準。`HypothesisProgressTracker` が auto-confirm を判定。
  - `refute_when`:`{zero_rows: true}` 等の refutation 基準
  - `follow_up_questions`:confirmed 時に自動 spawn される質問
  - `report_sections`:解決時に stale 化する section キー
- `correlate_with[]`:planner が「これも見ろ」と促される event ID 群。`{event_ids: [...], rationale: str}`。
- `fallback_search[]`:primary SQL 0 行時に宣言順で実行されるフェーズ。LLM 不在。許可フェーズは:
  - `keyword_in_raw_json`(LIKE エスケープ)
  - `related_event_ids`(別 event 表面)
  - `artifact_table`(別の正規化テーブル、`engine.py` で whitelist)

### Profile

プロファイルはルール選択ポリシーです。`src/forensia/profiles/` 配下。

| フィールド | 役割 |
|---|---|
| `name` | プロファイル名 |
| `rulepacks` | rulepack root 配下の対象ディレクトリ / パス |
| `rule_ids` | 任意の特定ルール ID 許可リスト |

プロファイルは選択メタデータです。ルールロジックを複製しないこと。

### 安定であるべきこと

- ルール ID は外部識別子として永続的に扱う。
- プロファイルは「どのルールが active か」を意味し、「どう実行するか」ではない。
- ルールクエリは read-only / 証拠指向のまま保つ。
- finding テンプレは行駆動で、各 finding が evidence traceability を保つ。
- パッケージ同梱のルールメタデータと finding テキストは英語で書く。

選択意味論ではなく実行意味論を変える必要があるなら、それは rule engine の変更であり、profile フォーマットの変更ではありません。

### Allowlist と suppression モデル

`allowlist.yaml` は概念的にルールに隣接しますが、ルールを選択しません。

- プロファイルがどのルールを走らせるかを決める。
- ルールが候補 findings を生成する。
- allowlist が rule_id スコープのフィールドマッチで `suppressed` を決める。

現在のマッチモデルは:

- 1 つの `rule_id`
- `when` 配下の 1 つ以上のフィールド述語
- 値は対象 finding の最初の構造化 evidence 行から取得

これは pre-filter ではなく post-generation な提示・triage コントロールです。

### ファイル配置慣習

- パッケージ既定は `src/forensia/report_template/` / `profiles/` / `rulepacks/` 配下に置く。
- case-local `report_template/` は初期化時にコピーされる override 入力として扱う。
- 現状、profile と rulepack の case-local コピーには依存しないこと(package tree から解決される)。

## テスト方針

テストスイートは秒単位で完了させ続けるため、次のルールを守ること。

- **LLM 呼び出し経路を通るテストを書かない**。`patch("...request_llm_json", ...)` でモックしても、完全な調査サイクル(`investigate(...)`、`run_section_block_agent`、`async_refresh_report_sections` など)は副作用(DuckDB 書き込み、memory I/O、ファイル走査)が多すぎて軽くなりません。
- **実 LLM サーバを叩くテストを書かない**。過去にあった `tests/test_benchmark_e2e_real_llm.py`(`FORENSIA_LLM_BASE_URL` で gate)は同じ理由で削除済み。
- 代わりに次でカバーする:純粋関数ヘルパのユニットテスト(`_slim_findings`、`_quality_gate_section`、`_render_benchmark_answer_markdown` 等)、永続化の DB-only テスト、LLM モジュールを import しない CLI / HTTP テスト。
- 調査ループの挙動を本気で見たいときは、ローカルモデル相手に `forensia investigate ...` を回し、`ai_logs/` を目で確認する。pytest にしない。

## 補助スクリプトと `forensia doctor`

`scripts/` は宣言層 / コード / ドキュメントを揃え続けるためのオフライン監査群です。runtime ではなく、`forensia doctor` がこれらをまとめて実行します。

| スクリプト | 用途 |
|---|---|
| `scripts/audit_schema_coverage.py` | 全ルール YAML の `query` SQL を sqlglot で AST 解析し、参照される `event_id` 値(`=` と `IN`)を抽出。`event_ids.yaml` / `question_routing.yaml` のカバレッジを照合。 |
| `scripts/regenerate_playbook.py` | `_schema/playbook/*.md` の `<!-- AUTO-FROM: ... -->` セクションをソース YAML から再生成。`--check` で drift 検出(exit 1)、引数なしで書き込み。 |
| `scripts/cycle_summary.py <case_dir>` | `progress_events.json` を解析し、cycle ごとの仮説 delta と benchmark 進捗を Markdown 表化。デバッグ補助。 |
| `forensia doctor` | CLI コマンド。schema coverage / playbook drift check / verdict taxonomy AST スキャン / pytest を順に実行し、全部 pass のときだけ exit 0。 |

`scripts/` は Python パッケージではありません。`scripts/` から import するテストは、`conftest.py` がリポジトリ root を `sys.path` に追加していることに依存します。

## UI 周辺

- `forensia serve` がビルド済み UI を FastAPI 経由で配信。
- `web_ui/dist/` は配信用のビルド成果物。
- DuckDB がロック中なら、UI は `reports/api/*.json` スナップショットにフォールバック。

### Cockpit 構成

`web_ui/src/App.svelte` は上から順に:

1. `Header`:ケース名、現在 phase、LLM モデル、最終更新タイムスタンプ。
2. `KpiBar`:Events / Findings / Hypotheses / Open Gaps の 4 KPI。Findings タイルに severity 内訳(High/Medium/Low)、Hypotheses タイルに verdict 内訳(Active/Confirmed/Refuted/Inconclusive)の細い積み棒。`caseStats` + `severityBreakdown` / `verdictBreakdown` ストアから算出。
3. `VolumeTimeline`:Chart.js 複合チャート。既定は全期間 day 解像度。range picker(年→月→日)で絞り込み、1 日を選ぶと hour 解像度に切替。検知 finding は折れ線オーバーレイ。
4. `ReportDraftProgress`:セクション単位の充填状態。
5. `AttackCoverage`:`findings.attack` から tactic × technique マトリックス。
6. `Cockpit`:`AiActivityPanel`、Active Hypotheses(`latestReasoningAt` desc)と Latest Reasoning ストリームをタブ切替する `HypothesisStream`、`OpenGaps`。
7. `TopRules` + `TopEntities`(2 列グリッド)。
8. `DetailsTabs`:findings / steps / sessions / activity / mft の生データタブ。

### Event Volume API 契約

`GET /api/event-volume` は `bucket=year|month|day|hour`、`source=all|detected`、任意の `start` / `end` ISO timestamp を受け付けます。`web.py` の解決順:

1. 全範囲クエリならスナップショットファイル(`reports/api/event_volume_<bucket>_<source>.json`)。
2. ライブ `CaseDB` クエリ。
3. DB ロック中で正確スナップショットが無い場合、より細い snapshot から `aggregate_event_volume` で集計。これで年 / 月 view が day / hour snapshot から再現できます。

`list_event_volume_dto` は year < 1980(Windows epoch 1601 ゴミ)と year > today + 5(NTFS FILETIME overflow、3220 / 30828 等)を除外。`aggregate_event_volume` でも同じフィルタを適用。

### サーバ側 date 健全性

API やレポート writer が raw 証拠からタイムスタンプを受け取る箇所では、1980 ≤ year ≤ today + 5 の健全性レンジを適用すること。レポート writer の quality gate も narrative 中の range 外日付を検出(「レポート品質ゲート」節)。MFT / EVTX タイムスタンプを valid と仮定しない。

### フロントエンドの timestamp 解析

`web_ui/src/lib/format.ts:parseServerTimestamp` の存在理由は、バックエンドの `datetime.isoformat()` が naive UTC datetime に対して `Z` サフィックスなし文字列を返すためです。JS の `new Date()` はこれをローカル時刻と解釈し、"X 前" 表示が狂います。サーバ timestamp を `Date.now()` と比較する UI コードは必ずこの関数を通すこと。

## 投資フラグ

| フラグ | 既定 | いつ気にするか |
|---|---|---|
| `--max-iter` | `20` | 長く回したいときだけ増やす |
| `--max-llm-calls` | `0` (無制限) | `investigate` あたりの LLM 呼び出し総数 opt-in hard cap。`0` は無効化。クラウド API 利用時にコスト暴走防止で明示的に指定。 |
| `--max-queries-per-hypothesis` | `5` | 1 仮説あたりの探索深さ。tracker が auto-confirm / refute / pivot で先に解決することはある。 |
| `--no-progress-limit` | `3` | 低信号サイクルを許容したいときに緩める |
| `--report-every-n-cycles` | `1` | レポート再充填コストが高すぎるときに増やす。間が空くと `stale` の優先順位効果が薄れる。 |
| `--report-parallelism` | `1` | ローカル LLM バックエンドが並列耐えるときだけ増やす |
| `--profile` | `windows-basic` | 別のルールプロファイルに切替 |
| `--report-only` | `false` | 仮説ループを回さずレポートだけ再充填 |

## 再実行のセマンティクス

- `forensia run` は既定で investigation を含む。
- 出力ディレクトリを初期化するには `--init`。
- `report` は render のみ。
- `report-write` は section 再充填してから render。

## README との境界

README はユーザ向け価値提案・ワークフロー・高レベルアーキテクチャ・インストール / 使い方を扱います。CONTRIBUTING はアーキテクチャ不変条件・状態所有・スキーマ責務・調査と記憶のセマンティクス・コントリビュータ向けの実装制約を扱います。新しい章を足すときはこの境界を意識すること。
