# Code Map

`src/forensia/**` 各ファイルの責務一覧。grep の代わりに使う住所録。

## CLI / コア

| パス | 責務 |
|---|---|
| [src/forensia/cli.py](../src/forensia/cli.py) | typer による CLI コマンド宣言 (`investigate` / `add` / `report` / `templates-export` など)、DB ライフサイクル、progress emit |
| [src/forensia/config.py](../src/forensia/config.py) | `.env` ベースの設定値読み出し (`get_llm_settings`) |
| [src/forensia/core/case.py](../src/forensia/core/case.py) | `Case` データクラス。ディレクトリ構造定義 + `extract_time_range` (DuckDB から first/last event を抽出) |
| [src/forensia/core/memory.py](../src/forensia/core/memory.py) | `MemoryManager`。`memory/*.md` の read/write 抽象 |

## DB

| パス | 責務 |
|---|---|
| [src/forensia/db/database.py](../src/forensia/db/database.py) | `CaseDB` クラス。DuckDB 接続 + スキーマ初期化 + マイグレーション |
| [src/forensia/db/query.py](../src/forensia/db/query.py) | クエリ補助 (`fetch_records`, `normalize_value`) |
| [src/forensia/db/schema.py](../src/forensia/db/schema.py) | テーブル DDL の定義 |

## 取り込み (Ingest)

| パス | 責務 |
|---|---|
| [src/forensia/ingest/__init__.py](../src/forensia/ingest/__init__.py) | `ingest_all` エントリ。raw/ をスキャンして適切なパーサに割り振り |
| [src/forensia/ingest/evtx.py](../src/forensia/ingest/evtx.py) | EVTX → `evtx_events` 投入 |
| [src/forensia/ingest/mft.py](../src/forensia/ingest/mft.py) | MFT → `mft_entries` + `mft_timeline` 投入 |
| [src/forensia/ingest/prefetch.py](../src/forensia/ingest/prefetch.py) | Prefetch → `prefetch_executions` + `prefetch_timeline` 投入 |

## ルール

| パス | 責務 |
|---|---|
| [src/forensia/rules/loader.py](../src/forensia/rules/loader.py) | `rulepacks/**/*.yaml` のロード + プロファイル絞り込み |
| [src/forensia/rules/models.py](../src/forensia/rules/models.py) | Pydantic モデル (`Rule`, `Finding`, `Hypothesis`, `AttackEntry`, ...) |
| [src/forensia/rules/engine.py](../src/forensia/rules/engine.py) | rule SQL の実行 + finding 生成 + `fallback_search` 発火 |
| [src/forensia/rulepacks/](../src/forensia/rulepacks/) | YAML ルール定義 (windows/, leakage/, _schema/) |

## AI / 仮説調査

| パス | 責務 |
|---|---|
| [src/forensia/ai/investigator.py](../src/forensia/ai/investigator.py) | 仮説調査ループ。`broad_plan` / `_investigate_one_hypothesis` / `_apply_memory_updates` / トラッキング |
| [src/forensia/ai/planner.py](../src/forensia/ai/planner.py) | 仮説検証クエリ立案。`plan_hypothesis_query` で `query_intent_planner` → `sql_self_check` → `sql_composer` の 3 段 |
| [src/forensia/ai/checker.py](../src/forensia/ai/checker.py) | 仮説判定。`_check_query` で `verdict_reviewer` → `finding_extractor` → `memory_updater` を呼ぶ |
| [src/forensia/ai/section_agent.py](../src/forensia/ai/section_agent.py) | レポートセクション block 単位の query → narrate → finalize。`_narrate_paragraph_with_retry` などの narrator ロジック |
| [src/forensia/ai/section_refresher.py](../src/forensia/ai/section_refresher.py) | 既存セクションの再生成エントリ |
| [src/forensia/ai/prompts.py](../src/forensia/ai/prompts.py) | LLM プロンプト構築 (`build_*_messages` 関数群) |
| [src/forensia/ai/schemas.py](../src/forensia/ai/schemas.py) | LLM 出力 JSON Schema (`MEMORY_UPDATER_SCHEMA`, `VERDICT_REVIEW_SCHEMA`, `PARAGRAPH_NARRATE_SCHEMA`, ...) |
| [src/forensia/ai/llm_client.py](../src/forensia/ai/llm_client.py) | OpenAI 互換 LLM クライアント (`chat_completion` / `async_chat_completion`)。HTTP リトライ + schema mode 自動降格 + `_SCHEMA_MODE_CACHE` |
| [src/forensia/ai/json_response.py](../src/forensia/ai/json_response.py) | JSON 返却型 LLM 呼び出し (`request_llm_json` / `async_request_llm_json`) |
| [src/forensia/ai/sql_schema.py](../src/forensia/ai/sql_schema.py) | SQL 生成支援。`information_schema` から live スキーマを取得して prompt に注入 |
| [src/forensia/ai/sql_templates.py](../src/forensia/ai/sql_templates.py) | テンプレート SQL カタログ (template_id → SQL) |
| [src/forensia/questions.py](../src/forensia/questions.py) | structured question テンプレ + answer_spec → builder ルーティング |
| [src/forensia/ai/report_gap.py](../src/forensia/ai/report_gap.py) | report セクションの gap 検出 + 仮説への変換 |

## レポート

| パス | 責務 |
|---|---|
| [src/forensia/report/writer.py](../src/forensia/report/writer.py) | レポート整形の本体。`REPORT_KEYPOINTS` カタログ、`build_report_markdown_from_db`、`finalize_section`、`_render_structured_answer_markdown`、claim 抽出、coverage 集計 |
| [src/forensia/report/html.py](../src/forensia/report/html.py) | Markdown → HTML 変換 |

## API / Web

| パス | 責務 |
|---|---|
| [src/forensia/api/dto.py](../src/forensia/api/dto.py) | Pydantic DTO 定義 |
| [src/forensia/api/service.py](../src/forensia/api/service.py) | DB → DTO 変換。UI / report_brief 用の集計クエリ |
| [src/forensia/api/cache.py](../src/forensia/api/cache.py) | API snapshot の書き出し (`write_volatile_api_snapshots` / `write_full_api_snapshots` / `write_progress_snapshot`) |
| [src/forensia/api/progress.py](../src/forensia/api/progress.py) | progress events の persist と list |
| [src/forensia/web.py](../src/forensia/web.py) | FastAPI ルーター。`/api/*` を snapshot or DB fallback で返す |
| [web_ui/](../web_ui/) | Svelte + Vite + Tailwind フロントエンド。snapshot polling で UI 更新 |

## 関連: ルートのドキュメント / テンプレ

| パス | 内容 |
|---|---|
| [scripts/](../scripts/) | 補助スクリプト (`audit_schema_coverage.py` 等) |
| [tests/](../tests/) | pytest テスト |
| [src/forensia/rulepacks/_schema/](../src/forensia/rulepacks/_schema/) | スキーマ定義 YAML (`evtx_events.yaml`, `mft_entries.yaml`, `question_routing.yaml` など) |
| [src/forensia/report_template/](../src/forensia/report_template/) | レポートのデフォルトテンプレ Markdown |
