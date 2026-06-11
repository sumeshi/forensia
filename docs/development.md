# Development

開発環境のセットアップ、テスト方針、補助スクリプト、CLI フラグ。

---

## 1. 開発環境

### 1.1 Python

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
| `LLM_REASONING_RESERVE_TOKENS` | 推論モデル向けの追加トークンバッファ |
| `FORENSIA_API_BASE_URL` | UI 開発時の API ベース URL |
| `FORENSIA_UI_ORIGINS` | FastAPI の CORS 許可リスト (カンマ区切り) |

CLI で base URL を指定する場合は `--llm-base-url`。

### 1.2 Web UI

```bash
cd web_ui
npx pnpm install
```

### 1.3 よく使うコマンド

```bash
# バックエンドテスト
UV_CACHE_DIR=/tmp/uv-cache PYTHONPATH=src uv run python -m unittest discover -s tests

# フロントエンド
cd web_ui
npx svelte-check
npx pnpm test
npx pnpm build

# ローカル実行
forensia investigate ./dist/DESKTOP-001 ./sample/DESKTOP-001 --profile windows-basic --max-iter 20
forensia report ./dist/DESKTOP-001
forensia report ./dist/DESKTOP-001 --write
forensia serve ./dist/DESKTOP-001
```

---

## 2. テスト方針

テストスイートは秒単位で完了させ続ける。

- **実 LLM 呼び出しを伴うテストを書かない**。`investigate(...)` の完全サイクルや実サーバ依存の section refresh は副作用 (DuckDB 書き込み、memory I/O、ファイル走査) が多すぎて軽くならない。`run_section_block_agent` などを通す場合は、structured answer / deterministic builder / mocked JSON response に閉じる
- **実 LLM サーバを叩くテストを書かない**。過去にあった `tests/test_benchmark_e2e_real_llm.py` (`FORENSIA_LLM_BASE_URL` で gate) は同じ理由で削除済み
- 代わりに次でカバー: 純粋関数ヘルパのユニットテスト (`_slim_findings`, `_quality_gate_section`, `_render_structured_answer_markdown` 等)、永続化の DB-only テスト、LLM モジュールを import しない CLI / HTTP テスト
- **決定論ゲートの回帰テスト**: verdict 整合ゲート・フォールバック降格・memory フィルタ・extracted finding 検証は `tests/test_checker_gates.py`、untestable 早期解決は `tests/test_untestable_resolution.py` でカバーする。これらのゲートを変更したら必ず同時に更新する
- 調査ループの挙動を本気で見たいときは、ローカルモデル相手に `forensia investigate ...` を回し、`ai_logs/` を目で確認する。pytest にしない

---

## 3. 補助スクリプトと `forensia doctor`

`scripts/` は宣言層 / コード / ドキュメントを揃え続けるためのオフライン監査群。runtime ではなく、`forensia doctor` がこれらをまとめて実行する。

| スクリプト | 用途 |
|---|---|
| `scripts/audit_schema_coverage.py` | 全ルール YAML の `query` SQL を sqlglot で AST 解析し、参照される `event_id` 値を抽出。`event_ids.yaml` / `question_routing.yaml` / `question_routing_eval.yaml` のカバレッジと QuestionSpec contract を照合 |
| `scripts/regenerate_playbook.py` | `_schema/playbook/*.md` の `<!-- AUTO-FROM: ... -->` セクションをソース YAML から再生成。`--check` で drift 検出 (exit 1)、引数なしで書き込み |
| `scripts/cycle_summary.py <case_dir>` | `progress_events.json` を解析し、cycle ごとの仮説 delta と benchmark 進捗を Markdown 表化。デバッグ補助 |
| `forensia doctor` | CLI コマンド。schema coverage / playbook drift check / verdict taxonomy AST スキャン / pytest を順に実行し、全部 pass のときだけ exit 0 |

`scripts/` は Python パッケージではない。`scripts/` から import するテストは、`conftest.py` がリポジトリ root を `sys.path` に追加していることに依存する。

---

## 4. CLI

| コマンド | 役割 |
|---|---|
| `add` | 既存ケースに追加アーティファクトを取り込み |
| `investigate` | 新規ケースなら case 作成 + ingest → normalize → analyze → investigate → report。既存ケースなら仮説ループを継続 |
| `report` | 既存 `report_sections` から Markdown / HTML を書き出し。`--write` 付きなら現在の証拠からセクションを再充填してから書き出し |
| `serve` | FastAPI と Svelte UI を提供 |
| `doctor` | hidden。schema coverage / playbook drift / verdict taxonomy AST / pytest をまとめて実行 |
| `templates-export` | hidden。同梱レポートテンプレートを書き出し |

### 4.1 投資フラグ

| フラグ | 既定 | いつ気にするか |
|---|---|---|
| `--max-iter` | `20` | 長く回したいときだけ増やす |
| `--max-llm-calls` | `0` (無制限) | `investigate` あたりの LLM 呼び出し総数 opt-in hard cap。クラウド API 利用時にコスト暴走防止で明示的に指定 |
| `--max-queries-per-hypothesis` | `5` | 1 仮説あたりの探索深さ |
| `--no-progress-limit` | `3` | 低信号サイクルを許容したいときに緩める |
| `--report-every-n-cycles` | `3` | レポート再充填コストが高すぎるときに増やす |
| `--report-max-queries-per-section` | `0` | section block agent の最大 query 数。`0` は `LLM_REPORT_MAX_QUERIES_PER_SECTION` の設定値 (既定 3) を使う |
| `--profile` | `windows-basic` | 別のルールプロファイルに切替 |
| `--report-only` | `false` | 仮説ループを回さずレポートだけ再充填 |
| `--rerun` | `false` | case tables と runtime outputs をリセットし、既存 `raw/` を使って normalize / analyze からやり直す |

### 4.2 再実行のセマンティクス

- `forensia investigate <case_dir> <input_dir>` は新規ケース作成から ingest / normalize / analyze / investigate / report までを実行する
- 既存ケースに `forensia investigate <case_dir>` を実行すると、前回状態を引き継いで仮説ループを継続する
- 出力ディレクトリを初期化してやり直すには `--rerun`。`raw/` は保持され、`input_dir` 省略時は既存 raw から re-normalize する
- `report` は render のみ
- `report --write` は section 再充填してから render

`--rerun` が呼ぶ `_reset_case_tables()` は、証拠由来の正規化テーブルだけでなく、派生 workflow state も消す必要がある。少なくとも `findings` / `hypotheses` / `report_sections` / `claims` / `section_facts` / `section_evidence` / `section_runs` / `section_questions` / `query_cache` / trace tables / `ingested_files` / `prefetch_timeline` を対象に含める。新しい mutable table を追加したら `_reset_case_tables()` と `tests/test_memory_and_ingest.py` の reset テストを同時に更新する。

### 4.3 スキーマ変更とマイグレーション

`db/schema.py` の `CREATE TABLE IF NOT EXISTS` を変更しても既存ケース DB には適用されない。既存テーブルへ列を追加する場合は、`db/database.py` の `_apply_migration_once("<key>", ...)` にマイグレーション (`ALTER TABLE ... ADD COLUMN IF NOT EXISTS`) を必ず追加する(例: `hypotheses_source_decl_id`, `mft_entries_fn_name`)。

---

## 5. UI 詳細

### 5.1 Cockpit 構成

`web_ui/src/App.svelte` は上から順に:

1. `Header`: ケース名、現在 phase、LLM モデル、最終更新タイムスタンプ
2. `KpiBar`: Events / Findings / Hypotheses / Open Gaps の 4 KPI。Findings タイルに severity 内訳 (High/Medium/Low)、Hypotheses タイルに verdict 内訳 (Active/Confirmed/Refuted/Inconclusive) の細い積み棒
3. `VolumeTimeline`: Chart.js 複合チャート。既定は全期間 day 解像度。range picker (年→月→日) で絞り込み、1 日を選ぶと hour 解像度に切替。検知 finding は折れ線オーバーレイ
4. `ReportDraftProgress`: セクション単位の充填状態
5. `AttackCoverage`: `findings.attack` から tactic × technique マトリックス
6. `Cockpit`: `AiActivityPanel`、Active / Resolved Hypotheses (`latestReasoningAt` desc) と Latest Reasoning ストリームをタブ切替する `HypothesisStream`、`OpenGaps`
7. `TopRules` + `TopEntities` (2 列グリッド)
8. `DetailsTabs`: findings / steps / sessions / activity / mft の生データタブ

### 5.2 Event Volume API 契約

`GET /api/event-volume` は `bucket=year|month|day|hour`、`source=all|detected`、任意の `start` / `end` ISO timestamp を受け付ける。[web.py](../src/forensia/web.py) の解決順:

1. 全範囲クエリならスナップショットファイル (`reports/api/event_volume_<bucket>_<source>.json`)
2. ライブ `CaseDB` クエリ
3. DB ロック中で正確スナップショットが無い場合、より細い snapshot から `aggregate_event_volume` で集計 (年 / 月 view が day / hour snapshot から再現できる)

`list_event_volume_dto` は year < 1980 (Windows epoch 1601 ゴミ) と year > today + 5 (NTFS FILETIME overflow、3220 / 30828 等) を除外。`aggregate_event_volume` でも同じフィルタを適用。

### 5.3 サーバ側 date 健全性

API やレポート writer が raw 証拠からタイムスタンプを受け取る箇所では、1980 ≤ year ≤ today + 5 の健全性レンジを適用する。レポート writer の quality gate も narrative 中の range 外日付を検出する ([report-pipeline.md](report-pipeline.md))。MFT / EVTX タイムスタンプを valid と仮定しない。

### 5.4 フロントエンドの timestamp 解析

`web_ui/src/lib/format.ts:parseServerTimestamp` の存在理由は、バックエンドの `datetime.isoformat()` が naive UTC datetime に対して `Z` サフィックスなし文字列を返すため。JS の `new Date()` はこれをローカル時刻と解釈し、"X 前" 表示が狂う。サーバ timestamp を `Date.now()` と比較する UI コードは必ずこの関数を通す。
