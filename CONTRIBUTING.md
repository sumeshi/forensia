# Contributing to forensia

forensia は、ローカルで完結する DFIR 調査支援ツールです。  
寄稿歓迎です。ただし、派手にすることより、壊れにくくすることを優先します。

優先順位は次のとおりです。

- 生ログをクラウドへ出さない
- 小型ローカル LLM の弱さを構造で補う
- Evidence に戻れる
- 同じケースを続きから回せる

## セットアップ

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

| 変数 | 説明 |
|---|---|
| `LLM_BASE_URL` | LM Studio の API ベース URL |
| `LLM_MODEL` | 使用モデル名 |
| `LLM_MAX_TOKENS` | 1 回のレスポンス上限 |
| `LLM_THINKING_LANGUAGE` | 内部推論言語 |
| `LLM_OUTPUT_LANGUAGE` | 人間向け出力の言語 |
| `LLM_MEMORY_MAX_BYTES` | Structured Memories の圧縮閾値 |

### Web UI

```bash
cd web_ui
npx pnpm install
```

## よく使うコマンド

### バックエンド

```bash
UV_CACHE_DIR=/tmp/uv-cache PYTHONPATH=src uv run python -m unittest discover -s tests
```

### フロントエンド

```bash
cd web_ui
npx svelte-check
npx pnpm test
npx pnpm build
```

### ローカル実行

```bash
forensia run ./sample/DESKTOP-001 --out ./dist/DESKTOP-001 --profile windows-basic --max-iter 20
forensia serve ./dist/DESKTOP-001
```

## リポジトリ構造

| 層 | 主な場所 | 役割 |
|---|---|---|
| Ingest | `src/forensia/ingest` | EVTX / MFT を JSONL 化 |
| Normalize | `src/forensia/normalize` | JSONL を DuckDB 向けに整形 |
| Rules | `src/forensia/rules` / `src/forensia/rulepacks` | YAML ルール実行と Finding 生成 |
| Investigation | `src/forensia/ai/investigator.py` | 仮説検証ループ制御 |
| Planner / Checker | `src/forensia/ai/planner.py` / `src/forensia/ai/checker.py` | SQL 提案と検証結果評価 |
| Memory | `src/forensia/core/memory.py` | Structured Memories の再構成 |
| Report | `src/forensia/report` | section 更新と HTML / Markdown レンダリング |
| API | `src/forensia/api` / `src/forensia/web.py` | FastAPI, DTO, SSE |
| UI | `web_ui/` | Svelte 5 + Vite + Tailwind |

## ケース構成

```text
case001/
  manifest.yaml
  allowlist.yaml
  raw/
  db/
    case.duckdb
  findings/
  report_template/
  ai_logs/
  memory/
    overview.md
    hosts/
    users/
    hypotheses/
    evidence/
      suspicious.md
  reports/
    report.html
    report.md
    api/
```

### ざっくり役割

| パス | 役割 |
|---|---|
| `raw/` | 再処理用の元 JSONL |
| `db/case.duckdb` | 調査の正本 |
| `memory/` | Structured Memories |
| `reports/` | 人間向けレポートと API スナップショット |

## 実装上の前提

### DuckDB が正本

`case.duckdb` が source of truth です。  
`memory/*.md` は LLM 用に射影したコンテキストであり、正本ではありません。必要なら再生成できます。

### AI の出力を正本にしない

- LLM I/O は `ai_logs/` に残す
- 調査ステップごとの `input_json` / `output_json` は `investigation_steps` に残す
- Finding / Hypothesis / report state は DB に保存する

### SQL は読み取り専用

LLM が提案する SQL は、実行前にバリデーションされます。

- `SELECT` / `WITH` のみ許可
- 複数文を禁止
- 破壊的 SQL を拒否
- 許可テーブル以外を拒否

### `suppressed` は削除ではない

Finding を見えなくすることと、DB から消すことは別です。  
`suppressed` は状態変更であり、Evidence への導線は残す必要があります。

### `approved` は人間承認ではない

現状の `report_sections.status=approved` は、人間レビュー済みという意味ではありません。  
AI 観点で「追加の導線がもう薄い」という粗い状態です。

## データモデル

| 用語 | 意味 |
|---|---|
| Evidence | 元イベントや MFT エントリ |
| Finding | ルールや証拠から得られた観測事実 |
| Hypothesis | その事実の解釈や説明仮説 |
| Claim | レポート上で述べる主張 |
| gap | まだ埋まっていない不足情報 |

Finding は事実寄り、Hypothesis は解釈寄り、Claim は人間向け、Evidence は元データです。  
この境界を崩すと、調査と作文が混ざって破綻します。

## 組み込みルールのカバレッジ

中心は次のあたりです。

- 認証 / ログオン
- Kerberos / NTLM
- RDP
- PowerShell / LOLBas
- サービス / タスクによる永続化
- アカウント操作
- ログ改ざん / 監査変更
- Defender 関連
- 再起動 / シャットダウン

ルールは `src/forensia/rulepacks/windows/` にあり、DuckDB に対する SQL と Finding テンプレート、ATT&CK Technique を持てます。

## 主な DuckDB テーブル

| テーブル | 役割 |
|---|---|
| `evtx_events` | 正規化済み EVTX |
| `mft_entries` | 正規化済み MFT |
| `mft_timeline` | MFT から展開した時系列 |
| `findings` | Finding 本体 |
| `ai_reviews` | LLM によるレビュー結果 |
| `hypotheses` | 仮説状態 |
| `report_sections` | レポート section の本文・状態・gap |
| `investigation_sessions` | investigate 実行履歴 |
| `investigation_steps` | 各ステップの入出力 |
| `progress_events` | UI 配信用イベント |

## UI を触るとき

- `web_ui/dist/` は配信物です
- `forensia serve` は build 済み UI を FastAPI から返します
- DuckDB がロックされているときは `reports/api/*.json` スナップショットで表示します

## README を触るとき

README は公開向けです。  
価値、思想、使い方、ケース構成までは README に置き、内部クラス名や実装都合は `CONTRIBUTING.md` に寄せてください。
