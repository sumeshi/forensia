# Data Model

forensia が扱う永続データの定義。3 つの層に分かれている。

- **DuckDB テーブル**: `db/case.duckdb` 内の構造化データ
- **メモリファイル**: `memory/*.md` の LLM 永続記憶
- **API DTO**: UI / レポート向けに API が公開する Pydantic モデル

---

## 1. DuckDB テーブル

スキーマ初期化は [src/forensia/db/database.py](../src/forensia/db/database.py) の `CaseDB.__init__` で行う。

### 1.1 正規化された証拠データ

| テーブル | 役割 | 主な列 |
|---|---|---|
| `evtx_events` | 正規化済 Windows イベント | `evidence_id`, `timestamp`, `computer`, `event_id`, `channel`, `user_name`, `target_user`, `subject_user`, `src_ip`, `logon_type`, `process_name`, `command_line`, `service_name`, `raw_json` |
| `mft_entries` | NTFS ファイル単位の MFT レコード | `evidence_id`, `record_number`, `file_path`, `file_name`, `fn_name`, `extension`, `is_deleted`, `size`, `si_created`, `si_modified`, `si_accessed`, `fn_created`, `fn_modified`, `fn_accessed` |
| `mft_timeline` | MFT エントリを timestamp_type で展開 | `timeline_id`, `evidence_id`, `record_number`, `file_path`, `timestamp`, `timestamp_type`, `description` |
| `prefetch_executions` | Prefetch 集約 (binary ごとに最新を 1 件) | `evidence_id`, `executable_name`, `exec_count`, `last_exec_time`, `prefetch_hash`, `filenames`, `volumes`, `raw_json` |
| `prefetch_timeline` | Prefetch 実行履歴 (binary × 8 件まで) | `timeline_id`, `evidence_id`, `executable_name`, `prefetch_hash`, `exec_time`, `exec_index` |
| `ingested_files` | ingest 重複防止用のハッシュ表 | `path`, `hash`, `source_kind`, `ingested_at` |
| `case_timeline` | 決定論的タイムライン (R2-11) | `entry_id`, `timestamp`, `source` (`finding`/`verdict`/`structured`/`keypoint`), `ref_id`, `host`, `summary`, `evidence_id` |

`case_timeline` は 3 つの決定論的 feeder で挿入される: (a) severity ≥ medium の findings の初証拠タイムスタンプ (`feed_findings_to_timeline` [engine.py:196](../src/forensia/rules/engine.py#L196))、(b) resolved hypothesis の decisive query row、(c) `question_routing.yaml` で `timeline: true` と宣言された structured answer の該当行。

`evidence_id` は全テーブル横断の証拠識別子。命名規則:
- EVTX: `evtx-<channel>-<sequence>` (例: `evtx-security-000000001166`)
- MFT: `mft-<record_number>-<seq>` (例: `mft-000000023554-00`)
- Prefetch: `prefetch-<executable>-<hash>` (例: `prefetch-iexplore-exe-4b6c9213`)

ホスト識別:
- `evtx_events` のみ `computer` / `user_name` 列を持つ
- `mft_*` / `prefetch_*` は単一ボリューム前提のため host 列なし

### 1.2 ルール検知と仮説

| テーブル | 役割 | 主な列 |
|---|---|---|
| `findings` | ルール検知の結果 | `finding_id`, `rule_id`, `title`, `summary`, `severity`, `confidence`, `status` (`new`/`accepted`/`suppressed`), `tags`, `attack`, `evidence`, `ai_summary`, `missing_checks`, `created_at` |
| `hypotheses` | 投資調査の仮説 | `hypothesis_id`, `description`, `status` (`active`/`resolved`), `verdict` (`confirmed`/`refuted`/`inconclusive`/`untestable`), `summary`, `origin`, `created_session`, `resolved_session`, `confidence`, `source_rule_ids`, `source_decl_id`, `required_entities`, `confirm_when` |
| `hypothesis_reasoning` | 仮説検証の reasoning 履歴 | `entry_id`, `hypothesis_id`, `session_id`, `iteration`, `phase` (`plan`/`do`/`check`/`act`/`memo`), `verdict`, `query_id`, `body`, `created_at` |

`findings.attack` は JSON 文字列で、`[{tactic, technique_id, technique_name}]` 形式。`list_attack_coverage_dto` ([src/forensia/api/service.py:716-](../src/forensia/api/service.py#L716)) で tactic × technique マトリックスに集計される。

`findings.evidence` は元 evidence_id を含む dict のリスト。再帰的な抽出は [`_evidence_ids_from_payload`](../src/forensia/api/service.py#L33) で行う。

### 1.3 セッションとステップ

| テーブル | 役割 | 主な列 |
|---|---|---|
| `sessions` | 投資調査 / レポート生成の実行単位 | `session_id`, `started_at`, `finished_at`, `iterations`, `status` |
| `investigation_steps` | session 内の各ステップ (plan / do / check) | `step_id`, `session_id`, `hypothesis_id`, `iteration`, `phase`, `input_json`, `output_json` |
| `progress_events` | UI 用の進捗イベントストリーム | `event_index`, `stage`, `status`, `iteration`, `current_query`, `summary`, `payload` |
| `query_cache` | LLM が出した SQL の結果キャッシュ | `sql_hash`, `sql_text`, `result_json`, `executed_at` |

### 1.4 レポート生成

| テーブル | 役割 | 主な列 |
|---|---|---|
| `report_sections` | セクション本文 | `section_key`, `title`, `body`, `confidence`, `status` (`draft`/`stable`/`ai_exhausted`/`human_reviewed`), `update_count`, `gaps`, `last_filled_session`, `last_filled_at`, `stale` |
| `section_runs` | セクション block の実行履歴 (debug) | `run_id`, `section_key`, `block_heading`, `iteration`, `phase`, `payload`, `created_at` |
| `section_evidence` | セクションが参照した evidence | `section_key`, `block_heading`, `evidence_id`, `role`, `source_query`, `created_at` |
| `section_facts` | セクション内で reusable な事実 | `fact_id`, `fact_type`, `fact_key`, `fact_value`, `evidence_ids`, `source_query`, `source_section`, `confidence` |
| `section_run_coverage` | block 別の keypoint カバレッジ | `section_key`, `block_heading`, `keypoint`, `queried`, `rows`, `used_in_answer` |
| `claims` | レポート段落から抽出した主張 | `claim_id`, `section_key`, `claim_text`, `support_status`, `finding_ids`, `hypothesis_ids`, `evidence_ids` |

`section_evidence` への INSERT は [section_agent.py:431 `_store_section_evidence`](../src/forensia/ai/section_agent.py#L431) の 1 箇所のみ。

`section_facts.source_section` には:
- 通常のセクションキー (`1_overview` など)
- 特殊値 `__case_probe__` — universal_question (last_human_logon など) の結果。デフォルトでは他セクションに reuse しないよう [`_load_reusable_section_facts`](../src/forensia/ai/section_agent.py#L648) でフィルタされる。`6_appendix` のみ `include_case_probe=True`。

### 1.5 レビューと監査

| テーブル | 役割 | 主な列 |
|---|---|---|
| `ai_reviews` | LLM レビューの結果 | `review_id`, `finding_id`, `verdict`, `report_text`, `missing_checks`, `confidence_adjustment`, `notes`, `raw_response` |
| `schema_migrations` | スキーマバージョン管理 | `version`, `applied_at` |

---

## 2. メモリファイル (`memory/*.md`)

`MemoryManager` ([src/forensia/core/memory.py](../src/forensia/core/memory.py)) が読み書きする。LLM が直接読み書きする「外部脳」で、構造化 (anchor 行 + 自由記述) を保持する。

### 2.1 ファイル構成

```
memory/
├─ overview.md              · ケース全体の short summary (LLM が縮約)
├─ facts.md                 · confirmed な事実の追記ログ
├─ timeline.md              · timestamp 付きの観測点
├─ tasks.md                 · follow-up / verification タスク
├─ evidence/
│  └─ suspicious.md         · 怪しい evidence のメモ
├─ entities/
│  ├─ user/<name>.md        · ユーザカード
│  ├─ host/<name>.md        · ホストカード
│  ├─ ip/<name>.md          · IP カード
│  ├─ process/<name>.md
│  ├─ service/<name>.md
│  ├─ file/<name>.md
│  ├─ registry/<name>.md
│  ├─ group/<name>.md
│  ├─ machine_account/<name>.md
│  └─ unknown/<name>.md
├─ hypotheses/<id>.md       · 仮説ごとのスクラッチ + 確定後の要約
├─ keypoints/KP-NNNN.md     · finding に紐づく keypoint カード
├─ scratch/H-NNN/           · 仮説検証中の暫定メモ (refute 時は archive へ退避)
└─ archive/
   ├─ refuted.md            · 棄却された仮説のログ
   └─ resolved_gaps.md      · 解消した gap のログ
```

### 2.2 entity カードの形式

[`investigator._render_entity_memory`](../src/forensia/ai/investigator.py#L529) で生成される。

```markdown
# user: alice

- type: user
- name: alice
- role: attacker
- notes: created malicious scheduled task at 03:14 UTC
```

`role` の許容値は `attacker` / `victim` / `actor_candidate` / `observed_user` / `suspicious_user` / `newly_created_user` / `machine_account` / `unknown` (`ENTITY_ROLES` 定数で定義)。

### 2.3 更新経路

| パス | 関数 |
|---|---|
| 投資調査ループ (verdict 反映) | [`_apply_memory_updates`](../src/forensia/ai/investigator.py#L737) が LLM の `memory_updates` 出力を読み、facts / timeline / tasks / overview / refuted_hypotheses / resolved_gaps / entities を反映 |
| セクションエージェント | [`_sync_keypoint_cards`](../src/forensia/ai/investigator.py#L547) が findings → keypoint カードを同期 |
| 仮説確定時 | `memory.upsert_hypothesis` が `memory/hypotheses/<id>.md` を書き換え (refute 時は `archive/refuted.md` へ追記) |

`memory_updates` の構造は `MEMORY_UPDATER_SCHEMA` ([src/forensia/ai/schemas.py:60-79](../src/forensia/ai/schemas.py#L60-L79)) で定義。LLM 出力スキーマの詳細は [llm-roles.md](llm-roles.md) を参照。

---

## 3. API DTO

`src/forensia/api/dto.py` で Pydantic モデルとして定義。`extra="ignore"` 設定により、snapshot JSON にキーが追加されても古い DTO で読める。

### 3.1 ケース概要

| DTO | 内容 | 由来テーブル |
|---|---|---|
| `CaseDTO` | ケース名 / paths / manifest | `manifest.yaml` |
| `CaseStatsDTO` | 件数集計 (evtx_rows, mft_entries, findings_accepted, active_hypotheses, ...) | 複数の `COUNT(*)` |

### 3.2 検知と仮説

| DTO | 内容 | 由来テーブル |
|---|---|---|
| `FindingDTO` | 1 finding | `findings` |
| `HypothesisDTO` | 1 仮説 + 直近 reasoning 3 件埋め込み | `hypotheses` + `hypothesis_reasoning` |
| `HypothesesResponseDTO` | `{active: [...], resolved: [...]}` | 上記を partition |
| `HypothesisReasoningEntryDTO` | reasoning 履歴の 1 行 | `hypothesis_reasoning` |

`FindingDTO` は `findings.evidence` JSON から `evidence_ids` / `evidence_count` を抽出して持つ。

### 3.3 セッション

| DTO | 内容 | 由来テーブル |
|---|---|---|
| `SessionDTO` | 1 セッション | `sessions` |
| `InvestigationStepDTO` | 1 ステップ | `investigation_steps` |
| `ProgressEventDTO` | 進捗イベント | `progress_events` |

### 3.4 レポート

| DTO | 内容 | 由来テーブル |
|---|---|---|
| `ReportSectionDTO` | 1 セクション + `section_evidence` 集計 | `report_sections` + `section_evidence` |
| `SectionQuestionDTO` | structured 質問の解決状態 | (構造化質問テーブル) |
| `ClaimDTO` | レポート段落から抽出した主張 | `claims` |

`ReportSectionDTO` は `section_evidence` テーブルからセクション別の `evidence_ids` / `evidence_count` を集計して持つ。

### 3.5 周辺情報

| DTO | 内容 | 由来 |
|---|---|---|
| `EntityCardDTO` | エンティティカード 1 件 (kind, name, mention_count, summary) | `memory/entities/<kind>/<name>.md` |
| `AttackCoverageRowDTO` | tactic × technique の集計 | `findings.attack` JSON を集計 |
| `EventVolumePointDTO` | イベント時系列 1 ポイント (bucket, series, count) | `evtx_events` + `mft_entries` |
| `MftTimelineDTO` | MFT timeline 1 行 | `mft_timeline` |
| `AIReviewDTO` | LLM レビュー結果 | `ai_reviews` |

DTO がどの API エンドポイントで使われるかは [src/forensia/web.py](../src/forensia/web.py) を参照。snapshot 経由のサーブ機構は [architecture.md](architecture.md) の「API スナップショットと UI」節を参照。
