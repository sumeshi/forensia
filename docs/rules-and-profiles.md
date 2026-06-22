# Rules / Profiles / Allowlist

検知ルール、プロファイル選択、allowlist による suppression、宣言層の仕様。

---

## 1. Rulepack

ルールパックは `src/forensia/rulepacks/windows/` (または類似) 配下の YAML 定義。`src/forensia/rules/models.py` の Pydantic モデルが `extra="forbid"` でスキーマ強制するため、未知フィールドはロード時に弾かれる。

### 1.1 検出部 (必須)

| フィールド | 役割 |
|---|---|
| `id` | 安定したルール識別子 |
| `title` | 人間向けタイトル |
| `severity` | findings の既定 severity |
| `confidence` | findings の既定 confidence |
| `query` | 正規化済み証拠への読み取り専用 SQL |
| `finding.title` / `finding.summary` | 行フィールドから render するテンプレ |
| `tags` | 分類タグ |
| `attack` | ATT&CK マッピング (full-form: `[{tactic, technique_id, technique_name}]`) |

ルールクエリの 1 行が 1 finding になる。元行は構造化 evidence として保存される。

### 1.2 仮説宣言 (任意、仮説ループを駆動)

ルールが LLM 駆動の仮説ループも seed するなら、次を宣言する。Python 側はこれを generic に消費する (kill-chain 知識は Python にハードコードしない)。

- `hypotheses[]`: ルール発火時に instantiate される仮説テンプレ
  - `id`: ルール内安定 id
  - `segment`: kill-chain segment (`persistence`, `lateral-movement` 等)
  - `description`: `{field}` プレースホルダ付き仮説文 (クエリ行カラムにバインドされる)
  - `required_entities`: confirm に必要な entity 名
  - `confirm_when`: `{co_observed_event_ids: [...], same_host: bool, within_minutes: int}` のような相関基準。`HypothesisProgressTracker` が auto-confirm を判定
  - `refute_when`: `{zero_rows: true}` 等の refutation 基準
  - `follow_up_questions`: confirmed 時に自動 spawn される質問
  - `report_sections`: 解決時に stale 化する section キー
- `correlate_with[]`: planner が「これも見ろ」と促される event ID 群。`{event_ids: [...], rationale: str}`
- `fallback_search[]`: primary SQL 0 行時に宣言順で実行されるフェーズ。LLM 不在。許可フェーズは:
  - `keyword_in_raw_json` (LIKE エスケープ)
  - `related_event_ids` (別 event 表面)
  - `artifact_table` (別の正規化テーブル、`engine.py` で whitelist)

### 1.3 例

```yaml
id: windows-security-4625-failed-logon
title: Failed account logon attempt
severity: medium
confidence: 0.6
required_fields: [target_user, src_ip]
tags: [windows, security, credential-access]
attack:
  - tactic: credential-access
    technique_id: T1110
    technique_name: Brute Force
query: |
  SELECT evidence_id, timestamp, computer, target_user, src_ip, logon_type, failure_reason
  FROM evtx_events
  WHERE event_id = 4625
finding:
  title: 'Failed logon for {target_user}'
  summary: '{target_user} failed to log on to {computer} from {src_ip}.'
hypotheses:
  - id: brute_force_attempt
    segment: credential-access
    description: Repeated 4625 from {src_ip} targeting {target_user} suggests brute-force
    required_entities: [src_ip, target_user]
    confirm_when:
      co_observed_event_ids: [4625, 4624]
      same_host: true
      within_minutes: 30
    refute_when:
      zero_rows: true
    follow_up_questions:
      - Did the brute force succeed? Look for 4624 from {src_ip} for {target_user}
    report_sections: [3_technical]
correlate_with:
  - event_ids: [4624, 4771]
    rationale: 'co-observed success / Kerberos pre-auth failure'
fallback_search:
  - phase: related_event_ids
    event_ids: [4776]
```

---

## 2. Profile

プロファイルはルール選択ポリシー。`src/forensia/profiles/` 配下。

| フィールド | 役割 |
|---|---|
| `name` | プロファイル名 |
| `rulepacks` | rulepack root 配下の対象ディレクトリ / パス |
| `rule_ids` | 任意の特定ルール ID 許可リスト |

プロファイルは選択メタデータ。ルールロジックを複製しない。

### 安定であるべきこと

- ルール ID は外部識別子として永続的に扱う
- プロファイルは「どのルールが active か」を意味し、「どう実行するか」ではない
- ルールクエリは read-only / 証拠指向のまま保つ
- finding テンプレは行駆動で、各 finding が evidence traceability を保つ
- パッケージ同梱のルールメタデータと finding テキストは英語で書く

選択意味論ではなく実行意味論を変える必要があるなら、それは rule engine の変更であり、profile フォーマットの変更ではない。

---

## 3. Allowlist と suppression モデル

`allowlist.yaml` は概念的にルールに隣接するが、ルールを選択しない。

- プロファイルがどのルールを走らせるかを決める
- ルールが候補 findings を生成する
- allowlist が rule_id スコープのフィールドマッチで `suppressed` を決める

現在のマッチモデル:
- 1 つの `rule_id`
- `when` 配下の 1 つ以上のフィールド述語
- 値は対象 finding の最初の構造化 evidence 行から取得

これは pre-filter ではなく post-generation な提示・triage コントロール。

---

## 4. 宣言層 (`_schema/`)

`src/forensia/rulepacks/_schema/` はルールディレクトリではなく、ルールとプロンプトが共有するスキーマと DFIR 知識を置く場所。ローダは enumerate 時にスキップする。

| ファイル | 消費側 | 役割 |
|---|---|---|
| `evtx_events.yaml` / `mft_entries.yaml` / `mft_timeline.yaml` / `prefetch_executions.yaml` / `prefetch_timeline.yaml` / `findings.yaml` | `prompts._build_schema_guidance()` 経由 `_load_schema_hints()` | DB テーブルの schema card。`core_columns` (planner 向け短いサブセット) + `column_descriptions` (1 行説明) + `columns` (SQL validator 用) + `json_field_extractors` (raw_json fallback) |
| `event_ids.yaml` / `logon_types.yaml` | `prompts._dfir_playbook()` | Event ID / Logon Type の DFIR 解説 |
| `app_catalog.yaml` / `artifact_inference.yaml` | `prompts._dfir_playbook()` | Prefetch / MFT / Registry / File → アプリ推定。planning 系では意図的に省略、interpretation 系のみに注入 |
| `false_positive_rules.yaml` | rule engine + `prompts._dfir_playbook()` | 既知 FP。interpretation 系プロンプトのみで参照 |
| `dfir_ioc_catalog.yaml` | `prompts._dfir_playbook()` | アンチフォレンジック / クラウド同期 / メール / Recycle Bin 等の補助 IOC 辞書 |
| `question_routing.yaml` | `questions.py` + `section_agent.py` + `prompts.build_section_agent_*` + `prompts.build_structured_classify_messages` | QuestionSpec の正本。`question_type` / `answer_spec` ごとの `expected_answer_shape` (コード側 `_format_structured_answer` が消費)、`evidence_chain` (primary 0-row 時に `_execute_evidence_chain` が決定論的に試行)、required/render fields、status rules を宣言 |
| `question_routing_eval.yaml` | `scripts/audit_schema_coverage.py --strict` | QuestionSpec ルーティングの mutation corpus。見出し・本文・言語が変わっても安定した `answer_spec` に解決されるかを監査 |
| `verdict_taxonomy.yaml` | `core/verdicts.py` | verdict 値の whitelist と層間マッピング |
| `playbook/*.md` | `prompts._dfir_playbook(phase)` | フェーズ別 (`broad_plan` / `hypothesis_plan` / `check` / `report_section` / `section_agent_plan` / `section_agent_check`) のプレイブック本文。`<CRITICAL_RULES>` / `<FORBIDDEN_PATTERNS>` / `<SCHEMA_CONSTRAINTS>` 等のタグ付き |

### 4.1 DB テーブル schema YAML が宣言すること

- `table`: テーブル名 (例: `evtx_events`)
- `core_columns`: planner LLM が見る短いリスト。13 以下に保つ
- `column_descriptions`: 各 `core_columns` に対する 1 行説明
- `columns`: 全列リスト (`validate_select_sql` が undeclared 列の SELECT / WHERE を弾くのに使う)
- `json_field_extractors` (任意): 列が NULL のときに raw_json から拾う DuckDB JSON 抽出式
- `notes` (任意): timestomp 注意点や Prefetch の `no_host_column` 等のヒント

新しい investigable テーブルを追加するなら `_schema/<table>.yaml` を置き、必要に応じて `sql_schema.py` の `_LEGACY_ALLOWED_TABLES` / `get_allowed_tables()` と SQL template allowlist を更新する。YAML は `_load_schema_hints()` で自動消費される。

### 4.2 playbook 自動再生成

`playbook/*.md` は `<!-- AUTO-FROM: <yaml-path> -->` ... `<!-- /AUTO-FROM -->` マーカー内を `scripts/regenerate_playbook.py` が再生成する。マーカー内は手編集せず、ソース YAML を編集して再生成する。

### 4.3 Allowlist スキップ

`kind: allowlist_services` のように `kind:` プレフィックスを持つファイルはルールではなく、ローダがスキップする (suppression ロジックが消費)。

---

## 5. ファイル配置慣習

- パッケージ既定は `src/forensia/report_template/` / `profiles/` / `rulepacks/` 配下に置く
- case-local `report_template/` は初期化時にコピーされる override 入力として扱う
- 現状、profile と rulepack の case-local コピーには依存しない (package tree から解決される)
