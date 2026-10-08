# FORENSIA v1 実装タスク（archive）

v2 進行に伴い 2026-10-09 に `TASKS.md` から移した作業記録。基準 revision は `242ca6a96b3c5382d857fc3ecda68a45205e2908`。**2026-10-08（午後 round）：R01/R02/R03・R13/R14・R09 未使用経路・R15 を実装・検証済み**。B0 比較元は [round-b0-baseline.md](../round-b0-baseline.md)。R04–R08、R09/R10/R11 の残部、R16/R17、R12 は未着手（v2 の V2-03/V2-04/V2-07/V2-08/V2-11 に引き継ぎ）。

目的は、**単純な構造で弱い local LLM の調査性能を改善し、改善理由を説明すること**。正しさの不変条件を守り、性能が同程度なら独立状態・同期・分岐・LLM call の少ない案を選ぶ。技術的な方法は実装者がこの基準で判断する。

`L1–L11` は GOAL §3、`C0–C10` は §12 の根拠を指す。仕様の単純化に合わせてタスクを再編し、**必須工程は T00–T11 の12件**とする。human command 基盤や multi-host 全面移行まで実装することを完了条件にしない。

## 各タスクの判断基準

- 現在の失敗と、それを生む責務・状態・条件の不一致を一つの経路で説明する。
- 既存の責務を整理した最小案を先に作る。予測する差と、その案では解けない点を示してから追加機構を検討する。
- 新しい mutable state、保存先、同期/失効処理、分岐、LLM call、調整パラメータを増減とも記録する。行数の削減だけで単純と判断しない。
- 正しさの修正は性能差が小さくても必要。性能最適化は、正しさを揃えた単純構成と比較して採否を決める。
- 現行機構で十分な項目は、追加不要という検証結果でも完了できる。これを「未検証のまま省略した」と混同しない。
- テストの存在や呼出回数の期待は、製品契約を残す根拠にしない。現行 producer/consumer と不変条件を先に決め、テストを更新・統合する。consumer が無い wrapper、未使用値、旧契約だけの分岐の撤去に実 LLM A/B 実験は要求しない。動作が変わる境界は実経路で確認する。

## GOAL との現行実装照合（2026-10-08）

対象は固定 main の初回調査だけでなく、前 round の未commit修正を含む現在の実装。
今回のレビューでは TASKS.md のみ変更し、コードは変更していない。以下は既存 T02/T04/T06–T11 の具体的な残件であり、別の実装計画や新 framework を追加するものではない。

「整合修正」はコードから確認できる条件・責務の不一致。「単純化比較」は複雑性の根拠があり、撤去・統合案の品質と費用を実測して採否を決める項目。「未評価」は効果の証明がまだない項目。実 case の発生頻度や LLM 性能差まで確認したとは扱わない。

| 残件 | 分類 | 既存タスク | GOAL の根拠 |
|---|---|---|---|
| R01：Spec の二重保持と未使用 policy | 整合修正・単純化 | T02 | §1.1、§14.3・16–17 |
| R02：query 数が独立支持に化ける | 整合修正 | T02・T04 | §14.6、§15.1 |
| R03：内容・Spec・policy 変更後の currentness | 整合修正 | T04 | §14.7、§15.1 |
| R04：work/eligibility/retry と Coverage の別判定 | 整合修正 | T06・T07 | §1、§14.8・12 |
| R05：report が順位を決める多項目 scoring | 整合修正・単純化比較 | T07・T11 | §1.1、§14.11・17 |
| R06：集計値による semantic progress と prose fallback | 整合修正 | T07 | §3 L6、§15.1 |
| R07：report-only と Case completion、session 所有期間 | 整合修正・方針訂正 | T08 | §14.11・13 |
| R08：Assessment の判断根拠と履歴参照の不足 | 整合修正 | T08（T04 と共通） | §3 L10、§15.1 |
| R09：未使用 checker context と Memory の多段経路 | 直接削減・単純化比較 | T09・T11 | §1、§14.9・17 |
| R10：再構築できると表示するだけの compaction | 整合修正・単純化 | T09 | §3 L9、§14.9 |
| R11：Spec と結びつかない schema 開示 | 単純化比較 | T10・T11 | §12 C6、§15.1 |
| R12：単純構成との local LLM 比較が未実施 | 未評価 | T11 | §1.1、§15.2–3 |
| R13：source identity の旧 path 探索と optional SHA | 互換撤去 | T04 | §13、§14.1・7・17 |
| R14：廃止済み MFT timeline 入力の第二経路 | 互換撤去 | T04・T11 | §13、§14.1・17 |
| R15：旧テスト用 wrapper、DTO/UI/template の旧契約 | 直接削減 | T11（各 owner で実施） | §1.1、§13、§14.17 |
| R16：log の文字列推測と二重保存 | 整合修正・互換撤去 | T08 | §7、§14.8・17 |
| R17：部分失敗した snapshot の虚偽の freshness | 整合修正・単純化 | T08 | §7–8、§14.8 |

修正の必要性と手段を分けて再確認した。R01–R06/R08/R10 は境界の整合が必要。R09 は明らかな未使用経路を先に削除し、残る LLM 要約の採否だけを比較する。R05 の scoring 簡略化・R11 の開示量削減は効果未測定であり、無条件の性能改善とは扱わない。R07 の「session terminal receipt を final report より前に移す」はそのまま採用しない。Case の調査結果は既に先に保存されており、session は report 実行中の lease も所有する。以下の訂正版を採用する。

### 検証の意味を先に揃える（実装済み：R01–R03、R13、R14）

- [x] **R01／T02：Spec を一つの検証契約にする。**
  - 実装済み（2026-10-08 午後 round）。Hypothesis の宣言 kwargs（rule/LLM 語彙）は model validator で 1 回だけ Spec 変換し、以降の model/storage/evaluator は canonical Spec のみ。`confirm_when` 等は spec 上の読み出し専用 derived property。store は Spec のみ書き込み、`_row_to_hypothesis` は壊れた/欠落 Spec を黙って旧条件へすり替えず明示失敗。legacy 列 3 個（confirm_when/refute_when/evidence_requirements）は DDL から削除し case schema version 2 へ。旧 case DB は version gate で拒否（ファイルは保全、再取込契約）。
  - 未使用 4 field（required_source_families / derivation_dedup_policy / allowed_settlement_states / untestable_conditions）は現行コードで consumer ゼロを再検証の上削除。`scope/correlation` は `execution.sql_absence_scope` が非空のとき absence 認証を unknown に落とす単一 guard で使用中 — 意味を維持して docs/data-model.md に記載。
  - 追加 fix：`_merge_hypothesis_fields` が宣言済み capability を黙って落としていた欠陥を発見し、spec-preserving merge に修正。
  - 確認：4624→4688 再現は消滅（regression `test_upsert_persists_canonical_spec_not_declaration_projection`）。admission→保存→reload→Assessment/Settlement が同じ条件を読む。

- [x] **R02／T02・T04：attempt identity と証拠の独立性を分ける。**
  - 実装済み（2026-10-08 午後 round）。Assessment の identity から `query_id` を除去（引数ごと削除、runner を同時更新）。同一 evidence の再観察は同一 assessment。sufficiency に `derivation_root_key` を追加：明示 `derivation_group` は（従来どおり）1 root を表し、なければ root = `row:<evidence_id>|<source_file>` の行 identity。Settlement の矛盾 gate も同一 key を共有。query ID は取得履歴のみ。
  - 確認：Q-one/Q-two での同一 evidence 1 行 → independent_groups 1→2 の再現が消滅（regression で sufficiency→settlement 両側確認）。別 source の別行は独立 root を保持。

- [x] **R03／T04：有効な支持の識別を内容・Spec・policy まで揃える。**
  - 実装済み（2026-10-08 午後 round）。link 作成時に backing evidence row の内容 fingerprint（`evidence/content_identity.py`：canonical row 内容の hash、volatile 管理列を除去）を `hypothesis_evidence.content_fingerprint` に保存（case schema version 3）。`evidence_link_currentness` は存在＋source 一致＋fingerprint 一致を検査し、不一致/判定不能は支持から除外。再評価は新 assessment_id とともに新しい link を追加（履歴保持）。
  - ingest 側は既存 invalidate owner に content-change hook を追加：同 ID・同 source で内容が変わると dependents を needs_review（identical 再取込は無効化しない）。
  - Spec/policy mutation の事実確認：post-assessment に judged spec を置換する経路は現行コードに無い。並行 validity state は追加せず、この意味を docs/data-model.md と sufficiency docstring に記録。
  - 確認：同 ID 内容変更 → `content_changed` 除外＋insufficient、再評価で新 link が支持を回復。identical 再取込は currentness 維持。

### work と lifecycle の重複判定を減らす（v2 の V2-03/V2-04 へ引き継ぎ）

- [ ] **R04／T06・T07：一つの読み出しから選択・停止・再開を決める。**
  - 根拠：selection の `check_eligibility`、work_state の `_coverage_state` / `reopen_retryable_work`、investigator の `_durable_open_work_counts`、store の active 分類が別々。selection は Coverage が無ければ通し、存在すればいずれか available を要求する一方、reopen は partial も ready とする。保存した `retry_condition` を読まず kind から再判定する。
  - `gather_selection_context` は Coverage を `family:capability` で上書きし、host/channel/time scope を落とす。複数 row の選択順に依存し得る。stop 集計も linked Gap と Task を別々に数え、共通 work identity になっていない。
  - 最小方針：Case State から work ref、現在の runnable/blocker、owner、retry 理由を必要時に導出する。必要 scope の Coverage を deterministic に照合し、partial の可否は同じ action/検証条件で判断する。再開の write は既存 owner に残す。Agenda table・cache・新 status・全面 multi-host model は追加しない。
  - 共通化するのは同じ問いの判定。partial な source を検索できることと、その空結果を absence と認定できることは別なので、retrieval eligibility と absence/sufficiency を一つの boolean に潰さない。
  - 確認：同じ DB を選択・停止・再開から読んでも readiness の理由が一致し、linked work を重複計数しない。未解決かつ runnable=0 は理由と再開条件を保存して停止し、無情報 broad planning を繰り返さない。

- [ ] **R05／T07・T11：report 由来の順位決定と説明できない scoring を整理する。**
  - 根拠：selection の `_compute_report_relevance` は admitted Gap link に加えて stale report の title/gap prose と候補 description の token overlap を加点する。`compute_priority_score` には report confidence/stale による項目もある。GOAL §14.11 の境界を満たさない。
  - 複雑性：relation 数を `dependency_impact` / `related_hypotheses`、selection 数を `retry_penalty` / `duplicate_penalty` で重ねて計上する。`report_changeability` は全候補共通の加点。`execution_cost` は対応条件語彙外の `queries/fallback` を読む。14項目の weight/range の効果は未測定であり、全部が有害と証明したとは扱わない。
  - 最小方針：report prose/confidence/stale が調査順位を決める経路を撤去する。admitted work の参照は残す。eligibility を先に適用し、少数の説明できる ordering と fairness を比較元にする。重複項目・意味のない加点・使われない YAML 設定は consumer と同時に整理する。
  - 確認：Case の admitted work を変えず report 文章だけ編集しても調査順位は変わらない。単純構成で prerequisite・必要な代替検証・長期未選択 work に到達できる。微差のための weight 調整機構は残さない。

- [ ] **R06／T07：state change と有用な progress を分ける。**
  - 根拠：`_semantic_progress_snapshot` は lifecycle rank の合計・歴史的 assessment 件数・Coverage rank を使う。同数置換・低下・相殺を識別できず、現在無効な link も集計する。`report_cycle_progress` には semantic snapshot が無いと prose `total_gaps` 減少を前進とする compatibility fallback が残る。loop の Coverage refresh は report-cycle の snapshot 比較より後にある。
  - 最小方針：必要な identity/scope/currentness を元状態から比較し、「再評価を要する変更」と「新しい有用な情報」を分ける。prose fallback を削除し、同じ root の再取得・状態の往復を前進としない。event bus・別 event store・revision framework は追加しない。
  - 確認：同数 source 置換/Coverage 低下で再評価され、文章変更や同じ情報の再評価だけでは no-progress budget が更新されない。比較タイミングも実 loop の state commit と揃える。

- [ ] **R07／T08：report-only の成功を Case 完了にせず、closing 中の所有権を保つ。**
  - 訂正：`investigate` は Case stop state を final report 前に保存する。`_final_report_refresh` は通常の `Exception` を捕捉して失敗件数を返すため、「report の通常例外で調査 session が failed になる」という前回の説明は誤り。session terminal receipt も finally 内の Memory/audit より先に保存済み。これらを未実装として再提案しない。
  - 残る不一致：`_check_termination(report_only=True)` は未解決 Gap/Task があっても completed を返し、その値が Case stop state にも保存される。report-only 操作の成功と Objective 達成を分ける。一時呼出でも open Gap/Task 各1件に対して `completed/report_only_mode` を確認した。
  - 最小方針：既存 Case state に調査結果、session に処理の phase/outcome を持たせ、closing 中は live owner を維持する。`reconcile_stale_sessions` は running session だけを排他対象にするため、final report 前に session を terminal 化するだけの修正は採用しない。session の実行期間を変えるための第二の lease/runtime は作らない。中断時は既存 finally/reconcile で調査結果と処理の終了理由を説明する。
  - 同じ owner の整理：`reconcile_stale_sessions` に残る「terminal_reason が無い全過去 terminal 行」の startup backfill は、現行 writer が reason を書く契約と揃えて撤去する。期限切れの running lease を回収する crash recovery は維持する。欠落した過去理由を今日の status から捏造しない。
  - 確認：report-only 後も未解決 Case は未解決として再開できる。closing 中の二重開始を拒否し、中断後の所有権回収と保存済み調査結果を確認する。既存の final-refresh 前 Case state、Memory/audit 失敗後 terminal receipt のテストは目的を維持する。

- [ ] **R08／T08：判断の最小参照を既存 Trace に残す。**
  - 根拠：runner は do step に receipt/evaluation、check step に Hypothesis/Spec の入力 snapshot と LLM 応答、sufficiency step に十分性結果を保存する。deterministic Assessment 自体は後で生成し、link には ID/role/group 等のみ渡し、`reason/matched_conditions` は保存しない。`create_hypothesis_evidence_link` は同 query/evidence/source/role の再評価時に assessment ID を上書きし得る。既存 snapshot と hash だけでは、元 evidence の内容変更後も含めた判断根拠の再構築を保証できない。
  - 最小方針：R03 と同じ入力識別を使い、既存 step payload/refs に不足する Assessment 根拠だけを残す。既存 Spec snapshot は参照し、同じ内容を別 model/table に重複保存しない。取得評価と支持判定は分けたまま、旧評価→新評価の経緯を辿れるようにする。新 Assessment authority/table、万能 lineage graph、完全 replay を要求しない。
  - 確認：一つの実 attempt の plan→receipt/evaluation→Assessment→Sufficiency→Settlement を既存 ID で説明できる。再評価で旧根拠を失わず、当時復元不能なものは明示する。LLM scratch を証拠にしない。

### context を直接投影し、追加 call の必要性を確かめる（v2 の V2-07/V2-08 へ引き継ぎ）

- [x] **R09／T09・T11：Memory 経由の多段解釈を縮める。**（部分完了）
  - 実施済み部分（2026-10-08 午後 round）：checkerが `_load_check_context` で取得後一度も参照しない `overview_md`/`memory_context_md` と、それだけが消費する session `Ctx.memory_overview/memory_check`、および dead になった `memory` 引数を producer/caller と同時に撤去。`compact_overview_if_needed`/`load_overview` は独立 consumer があるため保持。prompt 内容の変化なし。
  - 残件：memory updater / LLM digest を外した構成との比較（T09/R12 の測定前提）。endpoint 未接続のため未着手。

- [ ] **R10／T09：compaction の表示と実際の再構築契約を揃える。**
  - 根拠：`_compact_messages_after_context_rejection` は content と budget だけを `structured_compact` に渡す。blank-line 区切りを turn とみなし、source revision を 0 として `regeneratable=true` を出す。revision/ID validator は src/tests/scripts に呼出がない。wrapper 自体も予算超過時に mechanical truncation される。
  - 最小方針：まず元 message/source refs から必要 context を再選択する。一時 request に不要な durable revision 機構と、根拠のない再生成ラベル/未使用 helper は削除する。保存して再利用する projection だけに必要な source 識別を通す。critical 条件・contradiction・原本への展開先を保護する。
  - 確認：実 context-rejection 経路で削ってよい範囲だけが縮約され、必要 refs と再展開経路が残る。存在しない conversation turn/復元保証を表示しない。別 compactor や durable branch は追加しない。

- [ ] **R11／T10・T11：schema/card 選択を現在 work に結びつける。**
  - 根拠：planner は `_build_schema_guidance("evtx_events")` を使う。builder は selected card を選んでも `schema_column_guidance` で全 allowed table の列を付けるため、選択の削減効果が限定される。recipe は既に index と full body を分け、通常 full body は未選択なので、「全 recipe を毎回全文開示」とは扱わない。
  - 最小方針：未充足 Spec/eligible action から関連 family/table/card を選び、重複列開示を整理する。既存 recipe/index と一回の expansion を使い、alternative/反証の入口は残す。host の許可検査は開示とは独立に維持する。
  - 確認：EVTX 以外の work でも必要 schema に到達でき、不要列/token が減る。非開示を unavailable と誤認せず、有効 action 率・総 token を比較する。新 discovery framework/registry/ranker は作らない。

- [ ] **R12／T11：構造の整理を性能改善と同一視しない。**
  - 根拠：ここまでの pytest/doctor、コード・テスト削減、offline CLI は correctness/実経路の証拠。実 local LLM の B0/B1/個別変更比較は未実施である。
  - 最小方針：T00 の小さい corpus と既存手順で、正しい単純 B1 と各変更を固定 model/settings/budget で比較する。支持可能・回答不能、代替検証、無情報停止、context overflow、再開を含める。汎用 benchmark 基盤・恒久 feature flags は作らない。
  - 確認：FP/FN と到達性を落とさず、総 call/token/time と構造の増減を説明する。微差・未説明の効果しかない機構は外す。LLM 未測定ならこのタスクを未完了に保つ。

### 追加で確認した互換処理・不要経路（実装済み：R13/R14/R15）

- [x] **R13／T04：source を SHA と path の両方で扱う経路を閉じる。**
  - 実装済み（2026-10-08 午後 round）。`ingest_all` が唯一の production caller であることを確認の上、EVTX/MFT/Prefetch/Registry adapter の `source_sha` を必須化（`source_sha or path/basename` fallback 全削除）。`normalize._resolve_source_path`（SHA→絶対→相対→basename の 4 段探索）と coverage `_source_file_values`・`_check_row_count_invariant` の ORサブクエリを撤去。`_update_source_status` は SHA 直接照合。Registry の dataset/contributor identity は別責務として無変更。
  - 確認：regression で旧 path identity の行は静かに一致させず `failed`+`normalized_rows_missing` として標記。空 parser 出力・欠落・parse failure の区別は既存 `_raw_source_state` 経路で維持。path 型 fixture は SHA 契約へ更新。

- [x] **R14／T04・T11：MFT timeline の旧 raw 入力と空の戻り値を撤去する。**
  - 実装済み（2026-10-08 午後 round）。MFT は entries → DB timeline の一経路のみ。`_TIMELINE_COLUMNS`、`mft-timeline-*.jsonl` の glob/stage/insert 分岐、entries↔timeline 重複回避集合、旧 file unlink 副作用（`ingest_mft_file` は常に entries path のみ返す）を撤去。旧 JSONL は勝手に削除しない（regression で disk 保持を確認）。Prefetch で現在使う timeline 入力・共通 SQL helper は Prefetch の現行責務として保持。

- [x] **R15／T11：旧テスト用 wrapper と旧表示契約を consumer ごと撤去する。**
  - 実装済み（2026-10-08 午後 round）。`format_question_answer` wrapper（production caller なし）を削除し、必要な status/空回答の確認を実 entry `_format_structured_answer` へ統合。template parser `benchmark_id` alias（宣言側なし）を削除し docs の template contract も整合。`FindingDTO.attack` と `formatAttackMappings` の文字列分岐・旧 `name` fallback を typed mapping producer に合わせ撤去。cockpit `verdictBreakdown.inconclusive`（表示 consumer なし・status との二重集計）を削除。
  - producer 側 fix：`_result_source_label` は caller ゼロの dead で削除。`_summarize_sql_result` が表示 label を一度決定（`evidence_query`）し、後段の `replace("raw_sql","evidence query")`（現行出力にも作用していた「legacy safeguard」）を撤去。最終 markdown の `assertNotIn("raw_sql",...)` は旧 token 漏れ防止の regression として維持。

- [ ] **R16／T08：log の level を producer で決め、保存表現を一つにする。**（v2 の V2-04 へ引き継ぎ）
  - 根拠：core/log は本文の `failed/error/confirmed` 等から severity を推測する。progress_pusher は structured entry と旧文字列を `recent_log_entries/recent_logs` に二重保存し、UI が旧形式へ fallback する。`[QUERY] Searching for failed logons` が `level=error` になることを直接確認した。証拠の内容と処理失敗が混ざる。
  - 最小方針：既存 progress event/log producer が tag/level/message を出し、未指定は中立の info とする。保存は structured entry のみにして、CLI の文字列は描画時に導出する。新 logging framework は不要。
  - 確認：failed-logon 等の対象名で処理エラーにならず、実例外/警告/成功は明示された level で表示される。`test_core_log` 等が現在の単語推測を固定していても、その期待は変更する。

- [ ] **R17／T08：snapshot の部分失敗を current として公開しない。**（V2-01 で snapshot 経路ごと撤去済み）
  - 深さ（2026-10-09 記録）：api/cache の full/volatile writer は DTO ごとの広い `except Exception` で出力を飛ばし、最後に一括 metadata を更新する。`snapshot_metadata` は `generation_revision == state_revision`、`stale=False` を常に設定する。一時 DB で hypotheses DTO の生成だけを失敗させると、旧 hypotheses.json を残したまま revision が更新され、state=current/stale=false になることを再現した。この snapshot 経路自体は V2-01 で撤去済み。TUI/V2-09 以降で「部分失敗を current 表示しない」性質が必要になった場合は既存 Case/Trace read query で保証すること。

### 一括削除しない現行責務

`compatibility` / `fallback` / `getattr` の検索結果だけでは削除しない。local LLM endpoint の response-format 交渉、弱いモデルの bounded な JSON 修復、source 不明時に支持を拒否する検査、期限切れ lease の crash recovery は現在の問題を解いている。catalog に channel/provider 制約を持たない event があることや、case 全体を読む report context も、旧データ互換とは別に現行 producer/用途を確認する。R01/R09 の整理では内部型を確定させ、存在する field を optional duck typing で読む部分は同時に減らすが、外部入力の検証まで削らない。

### 次 round の優先順とレビュー範囲（→ v2 進行順に移管）

まず R01–R03（検証契約・独立性・currentness。source 整理の R13/R14 も同時に検討）、次に R04–R08 と R16/R17（共通 work 判定・report 境界・進捗・保存・表示）、その後 R09–R11（context/capability）を扱う。R09 の未使用経路と R15 の独立した削減は先行できる。R12 の測定は各段階で行う。（R01–R03・R13/R14・R09part・R15 は 2026-10-08 午後 round で実装済み。残りは v2 の V2-03/V2-04/V2-07/V2-08/V2-11 に引き継ぐ。）

既に整理した自動 migration/backfill、global case profile、planner の旧応答形式・戻り値、静的な重複 column 一覧、Rule.attack/Memory filename の互換処理は再提案しない。selector 例外時の旧 policy fallback も現行 `investigation_cycle` には残っていない。T07 の残件は共通判定への接続である。multi-host/entity・human command・追加 event/cache は引き続き条件付きとし、未実装という理由だけで必須タスクにしない。

## T00–T11（v1 のタスク残況）

### T00：小さな比較元と構造の棚卸しを作る

- [x] **成果**：既存 tests/fixtures から、条件一致/不一致、telemetry 不足、source replacement、矛盾、context overflow、停止・再開を確認する最小 corpus を選び、B0（現行 main）の結果を記録する。 → `docs/round-b0-baseline.md`（corpus 対応表、L1/L3/L5/L8 境界再現、`scripts/eval/b0_repro_*.py`、複雑性センサス）。focused suite は 162 passed（GOAL §15.4 と一致）。LLM endpoint 未接続のため LLM 実測は未実施と明記。

### T01–T05（M0：検証の意味を揃える）

- T01 [x]：`core/verification.py` に `EVALUABLE_CONDITION_KEYS`（単一語彙 owner）。Assessment は co-observation adapter 経由で `event_contexts` を評価可能、`event_constraints` は field 条件を満たす行に絞ってから相関判定し Assessment/Settlement が同じ witness を使う。未知 key は fail-closed＋明示理由。keywords は hint と分類。
- T02 [x]：R01/R02 由来。Spec 単一契約・並行書込撤去・未使用 field 削除・独立支持の分離（上記 R01/R02）。readiness 述語の統一は T06/T07 へ繰り越し。
- T03 [x]：`SettlementInput` に `absence_scope`/`absence_note`。runner が `judge_absence_scope` で判定し両 settle 経路へ渡す。rule 宣言 zero_rows の refuted は observable absence が条件、それ以外は `auto_untestable_*` へ downgrade。case-wide EVTX の exact event-ID lookup に限定した scope 認証を実 runner に接続。
- T04 [x]：R03 由来。currentness（存在＋source SHA＋内容 fingerprint）、ingest 側 invalidation、再評価の履歴保持。限界（adapter 例外経路 diff skip、sufficiency policy hash の consumer なし）は docs/data-model.md に記録。
- T05 [x]：文章消失の bulk resolve 廃止。消失・言い換え・同 section 別質問は open 維持＋`report_request_absent` / `linked_hypothesis_untestable` を既存 `coverage_reason` に記録。similarity/section による自動解決は撤去（レビューで欠陥確認）。`_check_termination` は durable `report_gaps`/`investigation_tasks` の未解決数を参照。

### T06–T11（M1/M2/M3）

- T06/T07（R04–R06）、T08（R07/R08/R16）、T09（R09 残部・R10）、T10（R11）、T11（R12）：未着手。v2 の V2-03/V2-04/V2-07/V2-08/V2-11 に引き継ぎ。

## Round 1 実装記録（2026-10-07 初回、2026-10-08 レビュー修正）

### 検証結果（B0 → B1、`docs/round-b0-baseline.md` §4/§7 参照）

| 境界 | B0（main `242ca6a`） | レビュー修正後の挙動 |
|---|---|---|
| L1 | admitted `event_contexts` spec が Assessment で常に `contextual` | catalog-qualified rows は `supporting`（matched_conditions に key 明示）。context 非保持 rows は fail-closed のまま |
| L3 | coverage partial/unavailable/unknown のいずれでも `refuted` | いずれも `untestable` に downgrade（理由に不足明細）。`absence_scope="observable"` の refuted 経路は維持 |
| L4 | 文章消失が Gap/Task を無条件 resolved 化、untestable も解決扱い | open 維持＋`report_request_absent` / `linked_hypothesis_untestable` を既存 `coverage_reason` に記録 |
| L5 | durable open gap があっても `completed/no_gaps_no_hypotheses` | durable work 未解決では完了しない（no-progress 停止機構へ）。解決後は完了 |
| L8 | 削除済み evidence の link が `sufficient` を維持 | `current_only` loader で支持から除外（履歴 link は保持、score 0.65→0.0） |

### 複雑性の増減

- **統合**：条件 key 語彙を 1 owner に（評価実装は既存 adapter 再利用）。capability 推論を `derive_required_capabilities` 1 箇所に。`event_constraints` 解釈を settlement から共通 owner へ委譲。dead 関数 1 個削除。
- **撤去**：文章消失の無条件 bulk resolve（Gap＋Task）、prose `total_gaps` による完了判定、runner 内 16 行の重複 field コピー、`get_capability_for_table`。
- **追加**：`SettlementInput.absence_scope/absence_note`（純入力 2 field）、`current_only` kwarg、case-wide EVTX absence scope の純粋な認証関数、durable 未解決 2 集計。新 table/column/status/LLM call/retry 層はゼロ。CSV `required_capability` 永続化は既存 storage として維持。
- 初回 B1 gates: pytest 1024 passed / ruff / check_imports / doctor 合格。ただし実経路の4欠陥を検出できていなかった。

### レビュー修正と整理（2026-10-08）

- 相関は context/field を満たす行で host/entity/time を判定し、別 witness の組み合わせで確認しない。
- report の similarity/section による後継推測・自動解決を撤去。古い work が残れば completion を拒否する。
- query から source が見えなくても新しい link は DB 原本の source を保存。判定不能な過去 link は再評価を要し、今日の source で埋めない。
- canonical 条件から capability を導出し、case-wide EVTX の限定した absence scope を実 runner から RetrievalEvaluation/Settlement へ渡す。sampling/derived rows 等を valid scope とみなさない。
- 不要な field-constraint wrapper、未使用 unlinkable-observation wrapper、no-op time gate を削除。Coverage 照合を既存関数へ統合。重複した相関テストを置換し、手動の absence-scope テスト2件を実 runner 経路へ統合。

### テスト全体の整理（2026-10-08）

owner の指摘を受け、修正箇所だけでなく suite 全体の重複を点検した。テスト件数は品質の指標にしない。同じ不変条件は主たる責務境界で確認し、内部 helper、mock forwarding、列順、型、同梱ファイルの数・文言を繰り返し固定するテストを削除する方針を `docs/development.md` に明記した。

- API の DTO mock・SQL 文字列検証を削り、既存の実 DB/HTTP シナリオで stats、finding filter/pagination、manifest、非公開設定、report table HTML を確認。
- snapshot の大量 mock を削除。空 case から状態追加・再生成まで実 DB で確認し、JSON 内容・上書き・削除範囲（nested/authored file の保全）を検証。
- audit の MagicMock path による偽のファイル名保証を撤去。実 transcript と usage summary、繰り返し識別を確認。
- Memory の private counter/glob、knowledge の件数・時間制限、prompt の文言重複を削除。再開時の fact ID 保全、relevance filtering、実 fragment budget、compaction の Evidence ID path 保全は公開経路の結果で確認。
- Evidence の artifact 別 lookup 重複を bulk routing/missing/dedup のシナリオへ集約。

集計：収集テスト **1036 → 807**（229件、約22%減）、tests/test_*.py 2,643 行減。20ファイルを整理。全体 pytest 805 passed / doctor 全8項目。

### コードをテストへ合わせない整理（2026-10-08）

テストは必要な責務境界に置き、実際の動作・成果物で保証する。古いテストの都合で API、別アルゴリズム、mock 専用分岐を保守しない。実施：cycle の旧 selector・focus score と任意例外での旧 policy 切替を削除（選択失敗は本来の failed/terminal receipt を保存）、旧 dedup helper と daily-session answer の互換 shim を削除、snapshot metadata の非 tuple/list 分岐を削除、final-summary の全言語同一値分岐を削除。実装 93 行減、テスト 66 行減。全体 pytest 802 passed。実 CLI `forensia report` で disposable case を確認（`/tmp/forensia-code-simplification-7i0mi2f_`）。実 LLM 未使用。

### Latest-only 契約への整理（2026-10-08）

owner が既存形式の互換維持より単純な理想形を優先すると明示したため、通常実行の旧形式対応を撤去した。過去migration/backfill/verdict修復群を削除し、core/trace各DBの最新形式version契約へ一本化（旧形式・version不一致・片方欠落は persistent DDL/DML の前に拒否）。case profile の module-global/path cache を削除。planner は現在の型付き action だけを受け付ける（flattened 応答の変換、原応答の書換え、二度目の正規化、Memory API がない時の scope 迂回、未使用 overview/initial_context 引数を撤去）。prompt の別 column 一覧は実 DB 生成に一本化。Rule.attack の旧 short-form 変換と Memory の旧 slug 削除を撤去。維持：verification spec の現行正規化、response-format 交渉、source provenance fail-closed 判定。実装 1,148 行減。全体 pytest 792 passed。doctor 全8項目。実 CLI で disposable case 確認（`/tmp/forensia-code-simplification-edes_stg`）。実 LLM・migration 未実行。

## Round 2 実装記録（2026-10-08 午後、R01–R03・R13/R14・R09part・R15）

### 成果と検証

| 項目 | 実測の確認 |
|---|---|
| R01 | 4624→4688 再現が消滅（canonical のみ保存）。壊れた/欠落 Spec は明示失敗。schema v2 へ（旧 case DB は拒否・ファイル保全）。merge の capability 欠落欠陥を同時修正 |
| R02 | 同一 evidence を Q-one/Q-two で観察 → independent_groups 1→2 の再現が消滅（1→1）。別 source の別行は独立維持。sufficiency↔settlement が同一 root key を共有 |
| R03 | 同 ID・同 source の内容変更 → `content_changed` 除外＋insufficient。identical 再取込は current。再評価は新 link 追加で履歴保持。ingest 側は内容変更で dependents を needs_review |
| R13/R14 | path identity 入口の全消滅。旧 MFT JSONL は読まず・削除せず。旧 path 行は静かに一致させず failed 標記 |
| R09part | checker 未使用 context の撤去（prompt 内容不変）。`len(calls)==2` の pin を残る planner context 1 呼出へ統合 |
| R15 | wrapper/alias/文字列 DTO 分岐/二重集計/後段 replace の撤去。唯一の実挙動変化は `raw_sql`→`evidence_query` の表示 label |

### 複雑性の増減

- **統合**：Spec 検証契約 1 本（宣言は admission で 1 回変換）、sufficiency↔settlement の独立判定 1 関数、source identity 1 形式（ingest SHA）。
- **撤去**：legacy 列 3 個＋二重書込＋row/assessment/推論 fallback 4 経路、未使用 spec field 4 種、`_resolve_source_path`（4 段 COUNT）、MFT 第二経路、単体 wrapper 4 件、後段置換、未使用 checker context。net src 約 −400 行。
- **追加**：case schema v3（`content_fingerprint` 1 列）、`content_identity.py`（純粋 fingerprint）、`derivation_root_key`（純関数）。新 table/status/LLM call/scheduler/registry はゼロ。

### Gates（全合格）

- 全体 pytest **798 passed, 2 skipped, 146 subtests** / ruff / check_imports / doctor 全 8 項目。frontend vitest 2 files 7 tests、`tsc --noEmit` clean。B0 再現スクリプト 4 件は期待挙動。

### 未測定・繰り越し

- LLM 実測は不可（endpoint 未接続）。R12 は未完了のまま維持。
- R04–R08、R09/R10/R11 残部、R16/R17 は次 round（→ v2 の V2-03/V2-04/V2-07/V2-08/V2-11）。
- 既存ユーザー case・`mft-timeline-*.jsonl`・authored Memory は変更していない（旧 case DB は新コードで拒否され、再取込契約）。
