# 調査の流れと根拠を対話的に確認する

## 目的

調査中と停止後のどちらでも、「何を確かめようとしたか」「何を実行したか」「何が得られたか」「なぜその判定になったか」を、保存済みの記録へ戻りながら確認できるようにする。[ARTEXの採用方針](artex-adoption.md)にある、作業に結び付いた記録と、概要から必要な詳細へ進む設計を、人が使う画面にも接続する。

ここで表示する考えは、明示的な計画、検索の目的、モデルが提出した判定理由、ホストが検査した条件である。内部の思考過程を新たに生成・要求する機能ではない。説明文を読めることと、その説明が証拠で裏付けられたことは区別する。

## 既存の基盤と追加した導線

既存のTUIには、Runtimeへの追加指示、停止・再開、永続イベントの閲覧、時刻からのイベント詳細表示、型とIDによる詳細取得がある。今回、短いログだけでは追いにくかった計画・実行・評価・判定の関係を、次の導線で読めるようにする。

| 操作 | 表示するもの |
| --- | --- |
| `/activity` | 既定の表示。イベントの目的・結果・理由と、関連記録への参照を読む。 |
| `/logs` | 同じイベントを短い一覧で読む。 |
| `/trace H-ID` | 指定した仮説に所属する、複数セッションにまたがる既存Traceをページ単位で読む。`H-ID`は実際の仮説IDに置き換える。 |
| 時刻や関連記録の参照をクリック | イベント、計画・実行のstep、Receipt、Assessment、Evidenceなどの保存記録を開く。 |
| `/detail KIND ID` | 型とIDを指定して元記録を開く。例えば`/detail hypothesis H-ID`。 |
| `/more`または詳細画面のMore | 次の詳細ページを読む。 |
| 詳細画面のBack、Raw / Summary | 直前の詳細へ戻る、または概要と保存済みの全フィールドを切り替える。 |
| `/older`、`/newer` | 以前のイベントへ戻る、または最新のイベントを追う。 |

例えば、仮説の計画から検索stepへ進み、検索結果のReceipt、採用されたEvidence、Assessment、ホストの判定を順に確認する。行数やツールの成功だけで確定とせず、未充足の条件や停止理由も同じ流れで確認する。画面で記録を開く操作によって、検索やモデル呼出しを再実行しない。

画面上部の`Now`欄には、現在の対象・目的・動作・モデル応答待ちを常設する。過去のログや詳細を読んでいる間も、現在作業はRuntimeのsnapshotから更新する。保存された直近のstepや、選択候補の一覧をそのまま「実行中」とはみなさない。停止済みセッションの対象・目的も現在作業へ持ち越さない。

入力欄へ自然文を送ると、`You`の指示と`FORENSIA`の受付・適用結果が活動表示へ残る。入力の全文はcommand receiptから確認できる。追加指示の受付と適用は別々に記録し、指示を受け付けたことだけで適用済み・停止済みと表示しない。

基本動作は自律調査であり、各段階で入力を求めて待つ構成ではない。調査中の追加指示は安全な処理境界で適用し、連続した指示を処理してから自律調査を再開する。指示を採用できない場合や解釈に失敗した場合は、その結果を正しく示し、元の調査の継続を妨げない。明示的な停止・終了は優先する。停止中に指示だけを更新した場合は勝手に調査を始めず、`/resume`で再開する。

## 表示する情報の信頼境界

| 記録 | 読み取れること | それだけでは決まらないこと |
| --- | --- | --- |
| 計画・検索目的・モデルの判定提案 | 次に何を確かめようとし、どう説明したか | 条件の充足、証拠の採用、正式な確定 |
| SQL実行とToolReceipt | 実行した問い合わせ、取得結果、失敗や不完全性 | 活動の不存在、問いの解決、独立した裏付け |
| AssessmentとSufficiency | 証拠と条件の対応、十分性、矛盾や不足 | 検査していない解釈や対象への一般化 |
| ホストのSettlement | 保存時の正式な判定と、通過・不通過の条件 | 証拠・VerificationSpecの変更後も同じ判定が有効であること |
| Taskの契約・完了記録 | 入力の版、期待成果物、完了条件と照合結果 | 親のQuestion Gapまで解決したこと |
| LLM試行のHTTP status・`parse_status`・`accepted` | HTTP応答の受信と、JSON objectとしての受理をそれぞれ確認する | 応答schemaへの適合、クエリの許可、証拠・判定の採用 |

モデルの提案とホストの判定を別の記録として保つ。表示する参照は、保存済みのIDと型から解決する。似た文面や、使い回せるquery IDだけを根拠に因果関係を補わない。参照先がない古い記録では不足をそのまま残す。

LLMのHTTP要求が`success`で終わっても、JSONの受理は未確定であり、その時点の`accepted`は`null`である。JSON parserが受理・拒否を記録してから`true`・`false`になる。JSONとして受理した後にも、用途ごとのschemaと調査・証拠の契約による検査が続く。これらの異なる成功を一つの「採用済み」にまとめない。

過去の評価は、その時点のTraceである。Assessmentの保存記録と現在のEvidenceLink、Receiptに保存された結果と現在の正規化Evidenceを区別する。現在の原本を詳細画面へ再取得しても、当時の検索結果が現在と同じだったことの証明にはならない。現行性と失効の扱いは、既存のEvidence fingerprint、VerificationSpec、[Taskの完了契約](task-contracts.md)に従う。

## 保存と読取りAPI

正本は既存のケースDBであり、画面用の別DBや新しい調査ループは作らない。

| 保存先 | 内容 |
| --- | --- |
| `trace.progress_events` | 順序付きのイベント、状態、severity、理由、参照、表示に使う属性 |
| `trace.investigation_steps` | 計画・検索・評価、契約、Settlementなどの入出力 |
| 同表の`runtime-provenance`、`session-settings` | セッション開始時の実装・実行環境の識別情報と採用設定 |
| `trace.hypothesis_reasoning` | 明示的に保存された仮説の説明・判定理由 |
| `trace.llm_logical_calls`、`trace.llm_provider_attempts` | 論理的な判断単位と実HTTP試行、要求・応答、失敗、使用量 |
| `main`のCase StateとEvidence | 現在の仮説・Task・Gap・評価リンク・原本の正規化レコード |

仮説検証のイベントでは、`payload.audit`のversion `1`に、記録元の`origin`、検索の`purpose`と`test_intent`、その段階で分かる件数・取得の評価・判定提案・ホスト判定・通過と不通過の条件を保存する。これは既存の公開された目的と実行・評価結果の投影であり、表示のために説明をモデルへ追加生成させない。これらの属性がない旧イベントでは、保存済みの概要と理由を表示する。

`refs`は、仮説と試行の参照に加えて、`plan_step_id`、`execution_step_id`、`receipt_id`、`check_step_id`、`assessment_id`、`sufficiency_step_id`、`settlement_ref`などの、存在する段階のIDを持つ。ある段階が未実行なら、その参照を作ったことにしない。検索に使うquery IDは補助情報であり、試行を一意に結ぶReceiptやstepの参照を置き換えない。

計画・評価のstepとLLM logical callは、同じ`action_id`、session、hypothesisの明示的な記録で結び付ける。logical callから実HTTP試行へは保存された`logical_call_id`を使う。似たphaseや同じquery IDから呼出しを推測せず、紐付けのない旧記録では不明のまま残す。

主SQLが0件で既存の補助検索を行う場合も、各補助SQLを`fallback-query`と`fallback-query-result`へ分けて記録する。実行したSQL・設定・元rule、開始と結果、0件を含む返却件数、truncation、失敗を残し、`fallback_start_step_id`と`fallback_step_ids`で主試行と結ぶ。未完了・失敗で件数が不明の場合は`null`とし、0件に置き換えない。補助検索の成功も、既存の評価を通さずに仮説を確定する根拠にはしない。

[db/views.py](../../src/forensia/db/views.py)の`case_snapshot`、`case_events`、`case_detail`と、[db/trace_views.py](../../src/forensia/db/trace_views.py)の参照・timeline投影が、live時と停止後で共通の読取り結果を返す。RuntimeのIPCも同じ投影を使い、[tui.py](../../src/forensia/tui.py)が表示と操作の受付を担う。読取りでは判定、契約の生成、Taskの完了を行わない。

`case_detail(db, "timeline", hypothesis_id, limit=50, offset=0)`は、指定した仮説へ明示的に所属するstep、LLM logical call、reasoningを、全セッションから取得する。順序は保存時刻と安定したIDで決める。返すページは最大50件で、`items`、`offset`、`next_offset`、`total_items`を持つ。項目には型、ID、時刻、session、phase、有限な概要、`related_records`を含める。

通常の詳細も、`related_records`に型・ID・ラベルを持つ参照を返す。長い元記録は文字単位でページングし、そのページでも参照を保持する。概要の省略は元記録の削除ではない。ライブイベントの順序を示す`event_index`と、仮説Traceの時刻順は異なるため、時刻順の一覧だけで因果関係を推定しない。

timelineの各ページには、そのページに含まれるセッションの`runtime-provenance`と`session-settings`への参照も、有限な表示枠で加える。記録のない過去のセッションへ、現在の環境情報を補って付けない。

## 監査で追えることと、再実行の限界

この機能が提供するのは、保存した調査の経路と判断材料を確認するための追跡性である。session設定、採用した方針、クエリ、取得と評価の参照、入力・応答が保存されたLLM試行へ戻れる。応答が得られなかった試行や異常終了時の不明値を、後から成功した記録で埋めない。使用量も実測・推定・不明を区別する。

[core/provenance.py](../../src/forensia/core/provenance.py)は、セッション開始時にversion `1`の識別記録を作る。Pythonの実装と版、OS・machine、FORENSIAと選定した依存packageの版、インストール先の`.py`と同梱`data/`の対象ファイルを識別する合成SHA-256を既存Traceへ保存する。packageの版が同じでも、ソースや同梱データが違えば識別できる。依存packageの版が得られなければ`null`、対象ファイルを完全に読めなければ`package_files.status=unavailable`として合成hashも`null`にする。ケース内の証拠、環境変数、認証情報はこのpackage識別の対象外である。

同じ入力から同じモデル出力を完全に再生成できる機能は提供していない。モデル名や要求本文の保存だけでは、モデルweight、量子化、seed、推論runtime、GPUや実行環境の完全な固定・保存にはならない。証拠やVerificationSpecが変わった後の再評価も、過去と同じ入力による再実行とは異なる。原本や実行環境を含めた保全・再現手順は別途必要である。

`runtime-provenance`のhashは、起動時にディスク上で観測したpackageファイルの識別である。読み込まれたbytecodeの同一性や、セッション中にファイルが変わらなかったことを保証せず、ソース・依存package・環境全体のアーカイブも作らない。

また、Traceの保存やfingerprintの照合だけで、保存物の第三者による改変を暗号学的に証明できるわけではない。画面は、証拠の保全や人による元記録の確認を代替しない。

## 変更時に確認する契約

- [test_investigation_observability.py](../../tests/test_investigation_observability.py)：実際の調査経路とLLM actionの対応、再試行・中断・補助検索の記録。
- [test_trace_views.py](../../tests/test_trace_views.py)：セッションをまたぐ時系列、所有者を照合した参照、ページングと読取り専用の投影。
- [test_llm_acceptance.py](../../tests/test_llm_acceptance.py)：HTTP成功、JSONの受理・拒否、修復後の試行の区別。
- [test_provenance.py](../../tests/test_provenance.py)：実装内容の変更検知と、欠損時の不明表示。
- [test_tui.py](../../tests/test_tui.py)：表示切替、参照から詳細への移動、ページング、過去イベント閲覧、狭い画面、更新中の詳細表示。
- [test_tui_steering.py](../../tests/test_tui_steering.py)：入力欄から実Runtimeへの指示、方針の適用、受付と適用の対話表示、自律調査の継続。
- [test_investigation_observability.py](../../tests/test_investigation_observability.py)：計画からSQL実行・評価・正式判定への参照、停止・再試行時の記録の保持。
- [test_db_progress.py](../../tests/test_db_progress.py)：永続イベントの順序、保持、snapshotの境界、有限な読取り。
- [test_trace_views.py](../../tests/test_trace_views.py)：明示的な所属・参照だけを使うtimeline、sessionの環境情報への参照、保存結果と現行Evidenceの区別。
- [test_provenance.py](../../tests/test_provenance.py)：packageと同梱データの変更識別、不完全・不明な環境情報の扱い。
- [test_llm_telemetry.py](../../tests/test_llm_telemetry.py)：HTTP試行、JSON受理、使用量・失敗の区別。
- [test_runtime.py](../../tests/test_runtime.py)：書込み中の確定済み状態の参照、操作の受付と適用、操作の重複防止。
- [test_runtime_continuity.py](../../tests/test_runtime_continuity.py)：停止・再接続・異常終了後に、未完了の試行と保存済みの結果を混同しないこと。
- [test_task_contracts.py](../../tests/test_task_contracts.py)：表示した完了情報と正式な成果物の照合、入力変更時の失効。

表示の追加によって、モデル呼出し、EvidenceLink、仮説・Task・Gapの状態が増減しないことも確認する。
