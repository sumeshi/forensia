# Taskの完了契約

## 実装範囲

通常の仮説検証を始めるときに、検証Taskとその完了契約を登録する。停止時に作るTask、必要な結果を外部や人へ求めるTaskにも契約を結び付ける。

検証Taskは、現在の入力と検証条件に対する正式なSettlementの結果を成果物として照合する。完了条件を満たしたTaskだけを`resolved`にする。検索の成功や終了、モデルが生成した判定文だけでは完了しない。

この契約は、[調査履歴の共有](investigation-history.md)で提示する過去の試行とは別の役割を持つ。履歴は次の検索の手がかりであり、Taskの完了記録は、その作業が固定した条件を満たしたかを記録する。

## 保存

Taskの状態・Gapや仮説への参照・担当・再試行条件は、既存の`investigation_tasks`に置く。契約と結果は、同じケースの`trace.investigation_steps`へversion付きの記録として保存する。

| Traceの記録 | 記録すること |
| --- | --- |
| `task-contract` | Task、仮説・Gap、入力証拠とVerificationSpecの識別情報、期待する成果物と完了条件。 |
| `settlement` | 共通のSettlementが返した正式な結果と、その判定を現在の入力・検証条件へ結び付ける参照。 |
| `task-completion` | 照合した契約と成果物の参照、完了の可否、未完了の理由。 |

新しいDB、表、列は追加せず、DBのschema versionは10を維持する。各payloadは[core/task.py](../../src/forensia/core/task.py)の`TaskContract`、`TaskSettlementReceipt`、`TaskCompletion`で検査し、記録形式の`version`は`1`である。形式や参照を解釈できない記録から、現在の完了を推測しない。

保存時の処理は[task_contracts.py](../../src/forensia/investigation/task_contracts.py)へ集約する。複数の記録やTask・Gapの状態を変える処理は、呼出し側の既存トランザクションへ接続する。CaseとTraceの片方だけを確定させない。

## 実行と完了の適用

1. [通常のrunner](../../src/forensia/investigation/hypotheses/hypothesis_runner.py)が`TASK-VERIFY-*`の検証Taskを準備し、現在の入力と条件を契約へ結び付ける。
2. 検索、Evidence IDによる原本の再取得、Assessment、Sufficiency、Settlementを既存経路で実行する。
3. 正式なSettlementの記録を成果物として保存し、契約のTask・入力・条件との対応を照合する。
4. 完了したTaskだけを閉じる。停止、通信障害、根拠不足、入力や条件の変更は、理由を持つ未完了として残す。

選択・保留・再開の可否は[WorkJudgment](../../src/forensia/investigation/work_judgment.py)を使う。完了契約は新しい証拠評価器や別の計画ループを持たず、既存の正式な判定を作業の成果物として確認する。

### 親のQuestion Gap

検証Taskの完了と、親の質問に必要な要求が揃うことは別に判定する。Question Gapは、[report_gap.py](../../src/forensia/investigation/report_gap.py)の既存の質問・admission receipt・対象範囲・評価済みEvidenceの条件で判断する。一部の観測だけが成立した場合に、Taskの完了を理由として親の質問全体を解決しない。

### 入力と条件の変更

完了の照合では、保存したVerificationSpecと入力証拠の識別情報を現在の状態と比較する。古い成果物の存在だけで、新しい入力のTaskを閉じない。

証拠の差替え・削除・同一IDの内容変更で根拠が失効した場合は、既存の[失効処理](../../src/forensia/evidence/invalidation.py)と[状態遷移](../../src/forensia/investigation/work_state.py)から、関連TaskとGapを再開する。過去の契約・完了・証拠リンクは履歴として残し、現在の評価を上書きして取り繕わない。

入力の識別には、既存のsource / Coverage / VerificationSpec / required entitiesに加え、正規化処理のrevisionを含める。成果物では、実際の検索Receiptの親仮説・仕様・出典revision、評価済みリンクの内容・強さ・派生元も照合する。Task自身のstatusや更新時刻は入力に含めず、完了したことで自分の入力が変わることを避ける。

0件の反証には、再開を伝えるEvidenceLinkが存在しない場合がある。[session開始処理](../../src/forensia/investigation/investigation_session.py)は通常の調査開始時に、完了契約と完了記録を持つ内部Taskを再点検する。入力が古くなっていれば、同じトランザクションで仮説・Task・Gapを再開し、依存するClaimと報告節も再評価対象にする。報告だけの実行では、この再開を行わない。

## 読取りAPIとWorking State

契約の保存と照合は[task_contracts.py](../../src/forensia/investigation/task_contracts.py)の次のAPIを使う。Task・Gapの状態遷移は[work_state.py](../../src/forensia/investigation/work_state.py)が適用する。

| API | 処理と書込みの範囲 |
| --- | --- |
| `ensure_task_contract` | 現在の入力を契約としてTraceへ保存する。同一契約は既存の参照を返す。 |
| `prepare_hypothesis_task_contracts` | 既存の未完了Taskに対し、実行開始時の契約を準備する。 |
| `record_settlement_receipt` | ホストの`SettlementDecision`、実行・契約・評価済みEvidenceへの参照をTraceへ記録する。 |
| `evaluate_task_completion` | 保存した契約と成果物を現在のCaseへ照合し、`completed`・`blocked`・`stale`を返す。書込みは行わない。 |
| `record_task_completion` | 照合結果をTraceへ保存する。これだけではTask・Gapの状態を変えない。 |
| `task_contract_summary` | 表示用の概要を読取り専用で返す。 |

`task_contract_summary(db, task_id)`は、保存した契約の参照、入力の現行性、期待する成果物、完了条件、結果の参照と理由を、件数・文字数を限定したdictへ投影する。

[working_state.py](../../src/forensia/investigation/working_state.py)は、各Taskの`contract`へこのdictを加え、モデルに渡すWorking Stateにも表示する。`task_contract_summary`とWorking Stateの生成は読取り専用で、契約やTask状態を作成・更新しない。契約のない旧記録を読んだ場合も、その不足を現在の状態として示す。

概要は表示・計画用の入力であり、完了適用のAPIへ渡す根拠の代わりにはしない。照合する側はTraceの元記録と現在のCaseを参照する。

## 制限と次の拡張

- 外部所有のTaskは契約化までを扱う。所有者の結果を受け付け、検査して完了へ適用する公開経路は未実装である。Coverageの準備だけで外部Taskを完了しない。
- 一般的な前提Taskの連鎖や、任意の作業を複数段へ分解する仕組みはまだない。既存のGap・仮説・必要能力・担当を使う。
- 入力の変更検出は、現在はケース全体の出典・Coverageを含む保守的な方式である。特定のTaskへ影響する変更だけに絞る最適化は、依存関係と再調査コストを測定してから行う。
- `partial`や0件の取得は、そのまま完了の根拠にならない。不在による反証には既存SettlementのCoverage・対象範囲・完全性の条件が必要になる。
- 契約と成果物を追跡できることは、自然文の問いを正しく解釈したことや、調査の正答率向上を保証しない。対象×目的のcoverageや反証作業の選択は[採用方針](artex-adoption.md)に残る候補である。
