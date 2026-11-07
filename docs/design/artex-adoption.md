# ARTEX由来の設計の採用方針

## 目的と判断の基準

FORENSIAは、小型のローカルLLMが、証拠を見つけ、仮説を検証し、長時間の調査を一貫して進めるためのハーネスを目指す。モデルや推論基盤が変わったときにも、調査状態、証拠の意味、作業の完了条件を保ったまま実装を交換できることを重視する。

この文書は`develop`の既存構成と、[調査履歴の共有](investigation-history.md)、[Taskの完了契約](task-contracts.md)で実装した範囲を基準に、次に採用する設計を整理する。実装範囲と追加候補を区別し、実調査での性能改善は別に測定する。

採用の判断には、次の三点を使う。

- 調査の問い、次の作業、その結果の関係が、モデルの会話を読み直さずに分かること。
- 検索経験を引き継いでも、根拠の独立性、対象範囲、証拠の現行性を維持できること。
- 同じ証拠と予算で、重複作業、未解決の問い、誤った結論、所要時間を比較できること。

## 資料の位置付け

### 開発者による一次の設計説明

[Autumn-27によるARTEX紹介](https://github.com/ruanyf/weekly/issues/10911)（2026-07-28 JST、著者Autumn-27）を全文確認した。目標に沿った計画と実行の循環、対象とタスクに結び付いたカバレッジ、構造化概要と必要時の実行履歴取得、複数経路の維持、重要な発見への対抗的な再確認が説明されている。

これは開発者が意図した構成の説明であり、各機構の効果を独立に測った結果ではない。FORENSIAへの採用では、[FORENSIA開発者の記事](https://sumeshi.github.io/posts/works/do-localllms-dream-of-forensic-investigator-2)（2026-10-18）の、ローカル完結、モデルの誤りを前提とする制御、時間をかけて検証を進める方針へ接続する。

### コミュニティの不具合報告

[ツール名不一致の報告](https://github.com/jiwoochris/artex-global/issues/19)（2026-10-10、著者Damin-Lee）を全文確認した。投稿者は、隔離した環境の2タスク・8セッションで279回のツール呼出し中141回が名称不一致で拒否されたと報告している。この数値は投稿者の実行記録であり、FORENSIAで再現した結果ではない。

この事例は、名称・入力・利用可能な能力を実行側の契約として扱い、拒否を観測可能な失敗にし、復旧を有限にする理由になる。FORENSIAに同じ不具合が存在するという根拠にはしない。

### 未実装の設計提案

[Evidence assuranceとcoverage provenanceの議論](https://github.com/jiwoochris/artex-global/issues/47)（2026-10-18 JST、著者jsr1234567）を全文確認した。報告された発見と独立に再現された発見、探索した対象と十分に検証した範囲を分け、証拠の版と依存関係に基づいて再検証する提案である。比較ベンチマーク未実施と明記されているため、ARTEXの実装済み機能や実証済みの改善として扱わない。

ARTEXの元リポジトリは非公開であり、公開ミラーの調査結果を現在の公式実装と同一とはみなさない。一般検索エンジンへのアクセスは通信制限で失敗した。ここでの外部情報は、全文を確認できた公開記事とGitHub上の文章資料に基づく。各投稿が参照する外部資料まで確認したとは主張しない。

## 採用候補の比較

優先度は、P0を今回の実装範囲、P1を次の設計・実装候補、P2を前提の整備と効果測定を経て追加する候補とする。

| 候補と優先度 | 既存実装と残る差分 | 採用理由 | 具体的な接続先 |
| --- | --- | --- | --- |
| **履歴共有：P0、今回実装** | 現在の仮説の直近試行に加え、同一ケース内の別仮説・以前のセッションの検索試行を、概要検索と限定的な詳細取得で提示する。検索結果・Assessment・判定の自動再利用は行わない。 | Findingにならなかった観測や失敗から、次の検索の手がかりを回収する。元の記録へ戻れる参照と有限な入力予算を維持する。 | [trace_history.py](../../src/forensia/investigation/trace_history.py)、[prompts.py](../../src/forensia/investigation/prompts.py)、[prompt_context.py](../../src/forensia/context/prompt_context.py)、既存のretrieval telemetry。詳細は[実装文書](investigation-history.md)。 |
| **Taskの完了契約：P0、今回実装** | 通常の仮説検証・停止由来・外部所有のTaskへ、入力の版、期待成果物、完了条件を既存Traceで結び付ける。検証Taskは正式なSettlement成果物を現在の契約と照合して閉じる。一般的な前提Taskの連鎖と外部所有者の結果受付は未実装。 | 作業の完了を検索成功やモデルの自己申告から切り離し、モデルや実行手段を交換しても成果物の条件を保つ。 | [task_contracts.py](../../src/forensia/investigation/task_contracts.py)、[work_state.py](../../src/forensia/investigation/work_state.py)、[hypothesis_runner.py](../../src/forensia/investigation/hypotheses/hypothesis_runner.py)、[working_state.py](../../src/forensia/investigation/working_state.py)。保存・API・制限は[完了契約の文書](task-contracts.md)。 |
| **対象×目的のcoverage：P1、未実装** | 既存Coverageは取り込めた証拠と検証能力を示す。個々の問いについて、どの対象・期間・条件を調べ、何が未検証かを一貫して列挙する投影には拡張の余地がある。 | 「証拠が利用できる」「検索を実行した」「要求を満たした」を分け、調査漏れと再開箇所を説明できるようにする。 | [knowledge/coverage.py](../../src/forensia/knowledge/coverage.py)の能力宣言、Gap/Task、[ToolReceipt](../../src/forensia/context/retrieval.py)、[Assessment](../../src/forensia/investigation/verification/assessment.py)、[Settlement](../../src/forensia/investigation/verification/settlement.py)、報告書への投影。 |
| **競合説明・反証の作業選択：P1、未実装の拡張** | `alternative_to`等の仮説関係、反証条件、矛盾の検査は存在する。選択時の情報利得は主に代替仮説の本数を使う代理値で、どの観測が説明を区別するかまでは表していない。 | 支持する証拠の追加だけに偏らず、誤りを減らしながら答えられる問いを増やす。重要な結論の再確認を、既存の作業選択へ載せる。 | [hypotheses/relations.py](../../src/forensia/investigation/hypotheses/relations.py)、[selection.py](../../src/forensia/investigation/selection.py)、VerificationSpec、既存のAssessment / Sufficiency / Settlement、[反証評価](../../scripts/eval/refutation.py)。 |
| **状態変化を起点とする計画：P2、未実装の拡張** | WorkJudgmentを使った実行可否・停止・再開の共通判断と、意味のある進捗の検査は存在する。変更の種類と影響する作業を明示し、再計画の入力を差分中心にする余地がある。 | 証拠追加、必要能力の利用可能化、指示変更、前提作業の完了に応じて、関係する作業を選び直す。状態が変わらない間の再計画を減らす。 | [work_judgment.py](../../src/forensia/investigation/work_judgment.py)、[work_state.py](../../src/forensia/investigation/work_state.py)、[investigation_cycle.py](../../src/forensia/investigation/investigation_cycle.py)、[working_state.py](../../src/forensia/investigation/working_state.py)、既存の変更・進捗記録。 |
| **段階的な能力開示：P2、未実装の拡張** | VerificationSpecと共通の能力カタログから、開示するテーブル・schema・recipeを選ぶ仕組みは存在する。能力の発見から必要な詳細を取得する過程や、選択方針を比較できる契約には拡張の余地がある。 | 証拠種別や実行手段が増えても、一度の入力とモデルの選択肢を限定する。新しいツールの追加が計画・検証の全面改修にならないようにする。 | [capability_disclosure_tables / disclosure_tables_for_spec](../../src/forensia/knowledge/coverage.py)、[sql_schema.py](../../src/forensia/context/sql_schema.py)、[playbook.py](../../src/forensia/context/playbook.py)、[prompt_context.py](../../src/forensia/context/prompt_context.py)、同じ能力宣言を読むWorkJudgment。 |

## 次の設計を具体化する順序

### 1. 固定した完了条件を、次の作業分解に使う

今回の契約は、仮説・Gap、入力のrevisionとVerificationSpec、期待する成果物・完了条件を参照できる形にした。正式なSettlementの結果を成果物として照合し、証拠の失効では関連TaskとGapも再開する。条件の意味は既存の評価処理に保ち、Working Stateの読取りでは契約を作成・更新しない。

次の拡張は、親の問いを入力と成果物の明確な有限の作業へ分け、前提となるTaskを明示することである。例えば「あるファイルの移動を調べる」なら、対象の同一性、必要な時刻・関係、競合説明を別々に確認する。こうした一般的な作業分解はまだ実装していない。個々の検証Taskが完了しても、親のQuestion Gapは既存の専用条件を満たすまで未解決のまま残す。現在の検証言語で表せない条件は、評価器を追加する独立した設計課題として扱う。

実行可否はWorkJudgment、状態の書込みはwork_state、証拠の採用は既存の評価経路に保つ。前提が変わったときも、同じ判断を選択・保留・再開で使う。

### 2. 対象と目的に対する調査範囲を投影する

最初は、既存のGap/Task、検索Receipt、評価結果から、対象・調査目的・期間・必要能力・入力のrevisionをキーとする読取り用の投影を作る。状態は少なくとも、未着手、観測可能な範囲で実行済み、途中、ブロック、評価済みを区別する。独立した正本は作らない。

対象の一覧や必要条件が定義できないときは、coverageの分母を不明として示す。検索したテーブル数、返却行数、ツールの成功回数から調査の完了率を作らない。0件の結果は、その時点の対象範囲・Coverage・取得の完全性とともに残し、不存在の採用はSettlementが判断する。

この投影は、ARTEXのAsset Graphから着想を得たFORENSIA向けの拡張である。対象と問いの関係は、まず既存DBの参照と投影で表現する。

### 3. 説明を区別できる作業を選ぶ

競合する仮説の本数から、どの未充足条件や矛盾を調べれば説明を区別できるかへ、優先度の根拠を具体化する。対象が異なる証拠の混同や、時刻の近さだけによる因果の推定を避けるため、同一性・時間・関係の条件を評価可能な形で保持する。

反証や再確認の作業も通常のTask、SQL検証、Assessment、Sufficiency、Settlementを通す。複数モデルの一致や、同じ原本を再検索した回数は独立した裏付けとして数えない。選択の理由には、区別したい条件と既知の実行コストを残す。現在の一律のコスト値を実測値へ置き換える場合も、測定値がない作業を不当に後回しにしない。

### 4. 変更に応じた選択と能力開示を整える

前の段階で入力と依存関係が明確になった後、証拠・Coverage・方針・前提作業の変化を、影響するTaskの再評価へ接続する。変更が起きるたびにLLMを呼ぶ構成にはしない。ホストがWorkJudgmentと既存の選択処理を使い、実行可能な作業と必要な文脈を作り直す。

能力開示も同じ宣言に基づく。開示した能力は実行側でも検査し、モデルに見えなかった能力や名前を曖昧に補って実行しない。能力が使えない場合は、理由と必要な前提を保存する。実行手段やモデルを交換しても、この契約と失敗の分類を維持する。

## 維持する責務

調査全体を管理する正本はCase、何を実行してどう評価したかはTrace、現在の作業へ渡す投影はWorking Stateに置く。履歴の概要や将来の圧縮表現は再生成可能な入力であり、元の証拠を置き換えない。

証拠はEvidence IDから現行の正規化レコードを参照し、Assessmentで条件との対応を確認し、Sufficiencyで十分性と独立性を検査し、Settlementで正式な判定を確定する。ARTEXのFactやGoalという名称だけで、モデル由来の説明をこの経路へ通さず確定しない。

追加する作業管理、coverage投影、再計画、能力開示は、既存のWorkJudgmentと一つの選択・状態遷移へ接続する。報告書のための別の探索ループ、独立したメモリDB、グラフサーバーを前提にせず、ローカルの同じ保存契約から構成する。

## 効果の確認と採用条件

今回の履歴共有は、同一ケースの関連試行へ到達し、有限な予算で通常のquery plannerへ渡す範囲である。Taskの完了契約は、通常の検証と停止・外部作業の契約化、正式なSettlement成果物の照合、証拠失効時の再開を扱う。外部所有者の結果受付、一般的なTask依存関係、対象×目的のcoverage、反証を区別する選択の改善は残る。

検索結果のキャッシュ、自動的な判定再利用、ケースをまたぐ学習、一般的な探索グラフ、hot/cold圧縮も実装範囲に含めていない。

各候補は一つずつ、同じ証拠revision・モデル・入力予算・実行予算で比較する。既存のテストで保存・検索・失効・停止・再開の契約を確認し、実調査では次を併せて測る。

- 重複した検索、失敗した呼出し、無進捗の再計画の回数。
- 根拠付きで解決した問いと、未解決を正しく残した問い。
- 根拠の不足した確定、古い証拠の採用、独立性の二重計上。
- 入出力token、最大文脈量、所要時間、再開までの時間。

実装したことと有効だったことを分けて記録する。誤った結論を増やさず、解決できる問いや重複作業に改善が確認できた範囲で採用を広げる。本文で説明したP1・P2の候補に、現時点の性能改善を主張しない。
