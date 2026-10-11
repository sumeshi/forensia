# 開発ガイド

プロジェクトの目的と目指す設計は[README-ja.md](README-ja.md)を参照してください。この文書は開発版の操作、実装を変更する場所、検証手順をまとめます。

## 開発環境

Python 3.14以降とuvを使います。ソースチェックアウトで`uv sync --locked`を実行し、依存関係を揃えてください。ネイティブパーサーの配布wheelと、LLMサーバーを動かすハードウェアは別途必要です。開発依存にはSigma変換用のpySigmaも含みます。

LLM接続は`.env`で設定します。`LLM_BASE_URL`は`/v1`を含まないサーバーのルートURL、`LLM_MODEL`は実際にロードしたモデルIDです。認証が必要なら`LLM_API_KEY`も指定します。調査開始時に設定を検証し、Runtimeへ渡します。

`investigate`はエンドポイントとモデルを必須とします。設定済みのサーバーが利用できない場合は、上限付きの復旧待機に入ります。実験前に接続先と予算を確認してください。

`.env`、入力証拠、ケース、生成物を公開しないでください。Traceにも証拠由来のプロンプトと応答を保存します。依存関係とモデルを事前に用意すれば、ローカルサーバーでの調査はオフライン実行できます。

## CLIと設定

公開CLIは新規調査の`investigate`と既存ケースの`attach`です。ソースチェックアウトでは`forensia`の前に`uv run`を付けてください。オプションの一覧は`uv run forensia investigate --help`、環境変数は[.env.example](.env.example)と[config.py](src/forensia/config.py)を参照します。開発用の健全性確認は`uv run python -m forensia.cli.doctor`で実行します。

```bash
# 新規ケースを開始してTUIへ接続する。
forensia investigate ./input --out ./case001

# Runtimeを背景で起動して端末へ戻る。
forensia investigate ./input --out ./case001 --background

# 停止済みの既存ケースを明示的に置き換える。
forensia investigate ./input --out ./case001 --overwrite

forensia investigate ./input --out ./case001 \
  --system-prompt ./FORENSIA.md --template ./REPORT.md
forensia attach ./case001
```

調査サイクル数やモデルの接続先などの細かな設定は`.env`で管理します。`--out`はケースの保存先です。`--background`はRuntimeを起動して端末へ戻り、`attach`で後から同じケースを開けます。通常起動ではTUIを接続しますが、端末を閉じてもRuntimeは停止しません。保存済みケースを`investigate`へ渡しても再開しません。閲覧や操作には`attach`を使います。入力証拠と明示指定したMarkdown文書はケース外に置いてください。

`attach`のTUIは保存済みケースの状態と進捗イベントを読み取り、Runtimeが動作中なら操作を送ります。`/stop`、`/resume`、`/add <input_dir>`、`/report`、`/report --write`と、通常文のsteeringを入力できます。`/report`は採用済みsectionを表示用に出力し、`/report --write`はsectionを更新して書き込みます。`/detail <kind> <id>`で詳細ウィンドウを開き、長い記録はMoreボタンか`/more`で次ページを読みます。EscapeまたはCloseで閉じます。ログの時刻をクリックすると、そのイベントと参照IDを確認できます。`/older`と`/newer`はイベント履歴を移動し、`/detach`は画面だけを閉じます。F1または`/help`でヘルプウィンドウを開きます。

Evidence、Assessment、reasoning、section、retrieval、LLM call/attemptなどの詳細を、保存済みIDから参照できます。query receiptは一意なreceipt IDで指定します。繰り返し使われる表示用query IDは参照キーにしません。LLM使用量はprovider実測、ローカル推定、不明を分けて表示します。

retrieval eventは予算調整前の文脈選択を記録します。provider attemptの`selected_ids`は実際の送信文に残ったID、`omitted_optional_blocks`は入力予算や接続先の文脈上限により省略したblockです。何を送信したかは、そのattemptのrequest本文から確認します。

停止済みケースでは`/resume`がRuntimeを起動して調査を再開します。`/add`、`/report`、`/report --write`、steeringはRuntimeをアイドル状態で起動してから、その操作だけを送ります。`/stop`は停止済みのままです。Runtimeが接続中に失われた場合、TUIは保存済み状態を表示し、操作を新しいRuntimeへ自動送信しません。再接続するには`attach`を開き直してください。

`--overwrite`はケースの全ファイルを削除して新規作成する操作です。調査中・操作適用中・受付済み操作のあるRuntimeでは拒否します。アイドルのRuntimeは終了させ、ケース外のwriter lockを取得してから削除します。入力ディレクトリとケースディレクトリの重なり、ケースへのシンボリックリンク、manifestのない既存ディレクトリ、現在の作業ディレクトリ自身とその親も削除前に拒否します。

Pythonからも[Runtime API](src/forensia/runtime/__init__.py)の`start_runtime(case_dir, input_dir=...)`と`RuntimeClient(case_dir)`を使えます。`request()`の操作契約は[ipc.py](src/forensia/runtime/ipc.py)が所有します。同じcommand IDの再送は保存済みreceiptを返し、別の内容への使い回しは拒否します。同期スクリプト用の[pipeline.py](src/forensia/pipeline.py)も同じwriter lock、設定検証、検索・判定・報告の所有者を通ります。

## Markdown入力

入力ごとに役割が異なります。操作者の指示、参考知識、報告書の要件はEvidenceにはならず、ホストによる実行検証やSettlementの検査を迂回できません。

### FORENSIA.md: 調査方針

ケースのルートに`FORENSIA.md`を置くか、新規調査時に`--system-prompt <path>`を指定します。エンジンは親ディレクトリや証拠ディレクトリから指示を探しません。

既定の調査では、特定のインシデント種別を仮定しません。ケースの目的と範囲は`FORENSIA.md`に記述してください。

```markdown
# Investigation policy

## Objective
リモートアクセスの後に、無許可の実行が行われたかを確認する。

## Scope
提供されたアーティファクトを使い、欠落したテレメトリーに関する不確実性を残す。

## Priority
調査範囲を広げる前に、リモートログオンとその後のプロセス活動を突き合わせる。

## Constraints
観測された活動と、意図に関する解釈を分ける。
```

本文全体を、Gapの特定、仮説の作成、クエリ計画への指示として使います。英語の`Objective`見出し直下の最初の段落は、既存のobjective admissionへの入力にもなります。`Objective`がなければ`Scope`を使います。他の見出しは指針として扱います。ファイルを編集しても、受け付け済みの作業の撤回、Specの書換え、判定の変更は行いません。

採用時には、本文、SHA-256、入力元、受け取るroleを、Traceの`forensia-md`ステップに保存します。明示指定なしの再開では、ファイルが変わったり消えたりしても記録済みの方針を再利用し、差異を知らせます。ケースルートのファイルを変更しただけでは再採用されません。既存ケースで明示的に採用する場合は、Python APIに`forensia_md`を渡します:

```bash
uv run python -c 'from forensia.pipeline import run_investigation; run_investigation("./case001", forensia_md="./FORENSIA.md")'
```

採用した方針は、そのセッション中は固定されます。初回採用または明示的な再読込みで、設定したシステムプロンプト文字数予算の半分を超える入力は、理由付きで拒否します。Runtimeのsteerも同じ文字数予算を適用します。固定のrole・出力スキーマと、Evidence/Assessment/Sufficiency/Settlementの検査は引き続き適用されます。[case_policy.py](src/forensia/investigation/case_policy.py)を参照してください。

steeringによる方針変更はObjective、Scope、Priority、Constraints、Guidanceのうち、依頼した節の本文だけを更新します。変更対象でない節はホストがそのまま保持し、旧revisionと変更した節をreceiptに記録します。新しい調査要件の追加は、方針の編集とは別に既存のGap/Task admissionを通ります。

### REPORT.md: 報告書仕様

ケースのルートに`REPORT.md`を置くか、新規調査時に`--template <path>`を指定します。既存のsection、Claim、rendererの経路を使います。

```markdown
---
instructions: |
  インシデント対応者向けに書く。証拠参照を示し、観測と解釈を区別し、
  重要な制約を明記する。
---
# 概要

## 評価
証拠が何を裏付けているかと、未確定の解釈を説明する。

# 未解決事項

## 残る調査作業
<!-- mode: table; builder: gaps_unresolved -->

## 追加調査
重要な不確実性を解消するために、次に必要な証拠を示す。
```

各`#`見出しがsectionを、`##`見出しがblockを定義します。任意のfrontmatterの`instructions`は、ファイル内の全sectionに適用されます。メタデータには`type`、`title`、`description`、`tags`、`timestamp`も使えます。実行時の言語は`FORENSIA_OUTPUT_LANGUAGE`で設定します。

少なくとも1つの`#`セクションが必要です。最初のセクションの前に本文を置いたり、正規化後のslugが重複する見出しを使ったりすることはできません。sectionのkeyは見出しの順序と文字列から決まるため、名前や順序の変更は報告書revision内での識別子も変えます。決定論的なblockには、既存のパーサーが`evidence_keypoints`、`mode`、`builder`、`answer_id`、`answer_spec`、`question`のhintを受け付けます。定義は[template_parsing.py](src/forensia/report/sections/template_parsing.py)と[同梱テンプレート](src/forensia/data/report/)にあります。

初回採用時は、`--template`で明示したファイル、ケースのルートにある`REPORT.md`、ケース内の同梱テンプレートの順で使います。明示的な報告書入力には、LLMを使う書込み実行が必要です。編集した仕様を採用する場合:

```bash
forensia investigate ./input --out ./case001 --template ./REPORT.md
```

明示指定なしの再開では、Traceの`report-input`ステップに記録した正規化済みsectionを使い、ファイルの変更を知らせます。通常の`report`は採用済みのsectionを出力します。明示的な再読込み後も古いsectionは保存されますが、有効な報告書からは除外されます。報告書の要件を変えても、調査作業は解決済みになりません。

番号付きMarkdownファイルでsectionを定義し、`_formats/report.yaml`で決定論的な文言とプレビューの上限を設定します。入力の`case001/REPORT.md`と出力の`case001/reports/report.md`は別ファイルです。出力先の検査で入力への上書きを拒否します。[report_input.py](src/forensia/report/sections/report_input.py)を参照してください。

### Knowledge: ローカルの調査知識

Knowledgeの選択APIはfrontmatterに`type: knowledge`を持つMarkdownを索引化します。[knowledge.sample/](knowledge.sample/)に入力例があります。これは公開CLIのオプションではありません。

```markdown
---
type: knowledge
title: リモートアクセスの確認
description: ログオンとその後の活動の相関を調べる。
tags: [windows, logon, rdp]
---
# リモートアクセスの確認

## 相関
レコードを関連付ける前に、host、account、送信元アドレス、時刻を比較する。
```

選択は決定論的に行います。tagと検索語で文書を絞り、プロンプト予算内で関連する`##`セクションを選びます。振り分けのための追加LLM呼出しはありません。ファイルごとに1つの話題を扱い、`description`と`tags`を付けてください。`##`セクションがあるファイルでは冒頭の段落を一緒に渡さないため、必須の前提はdescriptionか各sectionに記載してください。

Knowledgeは参考資料であり、証拠やツールの実行許可ではありません。schema card、SQL recipe、phase playbook、Knowledgeの抜粋は、現在の作業と利用可能なcapabilityに応じて開示します。現在のKnowledge索引は実行ごとにリセットされますが、本文はディスクから遅延読込みされます。FORENSIA.mdとREPORT.mdは採用した内容とrevisionをTraceに保存し、再開時に記録済み内容を再利用します。再現性を調べる実験では、実行中にフォルダを変更しないでください。[external.py](src/forensia/knowledge/external.py)と[retrieval.py](src/forensia/knowledge/retrieval.py)を参照してください。

## 実装の配置

| 場所 | 責務 |
|---|---|
| [pipeline.py](src/forensia/pipeline.py)、[cli/](src/forensia/cli/) | ステージの組立てと、コマンド・表示への適応 |
| [core/](src/forensia/core/)、[db/](src/forensia/db/) | Case/session/verificationの基本要素、保存契約、状態へのアクセス |
| [evidence/](src/forensia/evidence/) | アーティファクトの受付、parse、正規化、識別、無効化 |
| [knowledge/](src/forensia/knowledge/) | ルール実行、catalog読込み、Coverage、Knowledgeの選択 |
| [data/](src/forensia/data/) | packaged schema、SQL rule、playbook、report template、Sigma bundle |
| [investigation/](src/forensia/investigation/) | 作業選択・計画、仮説のライフサイクルと実行、検証gate、report gapの採否 |
| [report/](src/forensia/report/) | 報告書blockの実行と永続化、決定論的な回答、Claims、公開検査、出力、読取り専用の状態表示 |
| [context/](src/forensia/context/) | 両domainが使うprojection、schema/recipe/playbookの開示、予算、retrieval telemetry |
| [llm/](src/forensia/llm/) | 制約付きのモデル通信、応答契約、request縮約、call/attempt telemetry |
| [scripts/sigma/](scripts/sigma/)、[scripts/eval/](scripts/eval/)、[scripts/debug/](scripts/debug/) | 開発用の変換・検証、評価fixtureとツール、parser診断 |

依存検査は `core/db → evidence → knowledge → llm/context → report → investigation → cli/pipeline` の方向を保証します。各層は下位層を利用できます。report生成から調査のadmissionやsettlementを呼びません。domain固有のプロンプトはそれぞれのdomainが所有し、共有projectionは調査判断を行いません。[working_state.py](src/forensia/investigation/working_state.py)はCase/Traceから調査用の文脈を構成し、reportのsection・run・answer storeは`report/`以下でそれぞれのテーブルを所有します。

状態を追加する前に、既存の書込み責務を確認してください。別のagenda、planner、cache、status modelを追加するより、その責務を拡張します。同じ不変条件を守り、同程度の品質が得られるなら、独立した状態、同期経路、モデル呼出しが少ない構成を優先します。[scripts/check_imports.py](scripts/check_imports.py)は依存方向を検査します。互換性のない永続化の変更では、全consumerと現在のスキーマバージョンを一緒に更新します。自動migration/backfillやaliasの維持は行いません。古いケースデータは保全し、必要なら新しいディレクトリへ原本を再取込みしてください。

## 永続化と検証の契約

Evidence、Case State、Trace Stateは`db/case.duckdb`に保存します。EvidenceとCase Stateは`main`、Trace Stateは`trace`スキーマに配置します。関連する更新は同一トランザクションで管理します。Traceには更新されるライフサイクル行と冪等なstep書込みがあり、調査イベントは時系列で追加します。イベントには種類、状態、severity、理由、関連IDを記録し、詳細な検索結果やモデル入出力は元のTrace記録を参照します。表示の再構成にはイベントのcursorを使います。

処理時刻はCaseDBの接続とPythonのwriterでUTCへ統一します。証拠から取得した時刻とそのtimezoneは別に扱い、既存ケースの時刻を推測で補修しません。

Working Stateは作業ごとにDBから直接構成し、生成したMarkdownを再読込みしません。旧ケースの`memory/`には人のメモが含まれ得るため、ケースの保全時にはそのまま残してください。`raw/`はパーサー出力のJSONLであり、取得した原本は別途保存します。通常のFinding保存先はDBです。

Finding候補の識別と提示順は分けます。source・host・時刻・entityの参照を保持し、familyとruleへ提示機会を配分します。既存Gap/Taskも同じ生成枠で扱い、同じ入力・方針で失敗した提案を再開のたびに生成し直しません。配列は文脈上の代表値・総数・省略数として開示し、完全な値はEvidenceから参照します。

context設定は接続先の実上限へ合わせ、出力予約も含めて予算を検査します。上限の自動検出は行いません。候補生成の形式修復・文脈縮約・意味修正は初回生成後の1回の修正枠を共有します。通信障害の復旧待機は別に扱い、変更のないcontext超過リクエストは再送しません。

検索結果のEvidence IDから正規化済みの証拠行を取得し直し、VerificationSpecを満たす証拠の組だけに支持・反証の役割を付けます。SQLの別名や定数、LLMの選んだサンプルは判定の正本にしません。EVTXの共観測条件と、Prefetch・MFT・Registryの型付きfield条件は同じAssessment経路を通ります。Assessmentと根拠リンクには証拠内容・検証条件のidentityを残し、置換後に古い支持を再利用しません。過去の試行は既存Traceから読み、同じ検証条件・証拠状態・検索の繰返しは実行前に制限します。

EVTXの意味付けにはevent ID・channel・providerを使います。未知の文脈のレコードは閲覧できますが、番号だけで既知の活動へ分類しません。PrefetchのDLL参照やMFT時刻差も観測であり、それだけで不正なロードや反フォレンジックを確定しません。

型付きの観測条件で自動確定できるのは、VerificationSpecから導出する観測文だけです。実行痕跡から意図や因果関係まで述べた解釈は未確定に留めます。Prefetchの各実行時刻は同じ原本レコードからの派生であり、別々の独立証拠には数えません。観測条件には原本の`exec_times`などを使い、`min_count`は異なるEvidence IDの数を指定します。

現在の原本件数でも満たせない`min_count`や、対象schemaにない必須entityは、既存のWorkJudgmentで検索前に識別します。仮説を反証せず、理由と再試行条件をGap/Taskへ残します。件数不足は証拠追加後に再判定し、schemaにない列の要求は人間による検証条件の見直し対象とします。`source_file`など原本tableに存在する列は必須entityとして利用できますが、型付き観測条件のfieldとは区別します。

停滞予算を更新するのは、保存されたsource・Coverage、未解決作業、評価済みの観測・矛盾の変化です。confidence差、未採用の提案、文章の変化や検索回数は進捗に数えません。

MFTの`is_deleted`などのBoolean列は、JSONの`true`/`false`を使う`equals`条件で評価します。数値や文字列からBooleanへの変換は行いません。

報告書は採用したREPORTの要求と現在のCase/Evidenceから決定論的な材料を作り、保存してから任意の文章化を行います。Report Engineは独自の計画・検索・判定ループや永続query cacheを持ちません。ClaimはSettlement後の仮説と現在有効な根拠リンクから導出し、Sufficiencyだけで支持済みへ更新しません。JSON/CSVは再生成できる出力です。変更したsectionにつき文章化は最大1回とし、予算切れや停止でも保存済み材料を残します。文章化が既存の品質・引用検査に新しい問題を加える場合は採用せず、保存済み材料を保持します。最終検査で公開不可となった場合はMarkdown・HTMLにも監査状態と停止理由を表示します。報告書の完成、調査の停止、仮説の支持・反証・未確定、最終監査の結果は別の状態です。引用IDが実在することだけでは、文章と証拠の意味的一致までは保証できません。

証拠追加・置換では、標準のMarkdown・HTML・検査JSONを先に失効させ、現在のDBから再出力します。再出力に失敗しても古い成果物を残しません。staleな節の本文はDBに保持し、現在の報告書から除外します。入力の`REPORT.md`・`FORENSIA.md`と、独自の出力先は変更しません。

決定論的な表には検索条件・参照元source・行と本文のhashをsection receiptに保存します。文章化は最初の対象blockに限り、その資料を保持したまま「未確認のモデル解釈」として追記します。引用や表示の診断はreport validationへ残し、証拠不足や追加調査要件だけを調査Gapへ渡します。既定の見出し・表・説明は言語設定へ追従し、ユーザーのREPORT本文は翻訳しません。未使用の`report_brief.json`は出力せず、briefはDBから構成するメモリー上のprojectionとして使います。

通信待ち中の停止要求は受付と適用を分けて表示します。同期HTTPの応答待ちは直ちに中断できず、応答または通信エラー後の安全な境界で停止します。使用量は入力・出力ごとに実測・推定・不明を分け、cycleへ紐付けられない呼出しは評価で未割当として示します。所有者が異常終了した未完了attemptのprovider結果・完了時刻は不明のまま記録します。

sessionの終端receiptを先に保存し、停止・予算切れでも追加のprovider呼出しなしで最新の報告材料を更新します。表示用の更新が失敗しても、終了済みsessionをactiveへ戻しません。

TUIはTextualで構成し、トップにケース名・現在の作業・経過時間、右側のサイドバーにFinding数・仮説status・未完了作業・LLM使用量を表示します。サイドバーの区切り線より下にRuntimeとDBの読取り状況を置きます。中央は端末のローカル時刻を付けたログ、下部は入力欄です。イベントの明示的なseverityに従い、情報は水色、成功は緑、警告は黄、エラーは赤で表示します。長い参照IDやSQLは詳細ウィンドウで確認し、狭い端末では調査情報をログの下に配置します。経過時間は証拠処理runまたは調査sessionの保存済み開始時刻から算出し、終了後は終了時刻で固定します。

Runtimeの表示用読取りは、同じDuckDBの読取り専用MVCCスナップショットを使います。長い書込みの完了を待たず、確定済みの状態と進捗を表示し、未確定の変更は含めません。一回の読取り中は同じスナップショットを保ちます。DBの切替えなどで一時的に`busy`や`timeout`になった場合は、警告色で最後の表示と更新時刻を保持して次の更新を試みます。読取りエラーだけでRuntimeの接続や制御権を捨てず、接続終了・通信エラーの場合にRuntimeを失ったと扱います。

RuntimeへのIPCはPOSIXではUnix domain socket、Windowsではnamed pipeを使います。Windows 10・Python 3.14.5では、配布wheelのdoctorと、実IPC・lock・背景起動・停止・再開・アイドル上書き・異常終了からの復旧・実Prefetch parserによるsource置換・標準レポートの失効と再出力を確認しました。今回のTUI変更はLinuxのheadlessテストで確認し、実際のWindows端末での手動描画と実モデル調査は未検証です。TUIはRuntimeのcontroller claimを取得して操作を送信し、終了時にclaimを解放します。停止済みケースの制御lockもケース外に置き、複数TUIから同時に操作しないようにします。

細かな列、応答形式、判定条件は、次の実行可能な契約を正本にします。

| 変更する対象 | 契約・責務の所在 |
|---|---|
| Case/Traceのテーブル配置とバージョン | [schema.py](src/forensia/db/schema.py)、[database.py](src/forensia/db/database.py) |
| 仮説の検証条件 | [verification.py](src/forensia/core/verification.py) |
| モデルの応答と実行可能なaction | [schemas.py](src/forensia/llm/schemas.py)、[planner.py](src/forensia/investigation/planner.py) |
| 検索の妥当性、条件との照合、支持の十分性、最終判定 | [retrieval.py](src/forensia/context/retrieval.py)、[verification/](src/forensia/investigation/verification/) |
| 作業の選択・停止・再開 | [work_judgment.py](src/forensia/investigation/work_judgment.py)、[work_state.py](src/forensia/investigation/work_state.py) |
| sourceの置換と過去の支持の無効化 | [invalidation.py](src/forensia/evidence/invalidation.py)、[content_identity.py](src/forensia/evidence/content_identity.py) |
| 報告書のsection、Claim、出力の検査 | [report/sections/](src/forensia/report/sections/)、[section_store.py](src/forensia/report/sections/section_store.py) |
| 呼出し、試行、使用量 | [telemetry.py](src/forensia/llm/telemetry.py) |

## ルールと拡張点

ケース固有の回答、event ID、ツール名を汎用Pythonへ埋め込まず、宣言と既存の拡張点を使います。拡張の例は[tests/test_extension_points.py](tests/test_extension_points.py)にあります。

| 変更する対象 | 配置先 |
|---|---|
| アーティファクト種別 | [ArtifactAdapter](src/forensia/evidence/artifacts.py)、parser/normalizer、Coverage、source置換の経路 |
| SQLルール | [data/rules/](src/forensia/data/rules/)、[ルールモデル](src/forensia/knowledge/rules/models.py) |
| フィールド、capability、判定の語彙 | [data/schema/](src/forensia/data/schema/) |
| 構造化した質問 | [question_routing.yaml](src/forensia/data/schema/question_routing.yaml)、[answer_registry.py](src/forensia/report/answers/answer_registry.py) |
| 報告書の表と品質検査 | [table_registry.py](src/forensia/report/answers/table_registry.py)、[quality_gates.py](src/forensia/report/sections/quality_gates.py) |

SQLルールには`confirm_when`、`refute_when`、`evidence_requirements`を持つ仮説を宣言でき、admissionがVerificationSpecへ変換します。抑制設定はケースの`allowlist.yaml`で指定し、Finding生成後にルールIDと証拠行を照合します。Findingと証拠は保持します。

ルールは共通セットです。ケースごとに、対象telemetryがあり検索を終えた`completed`と、対象がなく検索しなかった`not_observed`を区別します。未観測と検索後の0件は別の結果です。

### Sigma bundleの再生成

SigmaHQの原本とfixtureは[submodule](knowledge/sigmahq/)で管理し、revisionは親リポジトリのgitlinkで固定します。lockedな開発依存を使って変換します。

```bash
git submodule update --init knowledge/sigmahq
uv sync --locked
uv run python scripts/sigma/build.py
```

builderはsubmoduleの未変更状態とgitlinkの一致を確認し、変換と検証が完了したbundleをatomicに書き込みます。runtimeは同梱bundleだけを使い、Sigma原本、pySigma、ネットワークを必要としません。

フィールドとtargetの対応は[schema.yaml](scripts/sigma/schema.yaml)、変換は[converter.py](scripts/sigma/converter.py)、検証は[validation.py](scripts/sigma/validation.py)が所有します。一つの原本ルールから、SecurityやSysmonなど複数のtarget bindingを生成する場合があります。

[bundle](src/forensia/data/sigma/sigma_bundle.json)では、変換・SQL検証・fixture検証を別々に記録します。採用条件は、変換とSQL検証の成功、およびfixtureが`passed`、`not_applicable`、`absent`のいずれかであることです。`not_applicable`はfixtureとtargetのtelemetryが異なる場合、`absent`はfixtureの宣言がない場合です。どちらも検出の正しさを確認済みという意味ではありません。

変換したqueryはDuckDBのEXPLAINと実行検査を通します。共通変換の意味論は型付きのsynthetic rowで、fixtureがある場合は宣言された期待件数とEvidence参照で確認します。実行結果から正解を作らず、失敗は理由付きで採用から除外してください。

bundleの`summary`には原本数の`total`、target別件数の`bindings`、採用した原本数の`admitted_rules`とtarget数の`admitted_bindings`を分けて記録します。`by_conversion`、`by_fixture`、`by_target`で内訳を確認できます。個別bindingには原本ID/path、author、変換・検証の理由、採用した実行Ruleが残ります。source、license、依存関係、build入力のhashは再現性確認用です。

再配布するときは、原本のauthor/source参照と[DRL 1.1](src/forensia/data/sigma/SIGMA_LICENSE.txt)を保持します。SigmaHQのlicense noticeはsubmoduleの原本とともに保持してください。


## 検証

開発用チェックアウトで実行します。

```bash
uv run pytest tests/ -q
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts
uv run python scripts/check_imports.py
uv run python scripts/audit_schema_coverage.py --strict
uv run python scripts/regenerate_playbook.py --check
uv run python -m forensia.cli.doctor
```

doctorはインストール済みの宣言、同梱した報告書テンプレート、使い捨てのCase/Traceへの永続化を検査します。ソースチェックアウト、テスト、開発ツールは不要です。CIは上記の開発検査を明示的に実行し、doctorで代替しません。

pytestはオフラインで、使い捨てのケースに対して実行してください。モデル・プロバイダーとの境界をmockし、実際の保存処理、CLIの動作、生成物を確認します。Evidence/provenance、Assessment/Sufficiency/Settlement、実行上限、作業の受付、停止、再開のテストを保持します。各不変条件には主となるテストを1つ定めます。廃止したAPIのテストは削除し、実装の形を固定するだけの定数、SQL文字列、内部counter、文章のassertionを避けてください。実モデルによる品質・性能実験はpytestの外で行います。

宣言を変更した場合は[audit_schema_coverage.py](scripts/audit_schema_coverage.py)を実行します。[regenerate_playbook.py](scripts/regenerate_playbook.py)はYAMLからplaybookの指定部分を再生成し、`--check`でずれを検出します。[cycle_summary.py](scripts/eval/cycle_summary.py)はCase/Traceに記録された指標をsession・cycleごとに表示します。receiptがない値はunknownとして扱います。

## 評価

この実験で問うのは、単純なハーネスが、弱いローカルモデルを呼出し・トークン・時間の予算内で根拠のある結論へ導けるかです。決定論的なテストはソフトウェアの契約を確認します。調査品質と性能には、別途計測が必要です。

公開されている[CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html)を評価用データの1つとして使います。[BENCHMARK.md](BENCHMARK.md)には、選定した問いと参照回答を、製品への指示とは分けた評価資料として置いています。リポジトリにはイメージ、抽出済みの証拠、生成済みケースを配布しません。期待する回答は、モデルのKnowledgeや報告書入力に含めないでください。

比較では、source内容、コード・モデルのrevision、endpoint設定、プロンプト・Knowledge・報告書仕様、予算を固定します。裏付けられた結論と見落とした問い、false positive/false negative、未解決作業、無効・反復した試行、仮説の多様性、コンテキストの重複、呼出し・トークン・時間のコスト、再開動作を記録します。より単純な構成と比較し、正しさの修正とモデル品質の変化を分けてください。モデルのばらつきが差を説明し得る場合は、複数回実行します。

評価スクリプトは現在のCase/Traceをread-onlyで開きます。再現可能な比較には凍結したコピーを使い、評価出力はcaseの外に保存します。

```bash
uv run python scripts/eval/run.py ./case-copy --output ./evaluation.json
uv run python scripts/eval/run.py ./baseline-copy ./after-copy --output ./comparison.json
```

指標は保存済みの状態と実行receiptから取得します。ルールの実行結果、候補の試行、採用先の仮説、query操作、使用量、sessionの停止、Claim参照を区別し、実測tokenとローカル推定を混ぜません。receipt、leadの注釈、処理時間、peak memoryがない値は理由付きunknownです。benign-contextの注釈やClaim参照先の存在は診断情報であり、侵害の正解やfalse positive率ではありません。processの時間とpeak memoryは外部から計測してください。調査品質の改善を示すには、注釈付きの入力と条件を固定したローカルモデルの比較が必要です。

## 変更を提出するとき

README-ja.mdは目的と設計を、CONTRIBUTING.mdは開発操作を説明します。正確なフィールドや内部スキーマはソースを参照し、同じ仕様を複数の文書へ複製しないでください。英語版は日本語本文を固めてから整備します。

PRには、具体的な問題、変更後の挙動、確認した経路と残る制約を記載してください。機密情報を含む実ケースを直接変更せず、凍結したコピーか新しいケースで検証します。互換性のためだけのaliasや旧経路、実装の形を固定するだけのテストは追加しません。
