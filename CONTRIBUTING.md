# 開発ガイド

プロジェクトの目的と目指す設計は[README-ja.md](README-ja.md)を参照してください。この文書は開発版の操作、実装を変更する場所、検証手順をまとめます。

## 開発環境

Python 3.14以降とuvを使います。ソースチェックアウトで`uv sync --locked`を実行し、依存関係を揃えてください。ネイティブパーサーの配布wheelと、LLMサーバーを動かすハードウェアは別途必要です。開発依存にはSigma変換用のpySigmaも含みます。

LLM接続は`.env`で設定します。`LLM_BASE_URL`は`/v1`を含まないサーバーのルートURL、`LLM_MODEL`は実際にロードしたモデルIDです。認証が必要なら`LLM_API_KEY`も指定します。`--llm-base-url`と`--model`は環境変数より優先されます。

エンドポイントとモデルが揃っていなければ、`investigate`は決定論的な証拠処理だけを行います。設定済みのサーバーが利用できない場合は、上限付きの復旧待機に入ります。実験前に接続先と予算を確認してください。

`.env`、入力証拠、ケース、生成物を公開しないでください。Traceにも証拠由来のプロンプトと応答を保存します。依存関係とモデルを事前に用意すれば、ローカルサーバーでの調査はオフライン実行できます。

## 開発版のCLIと設定

READMEの起動例に続けて、以下のコマンドを使います。ソースチェックアウトでは`forensia`の前に`uv run`を付けてください。オプションの一覧は`uv run forensia investigate --help`と`uv run forensia report --help`、環境変数は[.env.example](.env.example)と[config.py](src/forensia/config.py)を参照します。

```bash
# 新規ケースを開始する、または追加の入力を取り込んで調査する。
forensia investigate ./case001 ./input

# 既存ケースと、受け付け済みの調査作業から再開する。
forensia investigate ./case001 --max-iter 50

# 追加アーティファクトを取り込み、次の調査実行で正規化・分析する。
forensia add ./case001 ./new-input
forensia investigate ./case001

# LLMを呼ばず、既存の報告書セクションを出力する。
forensia report ./case001

# LLMで報告書セクションを更新してから出力する。
forensia report ./case001 --write

# 実際のオプション仕様を確認する。
forensia investigate --help
forensia report --help
```

`report --output <path>`はHTMLの出力先を指定します。Markdownの報告書は`case001/reports/report.md`に残ります。`investigate --report-only`は調査を省略し、既存の報告書を出力します。報告書の生成は、仮説の確定や調査完了の宣言を行いません。

| 調査オプション | 既定値・動作 |
|---|---|
| `--max-iter` | 調査サイクル数`20` |
| `--max-queries-per-hypothesis` | 選択した仮説ごとのクエリ数`5` |
| `--no-progress-limit` | 意味上の進展がないサイクル数`3` |
| `--report-every-n-cycles` | `3`。報告書セクションの定期更新間隔 |
| `--report-max-queries-per-section` | `0`なら環境変数の設定を使う |
| `--max-llm-calls` | `0`ならセッションの呼出し上限なし。正の値なら各論理呼出しの前に確認し、コンテキスト縮約や失敗した呼出しも数える |
| `--timezone` | `America/New_York`などのIANA名。ケースのmanifestより優先される |
| `--forensia-md`, `--report-spec`, `--knowledge` | 後述するMarkdown入力の明示指定 |
| `--template-dir` | 既存の報告書ディレクトリ入力。`--report-spec`とは排他的 |
| `--rerun` | 現在のケースのテーブルと生成済みの実行時出力を破壊的にリセットし、保持したrawレコードから再正規化する |

通常の再開ではケース状態を保持します。調査中のCtrl-Cは、エンジンが次に中断を扱う境界での停止を要求します。現在の処理が終わるまで待つ場合があります。セッションは終了理由を記録し、後の`investigate`は永続化された作業から再開します。

再開の判定には、Traceのステージreceiptと、有効なsourceの正規化状態を使います。パーサー実装や依存関係が変われば正規化を、ルール定義やケースの抑制設定が変われば分析を再実行します。sourceの状態が欠落または失敗している場合、正規化の完了条件を満たしません。

`--rerun`は、対応するスキーマのケース内で調査をやり直す機能です。正規化済みの状態、調査・報告書の状態、入力採用receiptを消去し、有効なsource登録、rawレコード、Memoryを保持します。現在のスキーマバージョンは**7**です。非対応のスキーマは移行せず拒否し、`--rerun`でも更新できません。このバージョンではparserのrawレコード契約も変わったため、以前のケースから移行する場合は新しいケースを作り、取得済みの原本を再取込みしてください。

## Markdown入力

入力ごとに役割が異なります。操作者の指示、参考知識、報告書の要件はEvidenceにはならず、ホストによる実行検証やSettlementの検査を迂回できません。

### FORENSIA.md: 調査方針

ケースのルートに`FORENSIA.md`を置くか、ケースの開始・再開時に`--forensia-md <path>`を指定します。エンジンは親ディレクトリや証拠ディレクトリから指示を探しません。

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

採用時には、本文、SHA-256、入力元、受け取るroleを、Traceの`forensia-md`ステップに保存します。明示指定なしの再開では、ファイルが変わったり消えたりしても記録済みの方針を再利用し、差異を知らせます。編集を明示的に採用する場合:

```bash
forensia investigate ./case001 --forensia-md ./case001/FORENSIA.md
```

採用した方針は、そのセッション中は固定されます。初回採用または明示的な再読込みで、設定したシステムプロンプト文字数予算の半分を超える入力は、理由付きで拒否します。固定のrole・出力スキーマと、Evidence/Assessment/Sufficiency/Settlementの検査は引き続き適用されます。[case_policy.py](src/forensia/investigation/case_policy.py)を参照してください。

### REPORT.md: 報告書仕様

ケースのルートに`REPORT.md`を置くか、`investigate`または`report --write`に`--report-spec <path>`を指定します。既存のsection、Claim、rendererの経路を使います。

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

初回採用または明示的な再読込みでの優先順位は、明示した`--report-spec`、明示した`--template-dir`、ケースのルートにある`REPORT.md`、ケース内の同梱テンプレートの順です。明示的な報告書入力には、LLMを使う書込み実行が必要です。編集した仕様を採用する場合:

```bash
forensia report ./case001 --write --report-spec ./case001/REPORT.md
```

明示指定なしの再開では、Traceの`report-input`ステップに記録した正規化済みsectionを使い、ファイルの変更を知らせます。通常の`report`は採用済みのsectionを出力します。明示的な再読込み後も古いsectionは保存されますが、有効な報告書からは除外されます。報告書の要件を変えても、調査作業は解決済みになりません。

現在はディレクトリ形式の入力も利用できます。

```bash
forensia templates-export ./my-templates
forensia report ./case001 --write --template-dir ./my-templates
```

番号付きMarkdownファイルでsectionを定義し、`_formats/report.yaml`で決定論的な文言とプレビューの上限を設定します。入力の`case001/REPORT.md`と出力の`case001/reports/report.md`は別ファイルです。出力先の検査で入力への上書きを拒否します。[report_input.py](src/forensia/report/sections/report_input.py)を参照してください。

### Knowledge: ローカルの調査知識

`--knowledge`でディレクトリを渡します。[knowledge.sample/](knowledge.sample/)に例があります。frontmatterに`type: knowledge`を持つMarkdownだけを索引化します。

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

```bash
forensia investigate ./case001 --knowledge ./knowledge.sample
```

選択は決定論的に行います。tagと検索語で文書を絞り、プロンプト予算内で関連する`##`セクションを選びます。振り分けのための追加LLM呼出しはありません。ファイルごとに1つの話題を扱い、`description`と`tags`を付けてください。`##`セクションがあるファイルでは冒頭の段落を一緒に渡さないため、必須の前提はdescriptionか各sectionに記載してください。

Knowledgeは参考資料であり、証拠やツールの実行許可ではありません。schema card、SQL recipe、phase playbook、Knowledgeの抜粋は、現在の作業と利用可能なcapabilityに応じて開示します。現在のKnowledge索引は実行ごとにリセットされますが、本文はディスクから遅延読込みされます。FORENSIA.mdやREPORT.mdのような、**記録済みrevisionを再開時に再利用する契約はまだありません**。再現性を調べる実験では、実行中にフォルダを変更しないでください。[external.py](src/forensia/knowledge/external.py)と[retrieval.py](src/forensia/knowledge/retrieval.py)を参照してください。

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

依存検査は `core/db → evidence → knowledge → llm/context → report → investigation → cli/pipeline` の方向を保証します。各層は下位層を利用できます。report生成から調査のadmissionやsettlementを呼びません。domain固有のプロンプトはそれぞれのdomainが所有し、共有projectionは調査判断を行いません。Memoryのファイル操作は`core/memory.py`が所有し、reportのsection・run・answer storeは`report/`以下でそれぞれのテーブルを所有します。

状態を追加する前に、既存の書込み責務を確認してください。別のagenda、planner、cache、status modelを追加するより、その責務を拡張します。同じ不変条件を守り、同程度の品質が得られるなら、独立した状態、同期経路、モデル呼出しが少ない構成を優先します。[scripts/check_imports.py](scripts/check_imports.py)は依存方向を検査します。互換性のない永続化の変更では、全consumerと現在のスキーマバージョンを一緒に更新します。自動migration/backfillやaliasの維持は行いません。古いケースデータは保全し、必要なら新しいディレクトリへ原本を再取込みしてください。

## 永続化と検証の契約

証拠とCase Stateは`db/case.duckdb`、実行履歴は`db/trace.duckdb`に保存します。ケースを保存・コピーするときは両方を保持してください。CaseDBがTraceをattachし、同じ接続から参照します。Traceには更新されるライフサイクル行と冪等なstep書込みがあり、progressには保持件数の上限があります。

`memory/`にはDBから生成する情報に加え、人が書いたメモも含まれます。ケースを保全するときはMemoryも残してください。`raw/`はパーサー出力のJSONLであり、取得した原本は別途保存します。通常のFinding保存先はDBです。

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
uv run forensia doctor
```

`doctor`と`templates-export`は、トップレベルのhelpには表示しない保守用コマンドです。doctorはインストール済みの宣言、同梱した報告書テンプレート、使い捨てのCase/Traceへの永続化を検査します。ソースチェックアウト、テスト、開発ツールは不要です。CIは上記の開発検査を明示的に実行し、doctorで代替しません。

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
