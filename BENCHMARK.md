# CFReDS evaluation reference

Source: https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html

This file preserves the project's selected evaluation questions and reference
answer notes. General measurement guidance lives in [CONTRIBUTING.md](CONTRIBUTING.md#評価).
The original source owns the scenario, acquisition details, and full question set.
Obtain images and artifacts there; they are not distributed in this repository.

These 12 questions define the selected scope, not a claim that the current
artifact support can answer every question. The other original questions are
outside this score. Missing evidence should be recorded as unavailable rather
than guessed. Record partial-credit and timezone assumptions when scoring:
several reference notes below give lists or approximate dates rather than a
complete row-by-row expected output.

Keep these expected answers out of investigation prompts, Knowledge files, and
report templates used as model input. They are evaluation material, not runtime
forensic knowledge.

## 実行と採点

実行用入力と採点資料を分けます。この`BENCHMARK.md`全体を`--system-prompt`や`--template`へ渡さないでください。

以下の`examples/`はGit管理外のローカル作業ディレクトリです。チェックアウトには含まれないため、[Markdown入力の説明](CONTRIBUTING.md#markdown入力)に沿って調査方針と報告書仕様を用意し、CFReDS用コピーには下記の質問だけを追記します。

| 用途 | ファイル |
| --- | --- |
| 汎用の調査方針と報告書の雛形 | `examples/investigation/`の`FORENSIA.md`、`REPORT.md` |
| 汎用雛形に12問を追記した実行用コピー | `examples/cfreds/`の`FORENSIA.md`、`REPORT.md` |
| 質問・参照解答・採点条件 | このファイル。実行後の評価者だけが参照する |

CFReDS用コピーは、汎用雛形の本文を維持したうえで質問を末尾に追加しています。
質問の出典は下記の`Scored questions`です。既知のユーザー名、正解のパス、ツール名などを参照解答から追加しません。
調査方針は計画側へ、レポート仕様は報告側へ渡るため、質問を両方へ明記しています。
本文中の「上記で特定したタイムゾーン」は、証拠から確認する前提条件です。確認できなければ不明とし、Q13を完全回答に数えません。

取得済みの入力を`sample/cfreds`に置き、既存ケースと異なる出力先で実行します。

```bash
uv run forensia investigate sample/cfreds --out dist/cfreds-benchmark-01 --system-prompt examples/cfreds/FORENSIA.md --template examples/cfreds/REPORT.md
```

バックグラウンド実行なら同じコマンドに`--background`を追加し、`uv run forensia attach dist/cfreds-benchmark-01`で接続します。
モデルと予算は`.env`で設定します。実行ごとに出力先を変え、採点するまで元ケースを上書きしません。
雛形は自動同期される設定ではなく、実行時に明示指定するファイルです。比較する実行では、同じ入力revisionを使ってください。

終了後は`reports/report.md`の質問欄と、`reports/structured/`に出力される質問別JSON/CSVを確認します。
同ディレクトリはケース内の生成物です。正解や採点結果を書き戻さず、評価者の記録はケース外へ置きます。
保存済みCase/Traceの計測には、既存の評価スクリプトを使えます。

```bash
uv run python scripts/eval/run.py ./cfreds-benchmark-01-copy --output ./cfreds-benchmark-01-metrics.json
```

`cfreds-benchmark-01-copy`は、終了を確認してから作ったケース全体の凍結コピーです。このスクリプトは呼出し・token・停止理由などを取得し、12問の正誤は採点しません。

各問の採点は次の表で残します。

| 質問ID | 評価 | 回答できた範囲 | 証拠・出典クエリ | 未達の理由 | 回答の生成元 |
| --- | --- | --- | --- | --- | --- |
| Q6など | 完全回答 / 部分回答 / 未回答 / 誤答 | 実際の回答と不足項目 | 追跡できる参照 | 証拠不足 / 未調査 / 処理未対応 / モデル出力 / その他 | 定型抽出 / モデル解釈 |

- 完全回答は、要求された範囲を満たし、根拠を追跡できる回答です。正解の文字列だけ一致しても、根拠がなければ完全回答にしません。
- 部分回答は、正しく裏付けられた一部の回答です。不足項目と、誤った断定があればその内容も記録します。
- 未回答には、根拠を得られず判断を保留した場合も含め、理由を区別します。証拠不足を理由に分母から除外しません。
- 誤答は、証拠や参照解答に反する回答、または根拠のない断定です。候補と明記されたものを、確定した誤答と混同しません。

主要指標は「完全回答数 / 12」、部分回答数、未回答数、誤答数、所要時間です。
複合問題の部分点は、必要なら実行前に配点を固定します。現在の参照解答はQ12の全実行時刻・回数やQ28の全時刻を網羅していないため、このファイルだけで厳密な自動採点はできません。
時刻を比較するときはUTC offset・夏時間・対象日と、shutdown要求／ログサービス停止などのイベントの意味を確認します。

### 現在の評価上の制約

12問は既存の質問分類・定型検索に対応しています。定型抽出による得点と、モデルが追加調査・解釈で得た成果を分けて記録してください。
`answered`などの自動状態や、レポート全体の`complete`は採点結果ではありません。行が返っても、期間、必要項目、証拠の意味まで質問に一致するかを確認します。
特に現在の日次時系列builderは時間条件を見出しから読み、UTCで絞り込みます。質問本文の現地09:00–18:00が正しく適用されたとは限りません。改名候補やアンチフォレンジックの定型結果も、質問の日付条件との照合が必要です。
入力は質問の条件を維持し、実装に合わせて問いを易しくしたり、参照解答から検索条件を足したりしません。
CFReDSの得点だけを目的に製品へ専用ロジックを増やさず、他のケースでも同じ採点方法を使います。

## Scored questions

1. Original Q6. What is the computer name?
2. Original Q8. Who was the last user to log on to the PC?
3. Original Q9. When was the last recorded shutdown date/time?
4. Original Q12. List application execution logs.
   - executable path
   - execution time
   - execution count
5. Original Q13. List all traces related to system startup/shutdown and user logon/logoff.
   - Consider only the time range between 09:00 and 18:00 in the timezone identified above.
6. Original Q14. What web browsers were used?
7. Original Q19. What application was used for e-mail communication?
8. Original Q20. Where is the e-mail file located?
9. Original Q24. Identify all traces related to renaming files on the Windows Desktop.
   - Consider only the date range between 2015-03-23 and 2015-03-24.
   - Hint: the parent directories of renamed files were deleted and their MFT entries were also overwritten, so full paths may not be recoverable.
10. Original Q25. Find traces related to cloud services on the PC.
    - service name
    - log files
11. Original Q28. Identify all timestamps related to a resignation file on the Windows Desktop.
    - Hint: the resignation file is a DOCX file in the NTFS file system.
12. Original Q45. What actions were performed for anti-forensics on the PC on the last day, 2015-03-25?

## Reference answers

1. Original Q6. Computer name:
   - INFORMANT-PC

2. Original Q8. Last logged-on user:
   - informant

3. Original Q9. Last shutdown:
   - 2015-03-25 11:31:05 Eastern Time + DST

4. Original Q12. Application execution logs:
   - IE11 installer
   - googledrivesync.exe
   - icloudsetup.exe
   - GoogleUpdate.exe
   - EXCEL.EXE
   - POWERPNT.EXE
   - SOLITAIRE.EXE
   - StikyNot.exe
   - CHROME.EXE
   - OUTLOOK.EXE
   - wmplayer.exe
   - Eraser installer
   - ccsetup504.exe
   - Eraser.exe
   - CCLEANER64.EXE
   - GoogleDriveSync.exe
   - iexplore.exe
   - WINWORD.EXE
   - xpsrchvw.exe

5. Original Q13. System on/off and logon/logoff:
   - 2015-03-22: startup, logons, logoff, shutdown
   - 2015-03-23: startup/logon at 13:24, additional logons, logoff/shutdown at 17:02
   - 2015-03-24: startup/logon at 09:21, multiple logons, logoff/shutdown at 17:07
   - 2015-03-25: startup/logon at 09:05, multiple logons

6. Original Q14. Web browsers:
   - Microsoft Internet Explorer 11.0.9600.17691
   - Google Chrome 41.0.2272.101

7. Original Q19. E-mail application:
   - Microsoft Outlook 2013

8. Original Q20. E-mail file:
   - `C:\Users\informant\AppData\Local\Microsoft\Office\iaman.informant@nist.gov.ost`

9. Original Q24. Desktop file renames:
   - `[secret_project]_detailed_proposal.docx` -> `landscape.png`
   - `[secret_project]_design_concept.ppt` -> `space_and_earth.mp4`
   - `(secret_project)_pricing_decision.xlsx` -> `happy_holiday.jpg`
   - `[secret_project]_final_meeting.pptx` -> `do_u_wanna_build_a_snow_man.mp3`
   - `[secret_project]_detailed_design.pptx` -> `winter_whether_advisory.zip`
   - `[secret_project]_revised_points.ppt` -> `winter_storm.amr`
   - `(secret_project)_market_analysis.xlsx` -> `new_years_day.jpg`
   - `(secret_project)_market_shares.xls` -> `super_bowl.avi`
   - `(secret_project)_price_analysis_#1.xlsx` -> `my_favorite_movies.7z`
   - `(secret_project)_price_analysis_#2.xls` -> `my_favorite_cars.db`
   - `[secret_project]_progress_#1.docx` -> `my_smartphone.png`
   - `[secret_project]_progress_#2.docx` -> `new_year_calendar.one`
   - `[secret_project]_progress_#3.doc` -> `my_friends.svg`
   - `[secret_project]_detailed_proposal.docx` -> `a_gift_from_you.gif`
   - `[secret_project]_proposal.docx` -> `diary_#1d.txt`
   - `[secret_project]_technical_review_#1.docx` -> `diary_#1p.txt`
   - `[secret_project]_technical_review_#1.pptx` -> `diary_#2d.txt`
   - `[secret_project]_technical_review_#2.docx` -> `diary_#2p.txt`
   - `[secret_project]_technical_review_#2.ppt` -> `diary_#3d.txt`
   - `[secret_project]_technical_review_#3.doc` -> `diary_#3p.txt`

10. Original Q25. Cloud service traces:
   - Google Drive
   - Apple iCloud
   - Google Drive logs/config/db under `C:\Users\informant\AppData\Local\Google\Drive\user_default\`
   - Google Drive sync folder/account artifacts

11. Original Q28. Resignation file timestamps:
   - File: `Resignation_Letter_(Iaman_Informant).docx`
   - Created/modified/opened on 2015-03-24 and 2015-03-25
   - Opened on 2015-03-25 11:24

12. Original Q45. PC anti-forensics on 2015-03-25:
   - Searched anti-forensic tools, Eraser, CCleaner
   - Downloaded Eraser and CCleaner
   - Installed Eraser and CCleaner
   - Ran Eraser
   - Wiped `C:\Users\informant\Desktop\Temp\`
   - Emptied Recycle Bin
   - Shift-deleted Eraser/CCleaner installers
   - Ran CCleaner
   - Uninstalled CCleaner
   - Signed out of Google Drive
   - Deleted Google Drive `sync_config.db` and `snapshot.db`
   - Deleted some Outlook e-mails
