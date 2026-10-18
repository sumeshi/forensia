# CFReDS evaluation reference

Source: https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html

This file preserves the project's selected evaluation questions and reference
answer notes. General measurement guidance lives in
[CONTRIBUTING.md](../../CONTRIBUTING.md#評価) (Japanese).
Obtain the original scenario, acquisition details, full question set, and evidence
from the source above. Evidence images and artifacts are not distributed here.

These 12 questions define the evaluation scope. They do not imply that current
artifact support can answer every question. Other questions from the original
case are outside this score. Record unavailable evidence rather than guessing.
Some reference notes list applications or approximate dates without enumerating
all expected rows, so record partial-credit and timezone assumptions explicitly.

Keep reference answers out of investigation policies, Knowledge files, and report
specifications supplied to the model. Do not pass this file to `--system-prompt`
or `--template`.

## Running and scoring

Run commands from the repository root. The shared inputs are:

| Purpose | Investigation policy | Report specification |
| --- | --- | --- |
| General investigation | [FORENSIA.md](../../examples/investigation/FORENSIA.md) | [REPORT.md](../../examples/investigation/REPORT.md) |
| CFReDS: general inputs plus 12 questions | [FORENSIA.md](../../examples/cfreds/FORENSIA.md) | [REPORT.md](../../examples/cfreds/REPORT.md) |

The CFReDS inputs retain the general guidance and append only the questions below.
They do not add known usernames, answer paths, or tool names from the reference
answers. Questions appear in both inputs because the policy guides investigation
planning while the report specification guides reporting. Establish the timezone
from evidence; if it remains unknown, do not count Q13 as fully answered.

Place acquired evidence under `sample/cfreds` and use a new output directory:

```bash
uv run forensia investigate sample/cfreds --out dist/cfreds-benchmark-01 --system-prompt examples/cfreds/FORENSIA.md --template examples/cfreds/REPORT.md
```

Add `--background` to run without the TUI, then connect with
`uv run forensia attach dist/cfreds-benchmark-01`. Configure the model and budgets
in `.env`. Use a different output directory for each run and preserve the original
case until scoring is complete. Inputs are selected explicitly at startup, not
automatically synchronized. Compare runs using the same input revision.

After completion, review the question sections in `reports/report.md` and the
question-specific JSON/CSV exports under `reports/structured/` within the case.
Do not write expected answers or scores back into the case. Keep evaluator notes
outside it.

For Case/Trace measurements, confirm the run has stopped and make a frozen copy
of the entire case before running:

```bash
uv run python scripts/eval/run.py ./cfreds-benchmark-01-copy --output ./cfreds-benchmark-01-metrics.json
```

This script measures calls, tokens, stop reasons, and related execution data. It
does not grade the 12 answers. Record question-level judgments separately:

| Question ID | Grade | Answer coverage | Evidence and source queries | Reason for shortfall | Answer origin |
| --- | --- | --- | --- | --- | --- |
| Q6, etc. | Full / Partial / Unanswered / Incorrect | Supported answer and missing items | Traceable references | Missing evidence / Not investigated / Unsupported processing / Model output / Other | Deterministic extraction / Model interpretation |

- **Full:** satisfies the requested scope with traceable evidence. Matching an
  answer string without supporting evidence is insufficient.
- **Partial:** provides a correctly supported part of the answer. Record missing
  items and any incorrect assertions.
- **Unanswered:** includes questions left unresolved with a reason. Do not remove
  questions from the denominator because evidence is missing.
- **Incorrect:** contradicts the evidence or reference answers, or makes an
  unsupported assertion. Do not treat an explicitly labeled candidate as a
  definite claim.

Report fully answered questions out of 12, counts of partial, unanswered, and
incorrect answers, and elapsed time. If assigning partial credit to compound
questions, fix the weights before the run. The reference notes do not enumerate
all execution times and counts for Q12 or all timestamps for Q28, so this file
alone cannot support strict automatic scoring. When comparing times, check UTC
offsets, daylight saving time, dates, and event meanings such as a shutdown
request versus log-service termination.

### Evaluation limitations

These questions have existing question classifications and deterministic search
support. Distinguish results from deterministic extraction from those obtained
through additional model investigation and interpretation. Automatic states such
as `answered` or a report marked `complete` are not scores: verify the requested
period, required fields, and meaning of the returned evidence.

The daily timeline builder uses time and date constraints in question headings
and bodies, converts evidence timestamps using the case time basis, and filters
accordingly. If a local time window is requested but the timezone is unknown, it
leaves that constraint unapplied and reports a partial answer with a reason.
The evaluator must verify the evidence for the case time basis. Rename candidates
and deterministic anti-forensics results also need checking against the requested
dates.

Preserve the original question constraints. Do not simplify questions to fit the
implementation or add search targets from reference answers. Do not add product
logic solely to improve CFReDS scores; apply the same evaluation method to other
cases.

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
