# BENCHMARK Answers

Source: https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html

## Scored Answers

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
