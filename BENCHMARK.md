# BENCHMARK - Data Leakage Case

Source: https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html

The purpose of this work is to learn various types of data leakage, and practice its investigation techniques.

## Scenario Overview

‘Iaman Informant’ was working as a manager of the technology development division at a famous international company OOO that developed state-of-the-art technologies and gadgets.

One day, at a place which ‘Mr. Informant’ visited on business, he received an offer from ‘Spy Conspirator’ to leak sensitive information related to the newest technology. Actually, ‘Mr. Conspirator’ was an employee of a rival company, and ‘Mr. Informant’ decided to accept the offer for large amounts of money, and began establishing a detailed leakage plan.

‘Mr. Informant’ made a deliberate effort to hide the leakage plan. He discussed it with ‘Mr. Conspirator’ using an e-mail service like a business relationship. He also sent samples of confidential information through personal cloud storage.

The information security policies in the company include the following:

- Confidential paper documents and electronic files can be accessed only within the allowed time range from 10:00 AM to 16:00 PM with the appropriate permissions.
- All employees are required to pass through the ‘Security Checkpoint’ system.

In addition, although the company managed separate internal and external networks and used DRM (Digital Rights Management) / DLP (Data Loss Prevention) solutions for their information security, ‘Mr. Informant’ had sufficient authority to bypass them. He was also very interested in IT (Information Technology), and had a slight knowledge of digital forensics.

In this scenario, find any evidence of the data leakage, and any data that might have been generated from the suspect’s PC.

## Target System

| Target | Detailed Information |
|---|---|
| Personal Computer (PC) | Type: Virtual System |
|  | CPU: 1 Processer (2 Core) |
|  | RAM: 2,048 MB |
|  | HDD Size: 20 GB |
|  | File System: NTFS |
|  | IP Address: 10.11.11.129 |
|  | Operating System: Microsoft Windows 7 Ultimate (SP1) |

## Acquired Data Information

| Item | Details |
|---|---|
| Personal Computer (PC) – `DD` Image | Download Links: `pc.7z.001`, `pc.7z.002`, `pc.7z.003` |
|  | Imaging S/W: FTK Imager 3.4.0.1 |
|  | Image Format: converted from VMDK |
| Personal Computer (PC) – `EnCase` Image | Download Links: `pc.E01`, `pc.E02`, `pc.E03`, `pc.E04` |
|  | Imaging S/W: EnCase Imager 7.10.00.103 |
|  | Image Format: E01 converted from VMDK |

## Digital Forensic Practice Points

| Practice Point | Description |
|---|---|
| Windows Forensics | Windows event logs, opened files and directories, application usage history, system caches, Windows Search databases, Volume Shadow Copy |
| Web Browser Forensics | History, cache, cookies, URLs, search keywords |
| E-mail Forensics | MS Outlook file examination, e-mails, attachments |
| Database Forensics | MS Extensible Storage Engine (ESE), SQLite |
| Deleted Data Recovery | Metadata-based recovery, signature/content-based recovery, Recycle Bin, unused area examination |
| User Behavior Analysis | Constructing a forensic timeline of events, visualizing the timeline |

## Scored Questions

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

## Deferred Questions

1. Original Q1. What are the hash values (MD5 & SHA-1) of the PC image?
2. Original Q2. Does the acquisition and verification hash value match?
3. Original Q3. Identify the partition information of the PC image.
4. Original Q4. Explain installed OS information in detail.
   - OS name
   - install date
   - registered owner
5. Original Q5. What is the timezone setting?
6. Original Q7. List all accounts in the OS except the system accounts:
   - Administrator
   - Guest
   - systemprofile
   - LocalService
   - NetworkService
7. Original Q10. Explain the information of network interface(s) with an IP address assigned by DHCP.
8. Original Q11. What applications were installed by the suspect after installing the OS?
9. Original Q15. Identify directory/file paths related to the web browser history.
10. Original Q16. What websites did the suspect access?
    - timestamp
    - URL
11. Original Q17. List all search keywords used in web browsers.
    - timestamp
    - URL
    - keyword
12. Original Q18. List all user keywords entered in the Windows Explorer search bar.
    - timestamp
    - keyword
13. Original Q21. What was the e-mail account used by the suspect?
14. Original Q22. List all e-mails of the suspect.
    - timestamp
    - From
    - To
    - Subject
    - Body
    - Attachment
15. Original Q23. If possible, identify deleted e-mails.
    - Hint: examine the OST file only.
16. Original Q26. What files were deleted from Google Drive?
    - filename
    - modified timestamp
    - Hint: find a transaction log file of Google Drive.
17. Original Q27. Identify account information for synchronizing Google Drive.
18. Original Q29. How and when did the suspect print a resignation file?
19. Original Q30. Where are Thumbcache files located?
20. Original Q31. Identify traces related to confidential files stored in Thumbcache.
    - Include 256 only.
21. Original Q32. Where are Sticky Note files located?
22. Original Q33. Identify notes stored in the Sticky Note file.
23. Original Q34. Was the Windows Search and Indexing function enabled?
24. Original Q35. How can you identify whether Windows Search and Indexing was enabled?
25. Original Q36. If it was enabled, what is the file path of the Windows Search index database?
26. Original Q37. What kinds of data were stored in the Windows Search database?
27. Original Q38. Find traces of Internet Explorer usage stored in the Windows Search database.
    - Consider only the date range between 2015-03-22 and 2015-03-23.
28. Original Q39. List the e-mail communication stored in the Windows Search database.
    - Consider only the date range between 2015-03-23 and 2015-03-24.
29. Original Q40. List files and directories related to Windows Desktop stored in the Windows Search database.
    - Windows Desktop directory: `\Users\informant\Desktop\`
30. Original Q41. Where are Volume Shadow Copies stored?
31. Original Q42. When were Volume Shadow Copies created?
32. Original Q43. Why can't Outlook's e-mail data be found in Volume Shadow Copy?
33. Original Q44. Examine Recycle Bin data on the PC.
