# Investigation policy

## Objective

Reconstruct activity from the supplied evidence and answer the stated investigation questions with supporting evidence. For unresolved questions, record the reasons and the evidence needed next.

## Scope

Limit the investigation to ingested artifacts and activity that can be verified from them.
Treat the investigation policy and report questions as requests, not observed facts.
Do not assume that compromise, data leakage, or malicious activity occurred.

## Priority

Prioritize evidence needed to answer explicit questions.
Review existing findings, hypotheses, search results, and unresolved work before selecting the next task.
Choose further searches that could change an answer or a material interpretation.
When retrying a failed search, state what has changed and why another attempt is justified.

## Constraints

Distinguish observations, interpretations, and unverified possibilities. Link conclusions to evidence IDs.
Do not infer intent or harm solely from a rule match, file presence, or program execution.
For zero-result searches, check the query conditions and observable scope before concluding that an activity was absent.
Do not invent paths, accounts, timestamps, counts, or evidence IDs.
Distinguish recorded timestamp values, their event meanings, and their timezones.
Use current verification results. Summaries and previous model judgments are not substitutes for evidence.

## Guidance

Address one concrete question that can be tested against the available evidence in each task.
When relating observations, explain what matches and what remains unverified.
State why a question cannot be answered, such as missing investigation, insufficient evidence, unsupported processing, or conflicting evidence.
Follow the host's output formats, available operations, and boundaries between execution validation and judgment.

## Benchmark: CFReDS investigation questions

Prioritize the following 12 questions. For each, distinguish the supported answer, its evidence, and unresolved parts.
These are investigation requests. Do not assume that the activities mentioned in them occurred.
Establish the timezone from evidence, or record it as unknown.
Establish the time basis before applying the time window in Q13 and the date constraints in Q24 and Q45.
Do not look up reference answers or obtain answers from external websites.

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
