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
