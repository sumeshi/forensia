CORE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS evtx_events (
    evidence_id VARCHAR,
    source_file VARCHAR,
    channel VARCHAR,
    event_id INTEGER,
    record_id BIGINT,
    timestamp TIMESTAMP,
    computer VARCHAR,
    user_name VARCHAR,
    target_user VARCHAR,
    subject_user VARCHAR,
    src_ip VARCHAR,
    dst_ip VARCHAR,
    dst_port VARCHAR,
    protocol VARCHAR,
    logon_type VARCHAR,
    process_name VARCHAR,
    process_id VARCHAR,
    command_line VARCHAR,
    service_name VARCHAR,
    exception_code VARCHAR,
    object_dn VARCHAR,
    attribute VARCHAR,
    target_server VARCHAR,
    target_group VARCHAR,
    task_name VARCHAR,
    session_id VARCHAR,
    share_name VARCHAR,
    access_mask VARCHAR,
    normalized_src_ip VARCHAR,
    normalized_target_user VARCHAR,
    parent_process VARCHAR,
    parent_process_id VARCHAR,
    parent_cmd VARCHAR,
    child_process VARCHAR,
    child_process_id VARCHAR,
    child_cmd VARCHAR,
    parent_image VARCHAR,
    file_path VARCHAR,
    parent_guid VARCHAR,
    child_guid VARCHAR,
    clear_time TIMESTAMP,
    clear_event_id INTEGER,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    hour_bucket INTEGER,
    request_count INTEGER,
    status VARCHAR,
    reason VARCHAR,
    message VARCHAR,
    raw_json JSON,
    tags JSON,
    severity VARCHAR
);

CREATE TABLE IF NOT EXISTS mft_entries (
    evidence_id VARCHAR,
    source_file VARCHAR,
    record_number BIGINT,
    file_path VARCHAR,
    file_name VARCHAR,
    extension VARCHAR,
    is_directory BOOLEAN,
    is_deleted BOOLEAN,
    size BIGINT,
    si_created TIMESTAMP,
    si_modified TIMESTAMP,
    si_accessed TIMESTAMP,
    si_mft_modified TIMESTAMP,
    fn_created TIMESTAMP,
    fn_modified TIMESTAMP,
    fn_accessed TIMESTAMP,
    fn_mft_modified TIMESTAMP,
    raw_json JSON,
    tags JSON,
    severity VARCHAR
);

CREATE TABLE IF NOT EXISTS mft_timeline (
    timeline_id VARCHAR,
    evidence_id VARCHAR,
    record_number BIGINT,
    file_path VARCHAR,
    file_name VARCHAR,
    timestamp TIMESTAMP,
    timestamp_type VARCHAR,
    source_file VARCHAR,
    description VARCHAR,
    tags JSON
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id VARCHAR,
    rule_id VARCHAR,
    title VARCHAR,
    summary VARCHAR,
    severity VARCHAR,
    confidence DOUBLE,
    status VARCHAR,
    tags JSON,
    attack JSON,
    evidence JSON,
    ai_summary VARCHAR,
    missing_checks JSON,
    created_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hypotheses (
    hypothesis_id VARCHAR PRIMARY KEY,
    description VARCHAR,
    status VARCHAR,
    verdict VARCHAR,
    summary VARCHAR,
    origin VARCHAR,
    created_session VARCHAR,
    resolved_session VARCHAR,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    source_rule_ids JSON,
    required_entities JSON,
    confirm_when JSON
);

CREATE TABLE IF NOT EXISTS report_sections (
    section_key VARCHAR PRIMARY KEY,
    title VARCHAR,
    body VARCHAR,
    confidence DOUBLE,
    status VARCHAR DEFAULT 'draft',
    update_count INTEGER DEFAULT 0,
    gaps JSON,
    last_filled_session VARCHAR,
    last_filled_at TIMESTAMP,
    stale BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS claims (
    claim_id VARCHAR PRIMARY KEY,
    section_key VARCHAR,
    claim_text VARCHAR,
    finding_ids JSON,
    hypothesis_ids JSON,
    evidence_ids JSON,
    support_status VARCHAR,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS claims_by_section ON claims(section_key, updated_at);

CREATE TABLE IF NOT EXISTS section_facts (
    fact_id VARCHAR PRIMARY KEY,
    fact_type VARCHAR NOT NULL,
    fact_key VARCHAR,
    fact_value JSON,
    evidence_ids JSON NOT NULL,
    source_query VARCHAR,
    source_section VARCHAR,
    confidence DOUBLE,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_section_facts_type ON section_facts(fact_type);
CREATE INDEX IF NOT EXISTS idx_section_facts_section ON section_facts(source_section, fact_type);

CREATE TABLE IF NOT EXISTS section_evidence (
    section_key VARCHAR,
    block_heading VARCHAR,
    evidence_id VARCHAR,
    role VARCHAR,
    source_query VARCHAR,
    created_at TIMESTAMP,
    UNIQUE(section_key, block_heading, evidence_id, source_query)
);

CREATE INDEX IF NOT EXISTS idx_section_evidence_section ON section_evidence(section_key, block_heading);
CREATE INDEX IF NOT EXISTS idx_section_evidence_id ON section_evidence(evidence_id);

CREATE TABLE IF NOT EXISTS query_cache (
    sql_hash VARCHAR PRIMARY KEY,
    sql_text VARCHAR,
    result_json JSON,
    executed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS section_runs (
    run_id VARCHAR PRIMARY KEY,
    section_key VARCHAR,
    block_heading VARCHAR,
    iteration INTEGER,
    phase VARCHAR,
    payload JSON,
    verdict VARCHAR,
    created_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_section_runs_section ON section_runs(section_key, block_heading, created_at);

CREATE OR REPLACE VIEW section_run_coverage AS
SELECT
    section_key,
    block_heading,
    COALESCE(
        NULLIF(json_extract_string(payload, '$.result.keypoint'), ''),
        NULLIF(json_extract_string(payload, '$.result.query_id'), ''),
        NULLIF(json_extract_string(payload, '$.result.purpose'), ''),
        NULLIF(json_extract_string(payload, '$.result.source_ref'), ''),
        NULLIF(json_extract_string(payload, '$.source_ref'), ''),
        NULLIF(json_extract_string(payload, '$.source_kind'), ''),
        'unknown_source'
    ) AS source_query,
    COALESCE(
        NULLIF(json_extract_string(payload, '$.result.source_ref'), ''),
        NULLIF(json_extract_string(payload, '$.result.source_kind'), ''),
        NULLIF(json_extract_string(payload, '$.source_ref'), ''),
        NULLIF(json_extract_string(payload, '$.source_kind'), ''),
        'unknown'
    ) AS evidence_table,
    COALESCE(CAST(json_extract_string(payload, '$.result.row_count') AS INTEGER), 0) AS row_count,
    CASE
        WHEN COALESCE(json_extract_string(payload, '$.result.kind'), 'rows') = 'rows' THEN 'Yes'
        ELSE 'No'
    END AS used_in_answer,
    'Yes' AS queried,
    created_at
FROM section_runs
WHERE phase = 'query';

CREATE TABLE IF NOT EXISTS ingested_files (
    sha256 VARCHAR PRIMARY KEY,
    path VARCHAR,
    source_kind VARCHAR,
    size BIGINT,
    ingested_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS prefetch_executions (
    evidence_id VARCHAR,
    source_file VARCHAR,
    executable_name VARCHAR,
    exec_count INTEGER,
    last_exec_time TIMESTAMP,
    exec_times JSON,
    prefetch_hash VARCHAR,
    filenames JSON,
    volumes JSON,
    raw_json JSON,
    tags JSON,
    severity VARCHAR
);

CREATE TABLE IF NOT EXISTS prefetch_timeline (
    timeline_id VARCHAR,
    evidence_id VARCHAR,
    executable_name VARCHAR,
    prefetch_hash VARCHAR,
    exec_time TIMESTAMP,
    exec_index INTEGER,
    source_file VARCHAR,
    tags JSON
);

CREATE UNIQUE INDEX IF NOT EXISTS findings_by_id ON findings(finding_id);
CREATE INDEX IF NOT EXISTS findings_by_status_confidence ON findings(status, confidence);
CREATE INDEX IF NOT EXISTS evtx_events_by_evidence_id ON evtx_events(evidence_id);
CREATE INDEX IF NOT EXISTS mft_entries_by_evidence_id ON mft_entries(evidence_id);
CREATE INDEX IF NOT EXISTS prefetch_executions_by_evidence_id ON prefetch_executions(evidence_id);
"""

TRACE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS trace.ai_reviews (
    review_id VARCHAR,
    finding_id VARCHAR,
    verdict VARCHAR,
    report_text VARCHAR,
    missing_checks JSON,
    confidence_adjustment DOUBLE,
    notes VARCHAR,
    raw_response JSON,
    created_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS trace.investigation_sessions (
    session_id VARCHAR PRIMARY KEY,
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    iterations INTEGER,
    status VARCHAR
);

CREATE TABLE IF NOT EXISTS trace.investigation_steps (
    step_id VARCHAR PRIMARY KEY,
    session_id VARCHAR,
    hypothesis_id VARCHAR,
    iteration INTEGER,
    phase VARCHAR,
    input_json JSON,
    output_json JSON,
    created_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS investigation_steps_by_session_hypothesis
    ON trace.investigation_steps(session_id, hypothesis_id);

CREATE TABLE IF NOT EXISTS trace.hypothesis_reasoning (
    entry_id VARCHAR PRIMARY KEY,
    hypothesis_id VARCHAR,
    session_id VARCHAR,
    iteration INTEGER,
    phase VARCHAR,
    verdict VARCHAR,
    query_id VARCHAR,
    body VARCHAR,
    created_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS hypothesis_reasoning_by_hypothesis
    ON trace.hypothesis_reasoning(hypothesis_id, created_at);

CREATE TABLE IF NOT EXISTS trace.progress_events (
    event_index BIGINT PRIMARY KEY,
    stage VARCHAR,
    status VARCHAR,
    iteration INTEGER,
    current_query VARCHAR,
    summary VARCHAR,
    payload JSON,
    created_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ai_reviews_by_finding
    ON trace.ai_reviews(finding_id);
"""

TRACE_TABLES = {
    "ai_reviews",
    "investigation_sessions",
    "investigation_steps",
    "hypothesis_reasoning",
    "progress_events",
}
