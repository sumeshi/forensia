SCHEMA_SQL = """
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
    logon_type VARCHAR,
    process_name VARCHAR,
    command_line VARCHAR,
    service_name VARCHAR,
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
    timestamp TIMESTAMP,
    timestamp_type VARCHAR,
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

CREATE TABLE IF NOT EXISTS ai_reviews (
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

CREATE TABLE IF NOT EXISTS investigation_sessions (
    session_id VARCHAR PRIMARY KEY,
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    iterations INTEGER,
    status VARCHAR
);

CREATE TABLE IF NOT EXISTS investigation_steps (
    step_id VARCHAR PRIMARY KEY,
    session_id VARCHAR,
    iteration INTEGER,
    phase VARCHAR,
    input_json JSON,
    output_json JSON,
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
    updated_at TIMESTAMP
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
    last_filled_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS progress_events (
    event_index BIGINT PRIMARY KEY,
    stage VARCHAR,
    status VARCHAR,
    iteration INTEGER,
    current_query VARCHAR,
    summary VARCHAR,
    payload JSON,
    created_at TIMESTAMP
);
"""
