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
    fn_name VARCHAR,
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
    source_decl_id VARCHAR,
    required_entities JSON,
    confirm_when JSON,
    refute_when JSON,
    evidence_requirements JSON,
    verification_spec JSON,
    source_gap_id VARCHAR,
    selection_count INTEGER DEFAULT 0,
    last_selected_at TIMESTAMP,
    next_eligible_at TIMESTAMP,
    blocked_reason VARCHAR,
    sufficiency_status VARCHAR,
    sufficiency_score DOUBLE,
    sufficiency_reason VARCHAR,
    sufficiency_policy_id VARCHAR,
    human_review_required BOOLEAN DEFAULT FALSE,
    target_keypoint_id VARCHAR
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

CREATE TABLE IF NOT EXISTS section_questions (
    question_id VARCHAR PRIMARY KEY,
    section_key VARCHAR,
    block_heading VARCHAR,
    question_text VARCHAR,
    question_type VARCHAR,
    answer_spec VARCHAR,
    intent VARCHAR,
    confidence DOUBLE,
    matched_rule VARCHAR,
    required_evidence JSON,
    status VARCHAR,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_section_questions_section ON section_questions(section_key, block_heading);
CREATE INDEX IF NOT EXISTS idx_section_questions_spec ON section_questions(answer_spec);

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
        WHEN COALESCE(json_extract_string(payload, '$.result.kind'), 'rows') = 'rows'
         AND COALESCE(CAST(json_extract_string(payload, '$.result.row_count') AS INTEGER), 0) > 0 THEN 'Yes'
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

CREATE TABLE IF NOT EXISTS case_timeline (
    entry_id VARCHAR PRIMARY KEY,
    timestamp TIMESTAMP,
    source VARCHAR,
    ref_id VARCHAR,
    host VARCHAR,
    summary VARCHAR,
    evidence_id VARCHAR
);

CREATE UNIQUE INDEX IF NOT EXISTS findings_by_id ON findings(finding_id);
CREATE INDEX IF NOT EXISTS findings_by_status_confidence ON findings(status, confidence);
CREATE INDEX IF NOT EXISTS evtx_events_by_evidence_id ON evtx_events(evidence_id);
CREATE INDEX IF NOT EXISTS mft_entries_by_evidence_id ON mft_entries(evidence_id);
CREATE INDEX IF NOT EXISTS prefetch_executions_by_evidence_id ON prefetch_executions(evidence_id);

CREATE TABLE IF NOT EXISTS evidence_sources (
    source_id VARCHAR PRIMARY KEY,
    artifact_family VARCHAR,
    display_path VARCHAR,
    ingest_status VARCHAR,
    parser_name VARCHAR,
    parser_version VARCHAR,
    row_count INTEGER,
    channel VARCHAR,
    hosts JSON,
    volume_id VARCHAR,
    min_time TIMESTAMP,
    max_time TIMESTAMP,
    error_code VARCHAR,
    error_summary VARCHAR,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_evidence_sources_family ON evidence_sources(artifact_family);
CREATE INDEX IF NOT EXISTS idx_evidence_sources_status ON evidence_sources(ingest_status);

CREATE TABLE IF NOT EXISTS evidence_coverage (
    capability VARCHAR,
    host VARCHAR,
    channel VARCHAR,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    source_family VARCHAR,
    state VARCHAR,
    reason_code VARCHAR,
    source_ids JSON,
    excluded_timestamps JSON,
    confidence DOUBLE,
    derived_at TIMESTAMP,
    UNIQUE(capability, host, channel, source_family)
);
CREATE INDEX IF NOT EXISTS idx_evidence_coverage_capability ON evidence_coverage(capability);

-- Registry keeps the parser's raw ECS document lossless while reusing
-- evidence_sources for source-level lineage.  These tables are deliberately
-- narrow: plugin completeness and verdict semantics remain outside ingest.
CREATE TABLE IF NOT EXISTS registry_datasets (
    dataset_id VARCHAR PRIMARY KEY,
    identity VARCHAR,
    admission_state VARCHAR,
    grouping_reason VARCHAR,
    member_source_ids JSON,
    parser_name VARCHAR,
    parser_version VARCHAR,
    parser_config JSON,
    raw_path VARCHAR,
    ingest_status VARCHAR,
    error_code VARCHAR,
    error_summary VARCHAR,
    row_count INTEGER,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_registry_datasets_status ON registry_datasets(ingest_status);

CREATE TABLE IF NOT EXISTS registry_artifacts (
    artifact_id VARCHAR PRIMARY KEY,
    dataset_id VARCHAR,
    source_ids JSON,
    plugin VARCHAR,
    hive VARCHAR,
    key_path VARCHAR,
    value_name VARCHAR,
    timestamp TIMESTAMP,
    timestamp_kind VARCHAR,
    raw_json JSON,
    created_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_registry_artifacts_dataset ON registry_artifacts(dataset_id);
CREATE INDEX IF NOT EXISTS idx_registry_artifacts_timestamp ON registry_artifacts(timestamp);

CREATE TABLE IF NOT EXISTS registry_timeline (
    timeline_id VARCHAR PRIMARY KEY,
    artifact_id VARCHAR,
    dataset_id VARCHAR,
    source_ids JSON,
    timestamp TIMESTAMP,
    timestamp_kind VARCHAR,
    raw_timestamp VARCHAR,
    summary VARCHAR
);
CREATE INDEX IF NOT EXISTS idx_registry_timeline_timestamp ON registry_timeline(timestamp);

CREATE TABLE IF NOT EXISTS investigation_state (
    state_id VARCHAR PRIMARY KEY DEFAULT 'case',
    objective VARCHAR,
    status VARCHAR DEFAULT 'active',
    termination_policy JSON,
    stop_reason_code VARCHAR,
    stop_reason VARCHAR,
    stop_summary JSON,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS report_gaps (
    gap_id VARCHAR PRIMARY KEY,
    section_key VARCHAR,
    block_heading VARCHAR,
    description VARCHAR,
    kind VARCHAR,
    status VARCHAR DEFAULT 'open',
    source_claim_id VARCHAR,
    hypothesis_id VARCHAR,
    task_id VARCHAR,
    coverage_reason VARCHAR,
    origin VARCHAR DEFAULT 'section',
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_report_gaps_status ON report_gaps(status);
CREATE INDEX IF NOT EXISTS idx_report_gaps_section ON report_gaps(section_key);

CREATE TABLE IF NOT EXISTS investigation_tasks (
    task_id VARCHAR PRIMARY KEY,
    kind VARCHAR,
    description VARCHAR,
    status VARCHAR DEFAULT 'open',
    gap_id VARCHAR,
    hypothesis_id VARCHAR,
    required_capability VARCHAR,
    required_source VARCHAR,
    owner_phase VARCHAR,
    retry_condition VARCHAR,
    blocked_reason VARCHAR,
    reason VARCHAR,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_investigation_tasks_status ON investigation_tasks(status);

CREATE TABLE IF NOT EXISTS hypothesis_relations (
    from_hypothesis_id VARCHAR,
    to_hypothesis_id VARCHAR,
    relation_type VARCHAR,
    origin VARCHAR,
    confidence DOUBLE,
    rationale VARCHAR,
    created_session VARCHAR,
    created_at TIMESTAMP,
    UNIQUE(from_hypothesis_id, to_hypothesis_id, relation_type)
);
CREATE INDEX IF NOT EXISTS idx_hypothesis_relations_from ON hypothesis_relations(from_hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_hypothesis_relations_to ON hypothesis_relations(to_hypothesis_id);

CREATE TABLE IF NOT EXISTS hypothesis_evidence (
    link_id VARCHAR PRIMARY KEY,
    hypothesis_id VARCHAR,
    evidence_id VARCHAR,
    finding_id VARCHAR,
    query_id VARCHAR,
    assessment_id VARCHAR,
    role VARCHAR,
    source_family VARCHAR,
    source_file VARCHAR,
    derivation_group VARCHAR,
    strength VARCHAR,
    created_session VARCHAR,
    created_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_hypothesis_evidence_hypothesis ON hypothesis_evidence(hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_hypothesis_evidence_evidence ON hypothesis_evidence(evidence_id);
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
    status VARCHAR,
    terminal_reason VARCHAR,
    owner_id VARCHAR,
    heartbeat_at TIMESTAMP,
    phase VARCHAR,
    status_reason VARCHAR
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

CREATE TABLE IF NOT EXISTS trace.retrieval_events (
    event_id VARCHAR PRIMARY KEY,
    session_id VARCHAR,
    scope_kind VARCHAR,
    scope_id VARCHAR,
    phase VARCHAR,
    source_kind VARCHAR,
    query_terms JSON,
    candidate_count INTEGER,
    selected_refs JSON,
    rejected_refs JSON,
    selected_chars INTEGER,
    budget INTEGER,
    created_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS retrieval_events_by_scope
    ON trace.retrieval_events(scope_kind, scope_id, created_at);

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

-- Three distinct LLM telemetry record kinds (T-10):
--   logical call: one application-level decision unit
--   provider attempt: one actual HTTP request (incl. retries/timeouts)
--   deterministic op: render/parse/validate/query, non-LLM
CREATE TABLE IF NOT EXISTS trace.llm_logical_calls (
    logical_call_id VARCHAR PRIMARY KEY,
    session_id VARCHAR,
    parent_logical_call_id VARCHAR,
    phase VARCHAR,
    iteration INTEGER,
    hypothesis_id VARCHAR,
    section_id VARCHAR,
    action_id VARCHAR,
    request_fingerprint VARCHAR,
    status VARCHAR,
    created_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS llm_logical_calls_by_session
    ON trace.llm_logical_calls(session_id, phase);

CREATE TABLE IF NOT EXISTS trace.llm_provider_attempts (
    attempt_id VARCHAR PRIMARY KEY,
    logical_call_id VARCHAR,
    parent_attempt_id VARCHAR,
    session_id VARCHAR,
    phase VARCHAR,
    retry_ordinal INTEGER,
    endpoint VARCHAR,
    provider VARCHAR,
    model VARCHAR,
    schema_mode VARCHAR,
    request_fingerprint VARCHAR,
    configured_output_limit INTEGER,
    reasoning_reserve_tokens INTEGER,
    known_context_limit INTEGER,
    requested_output_limit INTEGER,
    effective_output_limit INTEGER,
    input_chars INTEGER,
    output_chars INTEGER,
    input_tokens INTEGER,
    output_tokens INTEGER,
    input_tokens_source VARCHAR,
    output_tokens_source VARCHAR,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    duration_ms BIGINT,
    connect_timeout_ms BIGINT,
    read_timeout_ms BIGINT,
    logical_deadline_ms BIGINT,
    deadline_fired VARCHAR,
    http_status INTEGER,
    status VARCHAR,
    error_type VARCHAR,
    error_code VARCHAR,
    error_body_summary VARCHAR,
    exception_class VARCHAR,
    finish_reason VARCHAR,
    parse_status VARCHAR,
    truncated BOOLEAN,
    accepted BOOLEAN,
    discarded_reason VARCHAR,
    response_fingerprint VARCHAR,
    action_fingerprint VARCHAR,
    duplicate_of VARCHAR,
    retry_class VARCHAR,
    retry_reason VARCHAR,
    policy_decision VARCHAR,
    request_changed_fields JSON,
    prompt_metadata JSON,
    request_body JSON,
    response_body VARCHAR,
    created_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS llm_provider_attempts_by_logical
    ON trace.llm_provider_attempts(logical_call_id);
CREATE INDEX IF NOT EXISTS llm_provider_attempts_by_session
    ON trace.llm_provider_attempts(session_id, phase);

CREATE TABLE IF NOT EXISTS trace.llm_deterministic_ops (
    op_id VARCHAR PRIMARY KEY,
    session_id VARCHAR,
    phase VARCHAR,
    hypothesis_id VARCHAR,
    section_id VARCHAR,
    op_type VARCHAR,
    target VARCHAR,
    duration_ms BIGINT,
    note VARCHAR,
    created_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS llm_deterministic_ops_by_session
    ON trace.llm_deterministic_ops(session_id, phase);
"""

TRACE_TABLES = {
    "ai_reviews",
    "investigation_sessions",
    "investigation_steps",
    "hypothesis_reasoning",
    "progress_events",
    "retrieval_events",
    "llm_logical_calls",
    "llm_provider_attempts",
    "llm_deterministic_ops",
}
