"""SQLite baseline schema for the provenance graph, plans, actions and receipts."""

from __future__ import annotations

SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    record_id TEXT PRIMARY KEY,
    record_type TEXT NOT NULL,
    store_id TEXT NOT NULL,
    locator_json TEXT NOT NULL,
    fingerprint TEXT,
    fingerprint_key_version INTEGER,
    created_at TEXT,
    observed_at TEXT NOT NULL,
    sensitivity_json TEXT NOT NULL DEFAULT '[]',
    capabilities_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS lineage_edges (
    edge_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    evidence_ref TEXT,
    status TEXT NOT NULL DEFAULT 'confirmed',
    created_at TEXT NOT NULL,
    verified_by TEXT
);

CREATE TABLE IF NOT EXISTS candidate_edges (
    candidate_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    relation_guess TEXT NOT NULL,
    evidence_summary_redacted TEXT NOT NULL,
    model_id TEXT,
    confidence REAL,
    status TEXT NOT NULL DEFAULT 'candidate',
    reviewed_by TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS revocation_requests (
    request_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    mode TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    approved_at TEXT,
    approved_by TEXT,
    target_fingerprint TEXT,
    target_shingles_json TEXT NOT NULL DEFAULT '[]',
    target_anchors_json TEXT NOT NULL DEFAULT '[]',
    target_tokens_json TEXT NOT NULL DEFAULT '[]',
    target_label_redacted TEXT,
    target_key_version INTEGER,
    target_embedding_json TEXT NOT NULL DEFAULT '[]',
    target_embedding_model TEXT,
    target_normalized_len INTEGER
);

CREATE TABLE IF NOT EXISTS revocation_plans (
    plan_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    state TEXT NOT NULL,
    plan_hash TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    approved_at TEXT,
    approved_by TEXT,
    applied_at TEXT,
    execution_token TEXT,
    execution_pid INTEGER,
    execution_host TEXT,
    execution_started_at TEXT,
    FOREIGN KEY (request_id) REFERENCES revocation_requests(request_id)
);

CREATE TABLE IF NOT EXISTS revocation_plan_items (
    item_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    evidence_class TEXT NOT NULL,
    proposed_action TEXT NOT NULL,
    reason_redacted TEXT NOT NULL,
    risk TEXT NOT NULL,
    approved INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'planned',
    expected_fingerprint TEXT,
    fingerprint_key_version INTEGER,
    FOREIGN KEY (plan_id) REFERENCES revocation_plans(plan_id)
);

CREATE TABLE IF NOT EXISTS plan_item_reviews (
    review_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    plan_version INTEGER NOT NULL,
    decision TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    plan_version INTEGER NOT NULL,
    approval_ref TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);

CREATE TABLE IF NOT EXISTS actions (
    action_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    item_id TEXT,
    adapter_id TEXT,
    operation TEXT NOT NULL,
    result TEXT NOT NULL,
    error_code TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS verification_runs (
    verification_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    adapter_id TEXT NOT NULL,
    method TEXT NOT NULL,
    outcome TEXT NOT NULL,
    residual_count INTEGER NOT NULL,
    limitations_json TEXT NOT NULL,
    checked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS receipts (
    receipt_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    receipt_version TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_lineage_source ON lineage_edges(source_id, status);
CREATE INDEX IF NOT EXISTS idx_candidate_source ON candidate_edges(source_id, status);
CREATE INDEX IF NOT EXISTS idx_items_plan ON revocation_plan_items(plan_id);
CREATE INDEX IF NOT EXISTS idx_actions_request ON actions(request_id);
CREATE INDEX IF NOT EXISTS idx_item_reviews_plan ON plan_item_reviews(plan_id);
CREATE INDEX IF NOT EXISTS idx_verify_request ON verification_runs(request_id);

-- Revocation tombstones retain only keyed fingerprints and derived match anchors,
-- never the revoked content itself.
CREATE TABLE IF NOT EXISTS tombstones (
    tombstone_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    label_redacted TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    shingles_json TEXT NOT NULL DEFAULT '[]',
    anchors_json TEXT NOT NULL DEFAULT '[]',
    tokens_json TEXT NOT NULL DEFAULT '[]',
    related_record_ids_json TEXT NOT NULL DEFAULT '[]',
    related_fingerprints_json TEXT NOT NULL DEFAULT '[]',
    embedding_json TEXT NOT NULL DEFAULT '[]',
    embedding_model TEXT,
    scope_json TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    key_version INTEGER NOT NULL DEFAULT 1,
    normalized_len INTEGER,
    created_at TEXT NOT NULL,
    activated_at TEXT
);

CREATE TABLE IF NOT EXISTS ingestion_events (
    event_id TEXT PRIMARY KEY,
    tombstone_id TEXT,
    store_id TEXT,
    record_id TEXT NOT NULL,
    locator_json TEXT NOT NULL DEFAULT '{}',
    decision TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    match_score REAL NOT NULL DEFAULT 0,
    present_in_store INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    UNIQUE (tombstone_id, record_id, decision)
);

CREATE TABLE IF NOT EXISTS quarantine (
    quarantine_id TEXT PRIMARY KEY,
    tombstone_id TEXT,
    store_id TEXT,
    record_id TEXT NOT NULL,
    locator_json TEXT NOT NULL DEFAULT '{}',
    reason_code TEXT NOT NULL,
    match_score REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending_review',
    created_at TEXT NOT NULL,
    reviewed_at TEXT,
    reviewed_by TEXT,
    review_note TEXT,
    admission_event_id TEXT,
    admitted_at TEXT,
    recheck_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (tombstone_id, record_id)
);

CREATE INDEX IF NOT EXISTS idx_tombstones_status ON tombstones(status);
CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status);
CREATE INDEX IF NOT EXISTS idx_ingestion_tombstone ON ingestion_events(tombstone_id, decision);
"""
