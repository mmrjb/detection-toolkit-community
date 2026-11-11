-- Detection Toolkit v0.1 schema. Applied once by `python -m detection_toolkit init-db`.
-- PRAGMA user_version is set by the initializer after the seed data loads.

CREATE TABLE sources (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    license     TEXT NOT NULL,
    license_url TEXT NOT NULL DEFAULT '',
    homepage    TEXT NOT NULL DEFAULT '',
    notice      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE rules (
    uid                TEXT PRIMARY KEY,
    source_id          TEXT NOT NULL REFERENCES sources(id),
    rule_id            TEXT NOT NULL DEFAULT '',
    title              TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL DEFAULT '',
    level              TEXT NOT NULL DEFAULT '',
    author             TEXT NOT NULL DEFAULT '',
    rule_date          TEXT NOT NULL DEFAULT '',
    modified           TEXT NOT NULL DEFAULT '',
    logsource_product  TEXT NOT NULL DEFAULT '',
    logsource_category TEXT NOT NULL DEFAULT '',
    logsource_service  TEXT NOT NULL DEFAULT '',
    file_path          TEXT NOT NULL,
    reference_url      TEXT NOT NULL DEFAULT '',
    raw_yaml           TEXT NOT NULL,
    content_hash       TEXT NOT NULL
);
CREATE INDEX idx_rules_source ON rules(source_id);
CREATE INDEX idx_rules_logsource ON rules(logsource_product, logsource_category, logsource_service);

CREATE TABLE mitre_index (
    technique TEXT NOT NULL,
    rule_uid  TEXT NOT NULL REFERENCES rules(uid) ON DELETE CASCADE,
    PRIMARY KEY (technique, rule_uid)
);
CREATE INDEX idx_mitre_index_rule ON mitre_index(rule_uid, technique);

-- Demo environment telemetry (Data Source Mapper and Gap Prioritization).
CREATE TABLE data_sources (
    id               INTEGER PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    aliases          TEXT NOT NULL DEFAULT '',
    category         TEXT NOT NULL DEFAULT '',
    platform         TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL CHECK (status IN ('Available', 'Partial', 'Missing', 'Unknown', 'Not Applicable')),
    collected_fields TEXT NOT NULL DEFAULT '[]',
    notes            TEXT NOT NULL DEFAULT ''
);

CREATE TABLE event_types (
    key         TEXT PRIMARY KEY,
    data_source TEXT NOT NULL REFERENCES data_sources(name),
    label       TEXT NOT NULL,
    channel     TEXT NOT NULL DEFAULT '',
    event_id    INTEGER,
    fields      TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE logsource_event_map (
    product    TEXT NOT NULL,
    category   TEXT NOT NULL DEFAULT '',
    service    TEXT NOT NULL DEFAULT '',
    event_type TEXT NOT NULL REFERENCES event_types(key),
    preference INTEGER NOT NULL DEFAULT 1,
    field_map  TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (product, category, service, event_type)
);

CREATE TABLE technique_requirements (
    technique TEXT PRIMARY KEY,
    required  TEXT NOT NULL DEFAULT '[]',
    minimum   TEXT NOT NULL DEFAULT '[]',
    preferred TEXT NOT NULL DEFAULT '[]',
    guidance  TEXT NOT NULL DEFAULT ''
);

-- Synthetic threat rankings used to order Gap Prioritization.
CREATE TABLE threat_reports (
    id   TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    year INTEGER,
    note TEXT NOT NULL DEFAULT ''
);

CREATE TABLE threat_report_entries (
    report_id TEXT NOT NULL REFERENCES threat_reports(id) ON DELETE CASCADE,
    rank      INTEGER NOT NULL CHECK (rank BETWEEN 1 AND 10),
    technique TEXT NOT NULL,
    PRIMARY KEY (report_id, technique)
);

-- Synthetic sample events for the local Sigma check in the Data Source Mapper.
CREATE TABLE demo_events (
    id          INTEGER PRIMARY KEY,
    rule_uid    TEXT NOT NULL REFERENCES rules(uid) ON DELETE CASCADE,
    event_type  TEXT NOT NULL REFERENCES event_types(key),
    label       TEXT NOT NULL,
    expectation TEXT NOT NULL CHECK (expectation IN ('match', 'no_match')),
    explanation TEXT NOT NULL DEFAULT '',
    event_json  TEXT NOT NULL
);

-- Rule plans: the only table the application writes to after initialization.
CREATE TABLE rule_plan (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    technique         TEXT NOT NULL,
    title             TEXT NOT NULL,
    rule_uid          TEXT REFERENCES rules(uid) ON DELETE SET NULL,
    source_key        TEXT NOT NULL,
    origin            TEXT NOT NULL DEFAULT 'manual'
                      CHECK (origin IN ('manual', 'gaps', 'rules', 'coverage', 'data_sources', 'converter', 'seed')),
    priority          TEXT NOT NULL DEFAULT 'Medium' CHECK (priority IN ('High', 'Medium', 'Low')),
    status            TEXT NOT NULL DEFAULT 'planned'
                      CHECK (status IN ('planned', 'in_progress', 'completed', 'rejected')),
    validation_status TEXT NOT NULL DEFAULT 'not_assessed'
                      CHECK (validation_status IN ('not_assessed', 'implementable', 'blocked', 'validated')),
    telemetry         TEXT NOT NULL DEFAULT '',
    validation_notes  TEXT NOT NULL DEFAULT '',
    notes             TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);
CREATE UNIQUE INDEX ux_rule_plan_source_key ON rule_plan(source_key);
CREATE INDEX idx_rule_plan_technique ON rule_plan(technique);
