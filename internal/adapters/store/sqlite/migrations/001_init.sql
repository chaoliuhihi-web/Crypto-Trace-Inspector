PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

INSERT OR REPLACE INTO schema_meta (key, value) VALUES
  ('schema_version', '1'),
  ('schema_name', 'crypto_inspector');

CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY,
  case_no TEXT,
  title TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed', 'archived')),
  created_by TEXT,
  note TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  closed_at INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cases_case_no ON cases(case_no);
CREATE INDEX IF NOT EXISTS idx_cases_status_created_at ON cases(status, created_at);

CREATE TABLE IF NOT EXISTS case_devices (
  device_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  os_type TEXT NOT NULL CHECK (os_type IN ('windows', 'macos', 'android', 'ios')),
  device_name TEXT,
  identifier TEXT,
  connection_type TEXT NOT NULL DEFAULT 'local' CHECK (connection_type IN ('local', 'usb')),
  is_authorized INTEGER NOT NULL DEFAULT 0 CHECK (is_authorized IN (0, 1)),
  auth_note TEXT,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_case_devices_case_id ON case_devices(case_id);
CREATE INDEX IF NOT EXISTS idx_case_devices_case_os ON case_devices(case_id, os_type);
CREATE INDEX IF NOT EXISTS idx_case_devices_identifier ON case_devices(identifier);

CREATE TABLE IF NOT EXISTS artifacts (
  artifact_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  artifact_type TEXT NOT NULL CHECK (
    artifact_type IN (
      'installed_apps',
      'browser_history',
      'browser_extension',
      'mobile_packages',
      'mobile_backup'
    )
  ),
  source_ref TEXT,
  snapshot_path TEXT NOT NULL,
  sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
  sha256_algo TEXT NOT NULL DEFAULT 'sha256',
  size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
  mime_type TEXT,
  collected_at INTEGER NOT NULL,
  collector_name TEXT NOT NULL,
  collector_version TEXT NOT NULL,
  parser_version TEXT,
  acquisition_method TEXT,
  payload_json TEXT,
  is_encrypted INTEGER NOT NULL DEFAULT 0 CHECK (is_encrypted IN (0, 1)),
  encryption_note TEXT,
  record_hash TEXT NOT NULL CHECK (length(record_hash) = 64),
  created_at INTEGER NOT NULL,
  FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE,
  FOREIGN KEY (device_id) REFERENCES case_devices(device_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_artifacts_case_id ON artifacts(case_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_device_id ON artifacts(device_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_case_type ON artifacts(case_id, artifact_type);
CREATE INDEX IF NOT EXISTS idx_artifacts_collected_at ON artifacts(collected_at);
CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256);

CREATE TABLE IF NOT EXISTS rule_bundles (
  bundle_id TEXT PRIMARY KEY,
  bundle_type TEXT NOT NULL CHECK (bundle_type IN ('wallet_signatures', 'exchange_domains')),
  bundle_version TEXT NOT NULL,
  sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
  source TEXT,
  loaded_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rule_bundles_type_version ON rule_bundles(bundle_type, bundle_version);

CREATE TABLE IF NOT EXISTS rule_hits (
  hit_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  hit_type TEXT NOT NULL CHECK (
    hit_type IN ('wallet_installed', 'exchange_visited', 'wallet_address', 'token_balance')
  ),
  rule_id TEXT NOT NULL,
  rule_name TEXT,
  rule_bundle_id TEXT,
  rule_version TEXT,
  matched_value TEXT NOT NULL,
  first_seen_at INTEGER,
  last_seen_at INTEGER,
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  verdict TEXT NOT NULL DEFAULT 'suspected' CHECK (verdict IN ('confirmed', 'suspected', 'unsupported')),
  detail_json TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE,
  FOREIGN KEY (device_id) REFERENCES case_devices(device_id) ON DELETE CASCADE,
  FOREIGN KEY (rule_bundle_id) REFERENCES rule_bundles(bundle_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_rule_hits_case_id ON rule_hits(case_id);
CREATE INDEX IF NOT EXISTS idx_rule_hits_case_type ON rule_hits(case_id, hit_type);
CREATE INDEX IF NOT EXISTS idx_rule_hits_case_value ON rule_hits(case_id, matched_value);
CREATE INDEX IF NOT EXISTS idx_rule_hits_confidence ON rule_hits(confidence);

CREATE TABLE IF NOT EXISTS hit_artifact_links (
  hit_id TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  relation TEXT NOT NULL DEFAULT 'direct' CHECK (relation IN ('direct', 'derived')),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (hit_id, artifact_id),
  FOREIGN KEY (hit_id) REFERENCES rule_hits(hit_id) ON DELETE CASCADE,
  FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_hit_artifact_links_artifact ON hit_artifact_links(artifact_id);

CREATE TABLE IF NOT EXISTS audit_logs (
  event_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  device_id TEXT,
  event_type TEXT NOT NULL,
  action TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('started', 'success', 'failed', 'skipped')),
  actor TEXT,
  source TEXT,
  detail_json TEXT,
  occurred_at INTEGER NOT NULL,
  chain_prev_hash TEXT,
  chain_hash TEXT NOT NULL CHECK (length(chain_hash) = 64),
  FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE,
  FOREIGN KEY (device_id) REFERENCES case_devices(device_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_case_time ON audit_logs(case_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_case_status ON audit_logs(case_id, status);

CREATE TABLE IF NOT EXISTS reports (
  report_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  report_type TEXT NOT NULL CHECK (
    report_type IN ('internal_html', 'internal_json', 'forensic_pdf', 'forensic_zip')
  ),
  file_path TEXT NOT NULL,
  sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
  generated_at INTEGER NOT NULL,
  generator_version TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ready' CHECK (status IN ('ready', 'failed')),
  FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_reports_case_type ON reports(case_id, report_type);
CREATE INDEX IF NOT EXISTS idx_reports_generated_at ON reports(generated_at);

CREATE TRIGGER IF NOT EXISTS trg_cases_updated_at
AFTER UPDATE ON cases
FOR EACH ROW
BEGIN
  UPDATE cases SET updated_at = strftime('%s','now') WHERE case_id = OLD.case_id;
END;

CREATE TRIGGER IF NOT EXISTS trg_case_devices_updated_at
AFTER UPDATE ON case_devices
FOR EACH ROW
BEGIN
  UPDATE case_devices SET updated_at = strftime('%s','now') WHERE device_id = OLD.device_id;
END;

COMMIT;
