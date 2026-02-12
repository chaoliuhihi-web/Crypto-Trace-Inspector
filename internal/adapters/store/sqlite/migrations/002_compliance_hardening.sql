BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS precheck_results (
  check_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  device_id TEXT,
  scan_scope TEXT NOT NULL CHECK (scan_scope IN ('host', 'mobile', 'general')),
  check_code TEXT NOT NULL,
  check_name TEXT NOT NULL,
  required INTEGER NOT NULL DEFAULT 1 CHECK (required IN (0, 1)),
  status TEXT NOT NULL CHECK (status IN ('passed', 'failed', 'skipped')),
  message TEXT,
  detail_json TEXT,
  checked_at INTEGER NOT NULL,
  record_hash TEXT NOT NULL CHECK (length(record_hash) = 64),
  created_at INTEGER NOT NULL,
  FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_precheck_case_time ON precheck_results(case_id, checked_at);
CREATE INDEX IF NOT EXISTS idx_precheck_case_status ON precheck_results(case_id, status);
CREATE INDEX IF NOT EXISTS idx_precheck_case_code ON precheck_results(case_id, check_code);

-- 审计日志采用只追加模型：禁止 UPDATE / DELETE，避免链路被篡改。
CREATE TRIGGER IF NOT EXISTS trg_audit_logs_prevent_update
BEFORE UPDATE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'audit_logs is append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_logs_prevent_delete
BEFORE DELETE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'audit_logs is append-only');
END;

COMMIT;
