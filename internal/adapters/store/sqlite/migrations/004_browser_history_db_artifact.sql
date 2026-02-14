-- 004_browser_history_db_artifact.sql
--
-- 目的：
-- - artifacts.artifact_type 增加一个新枚举值：browser_history_db（浏览历史原始 SQLite DB 快照，zip）
-- - schema_version 升级到 3
--
-- 注意：
-- - SQLite 无法直接修改 CHECK 约束的枚举列表，因此通过“重建表”方式完成升级。
-- - 该迁移依赖 migrator 的“只执行一次”语义（schema_migrations），不要求可重复执行。

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

INSERT OR REPLACE INTO schema_meta (key, value) VALUES
  ('schema_version', '3');

CREATE TABLE artifacts_new (
  artifact_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  artifact_type TEXT NOT NULL CHECK (
    artifact_type IN (
      'installed_apps',
      'browser_history',
      'browser_extension',
      'browser_history_db',
      'mobile_packages',
      'mobile_backup',
      'chain_balance'
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

INSERT INTO artifacts_new(
  artifact_id, case_id, device_id, artifact_type, source_ref, snapshot_path,
  sha256, sha256_algo, size_bytes, mime_type, collected_at, collector_name,
  collector_version, parser_version, acquisition_method, payload_json,
  is_encrypted, encryption_note, record_hash, created_at
)
SELECT
  artifact_id, case_id, device_id, artifact_type, source_ref, snapshot_path,
  sha256, sha256_algo, size_bytes, mime_type, collected_at, collector_name,
  collector_version, parser_version, acquisition_method, payload_json,
  is_encrypted, encryption_note, record_hash, created_at
FROM artifacts;

DROP TABLE artifacts;
ALTER TABLE artifacts_new RENAME TO artifacts;

-- 重建索引（与 001_init.sql 对齐）
CREATE INDEX IF NOT EXISTS idx_artifacts_case_id ON artifacts(case_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_device_id ON artifacts(device_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_case_type ON artifacts(case_id, artifact_type);
CREATE INDEX IF NOT EXISTS idx_artifacts_collected_at ON artifacts(collected_at);
CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256);

COMMIT;

PRAGMA foreign_keys = ON;

