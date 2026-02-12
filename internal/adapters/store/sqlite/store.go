package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"crypto-inspector/internal/domain/model"
	"crypto-inspector/internal/platform/hash"
	"crypto-inspector/internal/platform/id"
)

// Store 封装与 SQLite 的读写逻辑。
type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// EnsureCase 确保案件存在；如果未传 caseID 则自动创建。
// caseNo 作为执法授权工单/文书编号落库，便于后续审计追溯。
func (s *Store) EnsureCase(ctx context.Context, caseID, caseNo, title, operator, note string) (string, error) {
	now := time.Now().Unix()
	if caseID == "" {
		caseID = id.New("case")
	}
	if title == "" {
		title = "Case"
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cases(case_id, case_no, title, status, created_by, note, created_at, updated_at)
		VALUES(?, ?, ?, 'open', ?, ?, ?, ?)
		ON CONFLICT(case_id) DO UPDATE SET
			updated_at=excluded.updated_at,
			case_no=CASE WHEN excluded.case_no IS NULL OR excluded.case_no='' THEN cases.case_no ELSE excluded.case_no END,
			title=CASE WHEN excluded.title IS NULL OR excluded.title='' THEN cases.title ELSE excluded.title END,
			note=CASE WHEN excluded.note IS NULL OR excluded.note='' THEN cases.note ELSE excluded.note END
	`, caseID, nullIfEmpty(caseNo), title, operator, note, now, now)
	if err != nil {
		return "", fmt.Errorf("upsert case: %w", err)
	}

	return caseID, nil
}

// GetSchemaMetaValue 查询 schema_meta 表指定 key 的 value。
func (s *Store) GetSchemaMetaValue(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `
		SELECT value
		FROM schema_meta
		WHERE key = ?
		LIMIT 1
	`, key).Scan(&v)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("query schema_meta %s: %w", key, err)
	}
	return v, nil
}

// UpsertDeviceWithConnection 将设备写入案件设备表，可指定连接方式（local/usb）。
func (s *Store) UpsertDeviceWithConnection(ctx context.Context, caseID string, d model.Device, connectionType string, authorized bool, authNote string) error {
	now := time.Now().Unix()
	auth := 0
	if authorized {
		auth = 1
	}
	if connectionType == "" {
		connectionType = "local"
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO case_devices(
			device_id, case_id, os_type, device_name, identifier, connection_type,
			is_authorized, auth_note, first_seen_at, last_seen_at, created_at, updated_at
		)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(device_id) DO UPDATE SET
			last_seen_at=excluded.last_seen_at,
			connection_type=excluded.connection_type,
			is_authorized=excluded.is_authorized,
			auth_note=excluded.auth_note,
			updated_at=excluded.updated_at
	`, d.ID, caseID, string(d.OS), d.Name, d.Identifier, connectionType, auth, authNote, now, now, now, now)
	if err != nil {
		return fmt.Errorf("upsert device: %w", err)
	}
	return nil
}

// UpsertDevice 将设备写入案件设备表，连接方式默认为 local。
func (s *Store) UpsertDevice(ctx context.Context, caseID string, d model.Device, authorized bool, authNote string) error {
	return s.UpsertDeviceWithConnection(ctx, caseID, d, "local", authorized, authNote)
}

// SaveArtifacts 批量写入 artifacts，使用事务保证原子性。
func (s *Store) SaveArtifacts(ctx context.Context, artifacts []model.Artifact) error {
	if len(artifacts) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx save artifacts: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO artifacts(
			artifact_id, case_id, device_id, artifact_type, source_ref, snapshot_path,
			sha256, sha256_algo, size_bytes, mime_type, collected_at, collector_name,
			collector_version, parser_version, acquisition_method, payload_json,
			is_encrypted, encryption_note, record_hash, created_at
		)
		VALUES(?, ?, ?, ?, ?, ?, ?, 'sha256', ?, 'application/json', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare insert artifacts: %w", err)
	}
	defer stmt.Close()

	now := time.Now().Unix()
	for _, a := range artifacts {
		_, err = stmt.ExecContext(ctx,
			a.ID,
			a.CaseID,
			a.DeviceID,
			string(a.Type),
			a.SourceRef,
			a.SnapshotPath,
			a.SHA256,
			a.SizeBytes,
			a.CollectedAt,
			a.CollectorName,
			a.CollectorVersion,
			a.ParserVersion,
			a.AcquisitionMethod,
			string(a.PayloadJSON),
			boolToInt(a.IsEncrypted),
			a.EncryptionNote,
			a.RecordHash,
			now,
		)
		if err != nil {
			return fmt.Errorf("insert artifact %s: %w", a.ID, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit save artifacts: %w", err)
	}
	return nil
}

// SavePrecheckResults 批量写入前置条件检查结果。
// 该表用于把“为何可采/为何不可采”的判断过程固化到数据库中。
func (s *Store) SavePrecheckResults(ctx context.Context, checks []model.PrecheckResult) error {
	if len(checks) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx save prechecks: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO precheck_results(
			check_id, case_id, device_id, scan_scope, check_code, check_name,
			required, status, message, detail_json, checked_at, record_hash, created_at
		)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare insert prechecks: %w", err)
	}
	defer stmt.Close()

	now := time.Now().Unix()
	for _, c := range checks {
		checkID := c.ID
		if checkID == "" {
			checkID = id.New("chk")
		}
		checkedAt := c.CheckedAt
		if checkedAt <= 0 {
			checkedAt = now
		}

		detail := c.DetailJSON
		if len(detail) == 0 {
			detail = []byte("{}")
		}

		recordHash := c.RecordHash
		if recordHash == "" {
			recordHash = hash.Text(
				checkID,
				c.CaseID,
				c.DeviceID,
				c.ScanScope,
				c.CheckCode,
				string(c.Status),
				c.Message,
				string(detail),
				fmt.Sprintf("%d", checkedAt),
			)
		}

		_, err = stmt.ExecContext(ctx,
			checkID,
			c.CaseID,
			nullIfEmpty(c.DeviceID),
			c.ScanScope,
			c.CheckCode,
			c.CheckName,
			boolToInt(c.Required),
			string(c.Status),
			c.Message,
			string(detail),
			checkedAt,
			recordHash,
			now,
		)
		if err != nil {
			return fmt.Errorf("insert precheck %s: %w", checkID, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit save prechecks: %w", err)
	}
	return nil
}

// SaveRuleHits 批量写入命中结果，并维护命中-证据关联表。
func (s *Store) SaveRuleHits(ctx context.Context, hits []model.RuleHit) error {
	if len(hits) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx save hits: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	hitStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO rule_hits(
			hit_id, case_id, device_id, hit_type, rule_id, rule_name,
			rule_bundle_id, rule_version, matched_value, first_seen_at, last_seen_at,
			confidence, verdict, detail_json, created_at
		)
		VALUES(?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare insert hits: %w", err)
	}
	defer hitStmt.Close()

	linkStmt, err := tx.PrepareContext(ctx, `
		INSERT OR IGNORE INTO hit_artifact_links(hit_id, artifact_id, relation, created_at)
		VALUES(?, ?, 'direct', ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare insert hit links: %w", err)
	}
	defer linkStmt.Close()

	now := time.Now().Unix()
	for _, h := range hits {
		_, err = hitStmt.ExecContext(ctx,
			h.ID,
			h.CaseID,
			h.DeviceID,
			string(h.Type),
			h.RuleID,
			h.RuleName,
			h.RuleVersion,
			h.MatchedValue,
			h.FirstSeenAt,
			h.LastSeenAt,
			h.Confidence,
			h.Verdict,
			string(h.DetailJSON),
			now,
		)
		if err != nil {
			return fmt.Errorf("insert hit %s: %w", h.ID, err)
		}

		for _, artifactID := range h.ArtifactIDs {
			_, err = linkStmt.ExecContext(ctx, h.ID, artifactID, now)
			if err != nil {
				return fmt.Errorf("insert hit-artifact link (%s,%s): %w", h.ID, artifactID, err)
			}
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit save hits: %w", err)
	}
	return nil
}

// AppendAudit 写入审计日志，并生成链式 hash 以便后续校验完整性。
func (s *Store) AppendAudit(ctx context.Context, caseID, deviceID, eventType, action, status, actor, source string, detail any) error {
	detailJSON := []byte("{}")
	if detail != nil {
		raw, err := json.Marshal(detail)
		if err == nil {
			detailJSON = raw
		}
	}

	prev := ""
	err := s.db.QueryRowContext(ctx, `
		SELECT chain_hash
		FROM audit_logs
		WHERE case_id = ?
		ORDER BY occurred_at DESC, event_id DESC
		LIMIT 1
	`, caseID).Scan(&prev)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("query previous chain hash: %w", err)
	}

	now := time.Now().Unix()
	eventID := id.New("evt")
	chain := hash.Text(prev, caseID, eventType, action, status, fmt.Sprintf("%d", now), string(detailJSON))

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO audit_logs(
			event_id, case_id, device_id, event_type, action, status,
			actor, source, detail_json, occurred_at, chain_prev_hash, chain_hash
		)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, eventID, caseID, nullIfEmpty(deviceID), eventType, action, status, actor, source, string(detailJSON), now, nullIfEmpty(prev), chain)
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}

	return nil
}

// SaveReport 记录报告产物信息，供 UI 或导出流程追踪。
func (s *Store) SaveReport(ctx context.Context, caseID, reportType, filePath, sha256, generatorVersion, status string) (string, error) {
	reportID := id.New("report")
	now := time.Now().Unix()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO reports(
			report_id, case_id, report_type, file_path, sha256, generated_at, generator_version, status
		)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)
	`, reportID, caseID, reportType, filePath, sha256, now, generatorVersion, status)
	if err != nil {
		return "", fmt.Errorf("insert report: %w", err)
	}
	return reportID, nil
}

// GetCaseOverview 返回案件聚合摘要（设备数/证据数/命中数/报告数）。
func (s *Store) GetCaseOverview(ctx context.Context, caseID string) (*model.CaseOverview, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT
			c.case_id,
			COALESCE(c.case_no, ''),
			COALESCE(c.title, ''),
			c.status,
			COALESCE(c.created_by, ''),
			COALESCE(c.note, ''),
			c.created_at,
			c.updated_at,
			(SELECT COUNT(*) FROM case_devices d WHERE d.case_id = c.case_id),
			(SELECT COUNT(*) FROM artifacts a WHERE a.case_id = c.case_id),
			(SELECT COUNT(*) FROM rule_hits h WHERE h.case_id = c.case_id),
			(SELECT COUNT(*) FROM reports r WHERE r.case_id = c.case_id)
		FROM cases c
		WHERE c.case_id = ?
	`, caseID)

	var out model.CaseOverview
	if err := row.Scan(
		&out.CaseID,
		&out.CaseNo,
		&out.Title,
		&out.Status,
		&out.CreatedBy,
		&out.Note,
		&out.CreatedAt,
		&out.UpdatedAt,
		&out.DeviceCount,
		&out.ArtifactCount,
		&out.HitCount,
		&out.ReportCount,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("query case overview: %w", err)
	}
	return &out, nil
}

// ListCaseHitDetails 查询案件命中明细，并附带证据 ID 列表。
// hitType 为空时返回全部类型。
func (s *Store) ListCaseHitDetails(ctx context.Context, caseID, hitType string) ([]model.HitDetail, error) {
	var (
		rows *sql.Rows
		err  error
	)

	// 重要：这里不能在 rows.Next() 循环里再发起子查询（例如按 hit_id 再查 artifact_ids），
	// 因为 webapp/CLI 都把 SQLite 连接池设置为单连接（SetMaxOpenConns(1)），
	// 子查询会等待“第二条连接”而导致死锁。
	//
	// 解决方式：使用 LEFT JOIN + GROUP_CONCAT 一次性把 artifact_id 聚合回来。
	if hitType == "" {
		rows, err = s.db.QueryContext(ctx, `
			SELECT
				h.hit_id, h.case_id, h.device_id, h.hit_type, h.rule_id,
				COALESCE(h.rule_name, ''), COALESCE(h.rule_version, ''), h.matched_value,
				COALESCE(h.first_seen_at, 0), COALESCE(h.last_seen_at, 0),
				h.confidence, h.verdict, COALESCE(h.detail_json, '{}'),
				COALESCE(GROUP_CONCAT(l.artifact_id, ','), '')
			FROM rule_hits h
			LEFT JOIN hit_artifact_links l ON l.hit_id = h.hit_id
			WHERE h.case_id = ?
			GROUP BY h.hit_id
			ORDER BY h.hit_type, h.confidence DESC, h.last_seen_at DESC
		`, caseID)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT
				h.hit_id, h.case_id, h.device_id, h.hit_type, h.rule_id,
				COALESCE(h.rule_name, ''), COALESCE(h.rule_version, ''), h.matched_value,
				COALESCE(h.first_seen_at, 0), COALESCE(h.last_seen_at, 0),
				h.confidence, h.verdict, COALESCE(h.detail_json, '{}'),
				COALESCE(GROUP_CONCAT(l.artifact_id, ','), '')
			FROM rule_hits h
			LEFT JOIN hit_artifact_links l ON l.hit_id = h.hit_id
			WHERE h.case_id = ? AND h.hit_type = ?
			GROUP BY h.hit_id
			ORDER BY h.hit_type, h.confidence DESC, h.last_seen_at DESC
		`, caseID, hitType)
	}
	if err != nil {
		return nil, fmt.Errorf("query case hit details: %w", err)
	}
	defer rows.Close()

	var out []model.HitDetail
	for rows.Next() {
		var item model.HitDetail
		var artifactIDsRaw string
		if err := rows.Scan(
			&item.HitID,
			&item.CaseID,
			&item.DeviceID,
			&item.HitType,
			&item.RuleID,
			&item.RuleName,
			&item.RuleVersion,
			&item.MatchedValue,
			&item.FirstSeenAt,
			&item.LastSeenAt,
			&item.Confidence,
			&item.Verdict,
			&item.DetailJSON,
			&artifactIDsRaw,
		); err != nil {
			return nil, fmt.Errorf("scan hit detail: %w", err)
		}

		if strings.TrimSpace(artifactIDsRaw) != "" {
			parts := strings.Split(artifactIDsRaw, ",")
			ids := make([]string, 0, len(parts))
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					ids = append(ids, p)
				}
			}
			sort.Strings(ids)
			item.ArtifactIDs = ids
		} else {
			item.ArtifactIDs = []string{}
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate hit details: %w", err)
	}

	return out, nil
}

// GetLatestReportByCase 返回案件最新报告索引。
func (s *Store) GetLatestReportByCase(ctx context.Context, caseID string) (*model.ReportInfo, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT report_id, case_id, report_type, file_path, sha256, generated_at, generator_version, status
		FROM reports
		WHERE case_id = ?
		ORDER BY generated_at DESC, report_id DESC
		LIMIT 1
	`, caseID)
	return scanReportInfo(row)
}

// GetReportByID 按报告 ID 查询报告索引。
func (s *Store) GetReportByID(ctx context.Context, reportID string) (*model.ReportInfo, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT report_id, case_id, report_type, file_path, sha256, generated_at, generator_version, status
		FROM reports
		WHERE report_id = ?
		LIMIT 1
	`, reportID)
	return scanReportInfo(row)
}

// ListReportsByCase 返回案件全部报告索引，按生成时间倒序。
func (s *Store) ListReportsByCase(ctx context.Context, caseID string) ([]model.ReportInfo, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT report_id, case_id, report_type, file_path, sha256, generated_at, generator_version, status
		FROM reports
		WHERE case_id = ?
		ORDER BY generated_at DESC, report_id DESC
	`, caseID)
	if err != nil {
		return nil, fmt.Errorf("query reports by case: %w", err)
	}
	defer rows.Close()

	var out []model.ReportInfo
	for rows.Next() {
		var item model.ReportInfo
		if err := rows.Scan(
			&item.ReportID,
			&item.CaseID,
			&item.ReportType,
			&item.FilePath,
			&item.SHA256,
			&item.GeneratedAt,
			&item.GeneratorVersion,
			&item.Status,
		); err != nil {
			return nil, fmt.Errorf("scan report: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate reports: %w", err)
	}
	if out == nil {
		out = []model.ReportInfo{}
	}
	return out, nil
}

func scanReportInfo(row *sql.Row) (*model.ReportInfo, error) {
	var out model.ReportInfo
	if err := row.Scan(
		&out.ReportID,
		&out.CaseID,
		&out.ReportType,
		&out.FilePath,
		&out.SHA256,
		&out.GeneratedAt,
		&out.GeneratorVersion,
		&out.Status,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("query report info: %w", err)
	}
	return &out, nil
}

// ListCases 返回案件列表，按更新时间倒序。
func (s *Store) ListCases(ctx context.Context, limit, offset int) ([]model.CaseSummary, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT
			c.case_id,
			COALESCE(c.case_no, ''),
			COALESCE(c.title, ''),
			c.status,
			COALESCE(c.created_by, ''),
			COALESCE(c.note, ''),
			c.created_at,
			c.updated_at
		FROM cases c
		ORDER BY c.updated_at DESC, c.created_at DESC
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("query cases: %w", err)
	}
	defer rows.Close()

	var out []model.CaseSummary
	for rows.Next() {
		var item model.CaseSummary
		if err := rows.Scan(
			&item.CaseID,
			&item.CaseNo,
			&item.Title,
			&item.Status,
			&item.CreatedBy,
			&item.Note,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan case summary: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate case summaries: %w", err)
	}
	if out == nil {
		out = []model.CaseSummary{}
	}
	return out, nil
}

// ListPrecheckResults 返回案件的前置条件检查明细。
func (s *Store) ListPrecheckResults(ctx context.Context, caseID string) ([]model.PrecheckResult, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			check_id,
			case_id,
			COALESCE(device_id, ''),
			scan_scope,
			check_code,
			check_name,
			required,
			status,
			COALESCE(message, ''),
			COALESCE(detail_json, '{}'),
			checked_at,
			record_hash
		FROM precheck_results
		WHERE case_id = ?
		ORDER BY checked_at ASC, check_id ASC
	`, caseID)
	if err != nil {
		return nil, fmt.Errorf("query prechecks: %w", err)
	}
	defer rows.Close()

	var out []model.PrecheckResult
	for rows.Next() {
		var item model.PrecheckResult
		var requiredInt int
		var status string
		var detail string
		if err := rows.Scan(
			&item.ID,
			&item.CaseID,
			&item.DeviceID,
			&item.ScanScope,
			&item.CheckCode,
			&item.CheckName,
			&requiredInt,
			&status,
			&item.Message,
			&detail,
			&item.CheckedAt,
			&item.RecordHash,
		); err != nil {
			return nil, fmt.Errorf("scan precheck: %w", err)
		}
		item.Required = requiredInt == 1
		item.Status = model.PrecheckStatus(status)
		item.DetailJSON = json.RawMessage(detail)
		if item.DeviceID == "" {
			item.DeviceID = ""
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate prechecks: %w", err)
	}
	if out == nil {
		out = []model.PrecheckResult{}
	}
	return out, nil
}

// ListAuditLogs 返回案件审计日志（按时间升序）。
func (s *Store) ListAuditLogs(ctx context.Context, caseID string, limit int) ([]model.AuditLog, error) {
	if limit <= 0 {
		limit = 500
	}
	if limit > 5000 {
		limit = 5000
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT
			event_id,
			case_id,
			COALESCE(device_id, ''),
			event_type,
			action,
			status,
			COALESCE(actor, ''),
			COALESCE(source, ''),
			COALESCE(detail_json, '{}'),
			occurred_at,
			COALESCE(chain_prev_hash, ''),
			chain_hash
		FROM audit_logs
		WHERE case_id = ?
		ORDER BY occurred_at ASC, event_id ASC
		LIMIT ?
	`, caseID, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit logs: %w", err)
	}
	defer rows.Close()

	var out []model.AuditLog
	for rows.Next() {
		var item model.AuditLog
		var detail string
		if err := rows.Scan(
			&item.EventID,
			&item.CaseID,
			&item.DeviceID,
			&item.EventType,
			&item.Action,
			&item.Status,
			&item.Actor,
			&item.Source,
			&detail,
			&item.OccurredAt,
			&item.ChainPrevHash,
			&item.ChainHash,
		); err != nil {
			return nil, fmt.Errorf("scan audit log: %w", err)
		}
		item.DetailJSON = json.RawMessage(detail)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit logs: %w", err)
	}
	if out == nil {
		out = []model.AuditLog{}
	}
	return out, nil
}

// ListArtifactsByCase 返回案件证据列表（不含 payload_json）。
func (s *Store) ListArtifactsByCase(ctx context.Context, caseID string) ([]model.ArtifactInfo, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			artifact_id,
			case_id,
			device_id,
			artifact_type,
			COALESCE(source_ref, ''),
			snapshot_path,
			sha256,
			size_bytes,
			collected_at,
			COALESCE(collector_name, ''),
			COALESCE(collector_version, ''),
			COALESCE(acquisition_method, '')
		FROM artifacts
		WHERE case_id = ?
		ORDER BY collected_at DESC, artifact_id DESC
	`, caseID)
	if err != nil {
		return nil, fmt.Errorf("query artifacts: %w", err)
	}
	defer rows.Close()

	var out []model.ArtifactInfo
	for rows.Next() {
		var item model.ArtifactInfo
		if err := rows.Scan(
			&item.ArtifactID,
			&item.CaseID,
			&item.DeviceID,
			&item.ArtifactType,
			&item.SourceRef,
			&item.SnapshotPath,
			&item.SHA256,
			&item.SizeBytes,
			&item.CollectedAt,
			&item.CollectorName,
			&item.CollectorVersion,
			&item.AcquisitionMethod,
		); err != nil {
			return nil, fmt.Errorf("scan artifact info: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate artifacts: %w", err)
	}
	if out == nil {
		out = []model.ArtifactInfo{}
	}
	return out, nil
}

// GetArtifactInfo 按 artifact_id 查询证据索引信息。
func (s *Store) GetArtifactInfo(ctx context.Context, artifactID string) (*model.ArtifactInfo, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT
			artifact_id,
			case_id,
			device_id,
			artifact_type,
			COALESCE(source_ref, ''),
			snapshot_path,
			sha256,
			size_bytes,
			collected_at,
			COALESCE(collector_name, ''),
			COALESCE(collector_version, ''),
			COALESCE(acquisition_method, '')
		FROM artifacts
		WHERE artifact_id = ?
		LIMIT 1
	`, artifactID)

	var item model.ArtifactInfo
	if err := row.Scan(
		&item.ArtifactID,
		&item.CaseID,
		&item.DeviceID,
		&item.ArtifactType,
		&item.SourceRef,
		&item.SnapshotPath,
		&item.SHA256,
		&item.SizeBytes,
		&item.CollectedAt,
		&item.CollectorName,
		&item.CollectorVersion,
		&item.AcquisitionMethod,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("query artifact info: %w", err)
	}
	return &item, nil
}

// ListCaseDevices 返回案件关联的设备列表。
func (s *Store) ListCaseDevices(ctx context.Context, caseID string) ([]model.CaseDevice, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			device_id,
			case_id,
			os_type,
			COALESCE(device_name, ''),
			COALESCE(identifier, ''),
			connection_type,
			is_authorized,
			COALESCE(auth_note, ''),
			first_seen_at,
			last_seen_at
		FROM case_devices
		WHERE case_id = ?
		ORDER BY os_type, device_name, device_id
	`, caseID)
	if err != nil {
		return nil, fmt.Errorf("query case devices: %w", err)
	}
	defer rows.Close()

	var out []model.CaseDevice
	for rows.Next() {
		var item model.CaseDevice
		var authInt int
		if err := rows.Scan(
			&item.DeviceID,
			&item.CaseID,
			&item.OSType,
			&item.DeviceName,
			&item.Identifier,
			&item.ConnectionType,
			&authInt,
			&item.AuthNote,
			&item.FirstSeenAt,
			&item.LastSeenAt,
		); err != nil {
			return nil, fmt.Errorf("scan case device: %w", err)
		}
		item.Authorized = authInt == 1
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate case devices: %w", err)
	}
	if out == nil {
		out = []model.CaseDevice{}
	}
	return out, nil
}

func (s *Store) listArtifactIDsByHit(ctx context.Context, hitID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT artifact_id
		FROM hit_artifact_links
		WHERE hit_id = ?
	`, hitID)
	if err != nil {
		return nil, fmt.Errorf("query artifact ids by hit: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan artifact id by hit: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate artifact ids by hit: %w", err)
	}
	sort.Strings(ids)
	return ids, nil
}

// SQLite 中没有布尔类型，统一转 0/1 存储。
func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// 空字符串按 NULL 写入，避免无意义空值污染查询条件。
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
