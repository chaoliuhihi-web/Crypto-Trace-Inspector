package model

import "encoding/json"

// CaseSummary 是案件列表页用的轻量结构（避免每次都做聚合统计）。
type CaseSummary struct {
	CaseID    string `json:"case_id"`
	CaseNo    string `json:"case_no,omitempty"`
	Title     string `json:"title,omitempty"`
	Status    string `json:"status"`
	CreatedBy string `json:"created_by,omitempty"`
	Note      string `json:"note,omitempty"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// AuditLog 表示一条审计日志记录（audit_logs 表）。
type AuditLog struct {
	EventID       string          `json:"event_id"`
	CaseID        string          `json:"case_id"`
	DeviceID      string          `json:"device_id,omitempty"`
	EventType     string          `json:"event_type"`
	Action        string          `json:"action"`
	Status        string          `json:"status"`
	Actor         string          `json:"actor,omitempty"`
	Source        string          `json:"source,omitempty"`
	DetailJSON    json.RawMessage `json:"detail_json,omitempty"`
	OccurredAt    int64           `json:"occurred_at"`
	ChainPrevHash string          `json:"chain_prev_hash,omitempty"`
	ChainHash     string          `json:"chain_hash"`
}

// ArtifactInfo 是证据列表页用的轻量结构（不包含 payload_json）。
type ArtifactInfo struct {
	ArtifactID        string `json:"artifact_id"`
	CaseID            string `json:"case_id"`
	DeviceID          string `json:"device_id"`
	ArtifactType      string `json:"artifact_type"`
	SourceRef         string `json:"source_ref,omitempty"`
	SnapshotPath      string `json:"snapshot_path"`
	SHA256            string `json:"sha256"`
	SizeBytes         int64  `json:"size_bytes"`
	CollectedAt       int64  `json:"collected_at"`
	CollectorName     string `json:"collector_name,omitempty"`
	CollectorVersion  string `json:"collector_version,omitempty"`
	AcquisitionMethod string `json:"acquisition_method,omitempty"`
}

// CaseDevice 是案件关联设备信息（case_devices 表）。
type CaseDevice struct {
	DeviceID       string `json:"device_id"`
	CaseID         string `json:"case_id"`
	OSType         string `json:"os_type"`
	DeviceName     string `json:"device_name,omitempty"`
	Identifier     string `json:"identifier,omitempty"`
	ConnectionType string `json:"connection_type"`
	Authorized     bool   `json:"authorized"`
	AuthNote       string `json:"auth_note,omitempty"`
	FirstSeenAt    int64  `json:"first_seen_at"`
	LastSeenAt     int64  `json:"last_seen_at"`
}
