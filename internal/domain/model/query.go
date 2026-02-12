package model

// HitDetail 是给 UI/CLI 使用的命中明细结构。
type HitDetail struct {
	HitID        string   `json:"hit_id"`
	CaseID       string   `json:"case_id"`
	DeviceID     string   `json:"device_id"`
	HitType      string   `json:"hit_type"`
	RuleID       string   `json:"rule_id"`
	RuleName     string   `json:"rule_name"`
	RuleVersion  string   `json:"rule_version"`
	MatchedValue string   `json:"matched_value"`
	FirstSeenAt  int64    `json:"first_seen_at"`
	LastSeenAt   int64    `json:"last_seen_at"`
	Confidence   float64  `json:"confidence"`
	Verdict      string   `json:"verdict"`
	DetailJSON   string   `json:"detail_json,omitempty"`
	ArtifactIDs  []string `json:"artifact_ids,omitempty"`
}

// ReportInfo 表示报告索引信息（reports 表）。
type ReportInfo struct {
	ReportID         string `json:"report_id"`
	CaseID           string `json:"case_id"`
	ReportType       string `json:"report_type"`
	FilePath         string `json:"file_path"`
	SHA256           string `json:"sha256"`
	GeneratedAt      int64  `json:"generated_at"`
	GeneratorVersion string `json:"generator_version"`
	Status           string `json:"status"`
}

// CaseOverview 是案件摘要，便于 UI 首页展示。
type CaseOverview struct {
	CaseID        string `json:"case_id"`
	CaseNo        string `json:"case_no,omitempty"`
	Title         string `json:"title,omitempty"`
	Status        string `json:"status"`
	CreatedBy     string `json:"created_by,omitempty"`
	Note          string `json:"note,omitempty"`
	CreatedAt     int64  `json:"created_at"`
	UpdatedAt     int64  `json:"updated_at"`
	DeviceCount   int    `json:"device_count"`
	ArtifactCount int    `json:"artifact_count"`
	HitCount      int    `json:"hit_count"`
	ReportCount   int    `json:"report_count"`
}
