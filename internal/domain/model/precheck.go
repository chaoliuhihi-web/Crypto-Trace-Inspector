package model

import "encoding/json"

// PrecheckStatus 表示前置条件检查结果状态。
type PrecheckStatus string

const (
	// PrecheckPassed 表示检查通过。
	PrecheckPassed PrecheckStatus = "passed"
	// PrecheckFailed 表示检查失败。
	PrecheckFailed PrecheckStatus = "failed"
	// PrecheckSkipped 表示检查跳过（例如当前环境不支持该项）。
	PrecheckSkipped PrecheckStatus = "skipped"
)

// PrecheckResult 表示一次采集前置条件检查记录（落入 precheck_results 表）。
type PrecheckResult struct {
	ID         string          `json:"check_id,omitempty"`
	CaseID     string          `json:"case_id"`
	DeviceID   string          `json:"device_id,omitempty"`
	ScanScope  string          `json:"scan_scope"`
	CheckCode  string          `json:"check_code"`
	CheckName  string          `json:"check_name"`
	Required   bool            `json:"required"`
	Status     PrecheckStatus  `json:"status"`
	Message    string          `json:"message,omitempty"`
	DetailJSON json.RawMessage `json:"detail_json,omitempty"`
	CheckedAt  int64           `json:"checked_at"`
	RecordHash string          `json:"record_hash,omitempty"`
}
