package auditverify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"crypto-inspector/internal/domain/model"
	"crypto-inspector/internal/platform/hash"
)

// FailureItem 表示一次审计链校验失败的明细项（用于 UI/CLI 展示）。
type FailureItem struct {
	Index int `json:"index"`

	EventID    string `json:"event_id"`
	OccurredAt int64  `json:"occurred_at"`
	EventType  string `json:"event_type"`
	Action     string `json:"action"`
	Status     string `json:"status"`

	// PrevHashMismatch 表示当前记录的 chain_prev_hash 与上一条记录 chain_hash 不一致。
	PrevHashMismatch bool   `json:"prev_hash_mismatch"`
	ExpectedPrevHash string `json:"expected_prev_hash,omitempty"`
	ActualPrevHash   string `json:"actual_prev_hash,omitempty"`

	// ChainHashMismatch 表示当前记录 chain_hash 与按公式重算的值不一致。
	ChainHashMismatch bool   `json:"chain_hash_mismatch"`
	ExpectedChainHash string `json:"expected_chain_hash,omitempty"`
	ActualChainHash   string `json:"actual_chain_hash,omitempty"`

	Message string `json:"message,omitempty"`
}

// Result 是审计链强校验结果。
type Result struct {
	OK bool `json:"ok"`

	Total int `json:"total"`

	Failed          int `json:"failed"`
	PrevHashFailed  int `json:"prev_hash_failed"`
	ChainHashFailed int `json:"chain_hash_failed"`

	LastChainHash string `json:"last_chain_hash,omitempty"`

	Failures []FailureItem `json:"failures,omitempty"`
}

// VerifyAuditLogs 对 audit_logs 做强校验：
// 1) chain_prev_hash 连续性
// 2) 重算 chain_hash 并与存量字段对比
//
// 校验公式必须与 Store.AppendAudit 保持一致。
func VerifyAuditLogs(logs []model.AuditLog) Result {
	res := Result{
		OK:       true,
		Total:    len(logs),
		Failures: []FailureItem{},
	}

	prev := ""
	for i, it := range logs {
		expectedPrev := prev
		actualPrev := strings.TrimSpace(it.ChainPrevHash)

		// 关键点：审计链 hash 的输入 detail_json 来自入库时的 json.Marshal（紧凑 JSON）。
		// 但在司法导出 ZIP 的 manifest.json 中，整体会被 MarshalIndent 美化，导致 detail_json 出现缩进/换行。
		// 因此这里必须先 compact，消除“仅格式不同”的影响，才能对比出真正的篡改差异。
		detail := compactJSON(it.DetailJSON)
		expectedChain := hash.Text(
			expectedPrev,
			it.CaseID,
			it.EventType,
			it.Action,
			it.Status,
			fmt.Sprintf("%d", it.OccurredAt),
			detail,
		)
		actualChain := strings.TrimSpace(it.ChainHash)

		prevMismatch := actualPrev != expectedPrev
		chainMismatch := actualChain != expectedChain

		if prevMismatch || chainMismatch {
			res.OK = false
			res.Failed++
			if prevMismatch {
				res.PrevHashFailed++
			}
			if chainMismatch {
				res.ChainHashFailed++
			}

			msg := ""
			switch {
			case prevMismatch && chainMismatch:
				msg = "chain_prev_hash and chain_hash mismatch"
			case prevMismatch:
				msg = "chain_prev_hash mismatch"
			case chainMismatch:
				msg = "chain_hash mismatch"
			}

			res.Failures = append(res.Failures, FailureItem{
				Index:      i,
				EventID:    it.EventID,
				OccurredAt: it.OccurredAt,
				EventType:  it.EventType,
				Action:     it.Action,
				Status:     it.Status,

				PrevHashMismatch: prevMismatch,
				ExpectedPrevHash: expectedPrev,
				ActualPrevHash:   actualPrev,

				ChainHashMismatch: chainMismatch,
				ExpectedChainHash: expectedChain,
				ActualChainHash:   actualChain,

				Message: msg,
			})
		}

		// 链推进：以“数据库中记录的 chain_hash”为准，这样可以把“错误链”继续向后验证并定位更多异常。
		prev = actualChain
		res.LastChainHash = actualChain
	}

	return res
}

func compactJSON(in []byte) string {
	if len(bytes.TrimSpace(in)) == 0 {
		return "{}"
	}
	var b bytes.Buffer
	if err := json.Compact(&b, in); err == nil {
		return b.String()
	}
	// 兜底：出现非 JSON（理论上不应发生），仍然尽量保持与原始输入一致。
	return strings.TrimSpace(string(in))
}
