package auditverify

import (
	"fmt"
	"testing"

	"crypto-inspector/internal/domain/model"
	"crypto-inspector/internal/platform/hash"
)

func TestVerifyAuditLogs_OK(t *testing.T) {
	logs := []model.AuditLog{
		{
			EventID:    "evt_1",
			CaseID:     "case_1",
			EventType:  "host_scan",
			Action:     "scan_start",
			Status:     "started",
			DetailJSON: []byte(`{"k":"v"}`),
			OccurredAt: 1700000000,
		},
		{
			EventID:    "evt_2",
			CaseID:     "case_1",
			EventType:  "host_scan",
			Action:     "scan_finish",
			Status:     "success",
			DetailJSON: []byte(`{}`),
			OccurredAt: 1700000001,
		},
	}

	prev := ""
	for i := range logs {
		logs[i].ChainPrevHash = prev
		logs[i].ChainHash = hash.Text(
			prev,
			logs[i].CaseID,
			logs[i].EventType,
			logs[i].Action,
			logs[i].Status,
			fmt.Sprintf("%d", logs[i].OccurredAt),
			string(logs[i].DetailJSON),
		)
		prev = logs[i].ChainHash
	}

	res := VerifyAuditLogs(logs)
	if !res.OK {
		t.Fatalf("expected OK, got %+v", res)
	}
	if res.Total != 2 || res.Failed != 0 {
		t.Fatalf("unexpected counters: %+v", res)
	}
}

func TestVerifyAuditLogs_Mismatch(t *testing.T) {
	logs := []model.AuditLog{
		{
			EventID:    "evt_1",
			CaseID:     "case_1",
			EventType:  "x",
			Action:     "a",
			Status:     "s",
			DetailJSON: nil, // 兜底：空 detail 视为 "{}"
			OccurredAt: 1,
		},
		{
			EventID:    "evt_2",
			CaseID:     "case_1",
			EventType:  "y",
			Action:     "b",
			Status:     "t",
			DetailJSON: []byte(`{"n":1}`),
			OccurredAt: 2,
		},
	}

	// 先构造一条正确链，再篡改第二条的 chain_hash。
	prev := ""
	for i := range logs {
		logs[i].ChainPrevHash = prev
		detail := string(logs[i].DetailJSON)
		if detail == "" {
			detail = "{}"
		}
		logs[i].ChainHash = hash.Text(prev, logs[i].CaseID, logs[i].EventType, logs[i].Action, logs[i].Status, fmt.Sprintf("%d", logs[i].OccurredAt), detail)
		prev = logs[i].ChainHash
	}
	logs[1].ChainHash = "deadbeef"

	res := VerifyAuditLogs(logs)
	if res.OK {
		t.Fatalf("expected NOT OK")
	}
	if res.Failed == 0 || res.ChainHashFailed == 0 {
		t.Fatalf("expected chain hash mismatch, got %+v", res)
	}
}
