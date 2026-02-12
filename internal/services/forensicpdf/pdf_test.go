package forensicpdf

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	sqliteadapter "crypto-inspector/internal/adapters/store/sqlite"
	"crypto-inspector/internal/domain/model"
	"crypto-inspector/internal/platform/hash"
	"crypto-inspector/internal/platform/id"

	_ "modernc.org/sqlite"
)

func TestGenerateForensicPDF_CreatesReportAndFile(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "inspector.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		t.Fatalf("set busy_timeout: %v", err)
	}

	m := sqliteadapter.NewMigrator(db)
	if err := m.Up(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	store := sqliteadapter.NewStore(db)
	caseID, err := store.EnsureCase(ctx, "", "AUTH-ORDER-001", "PDF Test", "tester", "note")
	if err != nil {
		t.Fatalf("ensure case: %v", err)
	}

	// 设备
	dev := model.Device{
		ID:         id.New("dev"),
		Name:       "test-host",
		OS:         model.OSWindows,
		Identifier: "host-identifier",
	}
	if err := store.UpsertDeviceWithConnection(ctx, caseID, dev, "local", true, "authorized"); err != nil {
		t.Fatalf("upsert device: %v", err)
	}

	// 证据：写一个最小 JSON 快照文件，计算 sha256 + record_hash。
	evidenceDir := filepath.Join(tmp, "evidence")
	if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
		t.Fatalf("mkdir evidence: %v", err)
	}
	snap1 := filepath.Join(evidenceDir, "artifact1.json")
	if err := os.WriteFile(snap1, []byte(`{"hello":"world"}`), 0o644); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	sum1, size1, err := hash.File(snap1)
	if err != nil {
		t.Fatalf("hash snapshot: %v", err)
	}
	collectedAt := time.Now().Unix()
	a1 := model.Artifact{
		ID:                id.New("art"),
		CaseID:            caseID,
		DeviceID:          dev.ID,
		Type:              model.ArtifactBrowserHistory,
		SourceRef:         "unit_test",
		SnapshotPath:      snap1,
		SHA256:            sum1,
		SizeBytes:         size1,
		CollectedAt:       collectedAt,
		CollectorName:     "unit-test",
		CollectorVersion:  "0.0.0",
		ParserVersion:     "0.0.0",
		AcquisitionMethod: "test",
		PayloadJSON:       []byte(`{"k":"v"}`),
		IsEncrypted:       false,
		EncryptionNote:    "",
		RecordHash: hash.Text(
			caseID,
			dev.ID,
			string(model.ArtifactBrowserHistory),
			snap1,
			sum1,
			"0",
			"unit-test",
			"0.0.0",
			"0.0.0",
			"test",
			string([]byte(`{"k":"v"}`)),
			"",
			"",
			time.Unix(collectedAt, 0).Format(time.RFC3339),
		),
	}
	if err := store.SaveArtifacts(ctx, []model.Artifact{a1}); err != nil {
		t.Fatalf("save artifacts: %v", err)
	}

	// 命中
	h1 := model.RuleHit{
		ID:           id.New("hit"),
		CaseID:       caseID,
		DeviceID:     dev.ID,
		Type:         model.HitExchangeVisited,
		RuleID:       "exchange_binance",
		RuleName:     "Binance",
		RuleVersion:  "2026-02-12",
		MatchedValue: "binance.com",
		FirstSeenAt:  collectedAt,
		LastSeenAt:   collectedAt,
		Confidence:   0.9,
		Verdict:      "confirmed",
		DetailJSON:   []byte(`{"match_field":"domain"}`),
		ArtifactIDs:  []string{a1.ID},
	}
	if err := store.SaveRuleHits(ctx, []model.RuleHit{h1}); err != nil {
		t.Fatalf("save hits: %v", err)
	}

	// 前置检查（用于 PDF 展示）
	_ = store.SavePrecheckResults(ctx, []model.PrecheckResult{{
		CaseID:     caseID,
		DeviceID:   dev.ID,
		ScanScope:  "general",
		CheckCode:  "authorization_order",
		CheckName:  "执法授权工单已提供",
		Required:   false,
		Status:     model.PrecheckPassed,
		Message:    "AUTH-ORDER-001",
		DetailJSON: []byte(`{"authorization_basis":"unit_test"}`),
		CheckedAt:  time.Now().Unix(),
	}})

	// 审计链（用于 PDF 摘要）
	_ = store.AppendAudit(ctx, caseID, dev.ID, "unit", "step1", "success", "tester", "pdf_test", map[string]any{"k": "v"})
	_ = store.AppendAudit(ctx, caseID, dev.ID, "unit", "step2", "success", "tester", "pdf_test", map[string]any{"k2": "v2"})

	res, err := GenerateForensicPDF(ctx, store, Options{
		CaseID:   caseID,
		DBPath:   dbPath,
		Operator: "tester",
		Note:     "unit_test",
	})
	if err != nil {
		t.Fatalf("GenerateForensicPDF: %v", err)
	}
	if res.ReportID == "" {
		t.Fatalf("expected report_id, got empty")
	}
	if res.PDFPath == "" {
		t.Fatalf("expected pdf_path, got empty")
	}
	if res.PDFSHA256 == "" {
		t.Fatalf("expected pdf_sha256, got empty")
	}

	st, err := os.Stat(res.PDFPath)
	if err != nil {
		t.Fatalf("stat pdf: %v", err)
	}
	if st.Size() <= 0 {
		t.Fatalf("pdf size should be > 0, got %d", st.Size())
	}

	info, err := store.GetReportByID(ctx, res.ReportID)
	if err != nil {
		t.Fatalf("get report by id: %v", err)
	}
	if info == nil {
		t.Fatalf("report not found by id: %s", res.ReportID)
	}
	if info.ReportType != "forensic_pdf" {
		t.Fatalf("unexpected report type: %s", info.ReportType)
	}
	if info.SHA256 != res.PDFSHA256 {
		t.Fatalf("sha mismatch: db=%s res=%s", info.SHA256, res.PDFSHA256)
	}
}
