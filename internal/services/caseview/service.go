package caseview

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	sqliteadapter "crypto-inspector/internal/adapters/store/sqlite"
	"crypto-inspector/internal/domain/model"

	_ "modernc.org/sqlite"
)

// HostHitView 是主机命中明细查询结果。
type HostHitView struct {
	Overview *model.CaseOverview `json:"overview,omitempty"`
	Hits     []model.HitDetail   `json:"hits"`
}

// ReportView 是报告展示查询结果。
type ReportView struct {
	Overview      *model.CaseOverview `json:"overview,omitempty"`
	Report        *model.ReportInfo   `json:"report,omitempty"`
	Content       string              `json:"content,omitempty"`
	ContentLength int                 `json:"content_length,omitempty"`
}

// GetHostHitView 查询案件命中明细（用于 UI 命中列表）。
func GetHostHitView(ctx context.Context, dbPath, caseID, hitType string) (*HostHitView, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		return nil, fmt.Errorf("set busy_timeout: %w", err)
	}

	store := sqliteadapter.NewStore(db)
	overview, err := store.GetCaseOverview(ctx, caseID)
	if err != nil {
		return nil, err
	}
	if overview == nil {
		return nil, fmt.Errorf("case not found: %s", caseID)
	}

	hits, err := store.ListCaseHitDetails(ctx, caseID, hitType)
	if err != nil {
		return nil, err
	}
	if hits == nil {
		hits = []model.HitDetail{}
	}

	return &HostHitView{
		Overview: overview,
		Hits:     hits,
	}, nil
}

// GetReportView 查询案件报告索引与可选内容（用于 UI 报告页）。
// reportID 为空时返回最新报告。
func GetReportView(ctx context.Context, dbPath, caseID, reportID string, includeContent bool) (*ReportView, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		return nil, fmt.Errorf("set busy_timeout: %w", err)
	}

	store := sqliteadapter.NewStore(db)
	overview, err := store.GetCaseOverview(ctx, caseID)
	if err != nil {
		return nil, err
	}
	if overview == nil {
		return nil, fmt.Errorf("case not found: %s", caseID)
	}

	var report *model.ReportInfo
	if reportID != "" {
		report, err = store.GetReportByID(ctx, reportID)
	} else {
		report, err = store.GetLatestReportByCase(ctx, caseID)
	}
	if err != nil {
		return nil, err
	}
	if report == nil {
		return &ReportView{Overview: overview}, nil
	}

	out := &ReportView{
		Overview: overview,
		Report:   report,
	}
	if includeContent {
		raw, err := os.ReadFile(report.FilePath)
		if err != nil {
			return nil, fmt.Errorf("read report file: %w", err)
		}
		out.Content = string(raw)
		out.ContentLength = len(raw)
	}

	return out, nil
}
