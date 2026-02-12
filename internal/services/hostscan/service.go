package hostscan

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"crypto-inspector/internal/adapters/host"
	"crypto-inspector/internal/adapters/rules"
	sqliteadapter "crypto-inspector/internal/adapters/store/sqlite"
	"crypto-inspector/internal/app"
	"crypto-inspector/internal/domain/model"
	"crypto-inspector/internal/platform/hash"
	"crypto-inspector/internal/services/matcher"

	_ "modernc.org/sqlite"
)

// Options 定义一次主机扫描的输入参数。
type Options struct {
	DBPath             string
	EvidenceRoot       string
	WalletRulePath     string
	ExchangeRulePath   string
	CaseID             string
	Operator           string
	Note               string
	AuthorizationOrder string
	AuthorizationBasis string
	RequireAuthOrder   bool
	PrivacyMode        string
}

// Result 定义一次主机扫描的摘要输出。
type Result struct {
	CaseID        string   `json:"case_id"`
	DeviceID      string   `json:"device_id"`
	DeviceName    string   `json:"device_name"`
	DeviceOS      string   `json:"device_os"`
	ArtifactCount int      `json:"artifact_count"`
	HitCount      int      `json:"hit_count"`
	WalletHits    int      `json:"wallet_hits"`
	ExchangeHits  int      `json:"exchange_hits"`
	Warnings      []string `json:"warnings,omitempty"`
	ReportID      string   `json:"report_id,omitempty"`
	ReportPath    string   `json:"report_path,omitempty"`
	StartedAt     int64    `json:"started_at"`
	FinishedAt    int64    `json:"finished_at"`
}

// Run 执行主机扫描主流程：
// 1) 准备数据库与目录
// 2) 迁移建表
// 3) 采集证据并入库
// 4) 规则匹配并入库
// 5) 生成内部报告与审计日志
func Run(ctx context.Context, opts Options) (*Result, error) {
	defaults := app.DefaultConfig()
	if opts.DBPath == "" {
		opts.DBPath = defaults.DBPath
	}
	if opts.EvidenceRoot == "" {
		opts.EvidenceRoot = "data/evidence"
	}
	if opts.WalletRulePath == "" {
		opts.WalletRulePath = defaults.WalletRulePath
	}
	if opts.ExchangeRulePath == "" {
		opts.ExchangeRulePath = defaults.ExchangeRulePath
	}
	opts.AuthorizationOrder = strings.TrimSpace(opts.AuthorizationOrder)
	opts.AuthorizationBasis = strings.TrimSpace(opts.AuthorizationBasis)
	opts.PrivacyMode = strings.ToLower(strings.TrimSpace(opts.PrivacyMode))
	if opts.PrivacyMode == "" {
		opts.PrivacyMode = "off"
	}
	if opts.PrivacyMode != "off" && opts.PrivacyMode != "masked" {
		opts.PrivacyMode = "off"
	}

	if err := os.MkdirAll(filepath.Dir(opts.DBPath), 0o755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}
	if err := os.MkdirAll(opts.EvidenceRoot, 0o755); err != nil {
		return nil, fmt.Errorf("create evidence directory: %w", err)
	}

	db, err := sql.Open("sqlite", opts.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()
	// 内部单机工具优先稳定性：SQLite 用单连接 + busy_timeout 减少“database is locked”。
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		return nil, fmt.Errorf("set busy_timeout: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	migrator := sqliteadapter.NewMigrator(db)
	if err := migrator.Up(ctx); err != nil {
		return nil, fmt.Errorf("apply migrations: %w", err)
	}

	// case/device 是后续 artifacts、hits、audit 的主关联键。
	store := sqliteadapter.NewStore(db)
	title := "Host Scan"
	if strings.TrimSpace(opts.CaseID) != "" {
		// UI 支持“先建案再采集”。如果这里强制写入 "Host Scan"，会覆盖用户自定义标题。
		// EnsureCase 的 upsert 逻辑：title 为空则不覆盖旧值，因此传空即可达到“只在新建时写默认值”的效果。
		title = ""
	}
	caseID, err := store.EnsureCase(ctx, opts.CaseID, opts.AuthorizationOrder, title, opts.Operator, opts.Note)
	if err != nil {
		return nil, err
	}

	authStatus := model.PrecheckPassed
	authMessage := opts.AuthorizationOrder
	if opts.AuthorizationOrder == "" {
		authStatus = model.PrecheckSkipped
		authMessage = "not provided"
		if opts.RequireAuthOrder {
			authStatus = model.PrecheckFailed
			authMessage = "authorization order is required but missing"
		}
	}
	prechecks := []model.PrecheckResult{{
		CaseID:    caseID,
		ScanScope: "general",
		CheckCode: "authorization_order",
		CheckName: "执法授权工单已提供",
		Required:  opts.RequireAuthOrder,
		Status:    authStatus,
		Message:   authMessage,
		DetailJSON: mustJSON(map[string]any{
			"authorization_basis": opts.AuthorizationBasis,
		}),
		CheckedAt: time.Now().Unix(),
	}}
	prechecks = append(prechecks, model.PrecheckResult{
		CaseID:    caseID,
		ScanScope: "general",
		CheckCode: "privacy_mode_reserved",
		CheckName: "隐私开关预留（当前仅记录，不做脱敏）",
		Required:  false,
		Status:    model.PrecheckPassed,
		Message:   opts.PrivacyMode,
		DetailJSON: mustJSON(map[string]any{
			"implemented": false,
		}),
		CheckedAt: time.Now().Unix(),
	})
	if opts.RequireAuthOrder && opts.AuthorizationOrder == "" {
		_ = store.SavePrecheckResults(ctx, prechecks)
		_ = store.AppendAudit(ctx, caseID, "", "host_scan", "precheck", "failed", opts.Operator, "hostscan.Run", map[string]any{
			"reason": "authorization order required",
		})
		return nil, fmt.Errorf("host precheck failed: authorization order is required")
	}

	if err := precheckWritable(opts.EvidenceRoot); err != nil {
		prechecks = append(prechecks, model.PrecheckResult{
			CaseID:     caseID,
			ScanScope:  "host",
			CheckCode:  "evidence_dir_writable",
			CheckName:  "证据目录可写",
			Required:   true,
			Status:     model.PrecheckFailed,
			Message:    err.Error(),
			CheckedAt:  time.Now().Unix(),
			DetailJSON: mustJSON(map[string]any{"evidence_root": opts.EvidenceRoot}),
		})
		_ = store.SavePrecheckResults(ctx, prechecks)
		_ = store.AppendAudit(ctx, caseID, "", "host_scan", "precheck", "failed", opts.Operator, "hostscan.Run", map[string]any{"error": err.Error()})
		return nil, fmt.Errorf("host precheck failed: %w", err)
	}
	prechecks = append(prechecks, model.PrecheckResult{
		CaseID:     caseID,
		ScanScope:  "host",
		CheckCode:  "evidence_dir_writable",
		CheckName:  "证据目录可写",
		Required:   true,
		Status:     model.PrecheckPassed,
		Message:    "ok",
		CheckedAt:  time.Now().Unix(),
		DetailJSON: mustJSON(map[string]any{"evidence_root": opts.EvidenceRoot}),
	})

	device, err := host.DetectHostDevice()
	if err != nil {
		prechecks = append(prechecks, model.PrecheckResult{
			CaseID:     caseID,
			ScanScope:  "host",
			CheckCode:  "host_os_supported",
			CheckName:  "主机操作系统受支持",
			Required:   true,
			Status:     model.PrecheckFailed,
			Message:    err.Error(),
			CheckedAt:  time.Now().Unix(),
			DetailJSON: mustJSON(map[string]any{}),
		})
		_ = store.SavePrecheckResults(ctx, prechecks)
		_ = store.AppendAudit(ctx, caseID, "", "host_scan", "precheck", "failed", opts.Operator, "hostscan.Run", map[string]any{"error": err.Error()})
		return nil, err
	}
	prechecks = append(prechecks, model.PrecheckResult{
		CaseID:    caseID,
		DeviceID:  device.ID,
		ScanScope: "host",
		CheckCode: "host_os_supported",
		CheckName: "主机操作系统受支持",
		Required:  true,
		Status:    model.PrecheckPassed,
		Message:   string(device.OS),
		CheckedAt: time.Now().Unix(),
		DetailJSON: mustJSON(map[string]any{
			"device_name": device.Name,
			"identifier":  device.Identifier,
		}),
	})
	if err := store.SavePrecheckResults(ctx, prechecks); err != nil {
		return nil, err
	}

	if err := store.UpsertDevice(ctx, caseID, device, true, "host local device"); err != nil {
		return nil, err
	}

	// 先写一条 started 审计日志，保证流程可追溯。
	started := time.Now().Unix()
	_ = store.AppendAudit(ctx, caseID, device.ID, "host_scan", "scan_start", "started", opts.Operator, "hostscan.Run", map[string]any{
		"os":                    device.OS,
		"hostname":              device.Name,
		"privacy_mode_reserved": opts.PrivacyMode,
	})

	scanner := host.NewScanner(opts.EvidenceRoot)
	artifacts, scanErr := scanner.Scan(ctx, caseID, device)
	if err := store.SaveArtifacts(ctx, artifacts); err != nil {
		_ = store.AppendAudit(ctx, caseID, device.ID, "host_scan", "save_artifacts", "failed", opts.Operator, "hostscan.Run", map[string]any{"error": err.Error()})
		return nil, err
	}

	// 规则加载失败属于硬错误：无法给出可信命中结果。
	loader := rules.NewLoader(opts.WalletRulePath, opts.ExchangeRulePath)
	loaded, err := loader.Load(ctx)
	if err != nil {
		_ = store.AppendAudit(ctx, caseID, device.ID, "host_scan", "load_rules", "failed", opts.Operator, "hostscan.Run", map[string]any{"error": err.Error()})
		return nil, err
	}

	matchResult, err := matcher.MatchHostArtifacts(loaded, artifacts)
	if err != nil {
		_ = store.AppendAudit(ctx, caseID, device.ID, "host_scan", "match_rules", "failed", opts.Operator, "hostscan.Run", map[string]any{"error": err.Error()})
		return nil, err
	}

	if err := store.SaveRuleHits(ctx, matchResult.Hits); err != nil {
		_ = store.AppendAudit(ctx, caseID, device.ID, "host_scan", "save_hits", "failed", opts.Operator, "hostscan.Run", map[string]any{"error": err.Error()})
		return nil, err
	}

	// scanErr 表示“部分采集失败”，不一定阻断整体流程。
	status := "success"
	warnings := []string{}
	if scanErr != nil {
		warnings = append(warnings, scanErr.Error())
		status = "failed"
	}

	reportPath, reportHash, reportErr := writeInternalReport(opts.DBPath, caseID, opts.AuthorizationOrder, opts.PrivacyMode, device, artifacts, matchResult.Hits, warnings, prechecks)
	reportID := ""
	if reportErr == nil {
		reportID, _ = store.SaveReport(ctx, caseID, "internal_json", reportPath, reportHash, "hostscan-0.1.0", "ready")
	} else {
		warnings = append(warnings, "write report failed: "+reportErr.Error())
	}

	// 结束审计日志写入最终统计。
	_ = store.AppendAudit(ctx, caseID, device.ID, "host_scan", "scan_finish", status, opts.Operator, "hostscan.Run", map[string]any{
		"artifacts": len(artifacts),
		"hits":      len(matchResult.Hits),
		"warning":   scanErrString(scanErr),
		"report":    reportPath,
	})

	walletHits := 0
	exchangeHits := 0
	for _, h := range matchResult.Hits {
		switch h.Type {
		case model.HitWalletInstalled:
			walletHits++
		case model.HitExchangeVisited:
			exchangeHits++
		}
	}

	return &Result{
		CaseID:        caseID,
		DeviceID:      device.ID,
		DeviceName:    device.Name,
		DeviceOS:      string(device.OS),
		ArtifactCount: len(artifacts),
		HitCount:      len(matchResult.Hits),
		WalletHits:    walletHits,
		ExchangeHits:  exchangeHits,
		Warnings:      warnings,
		ReportID:      reportID,
		ReportPath:    reportPath,
		StartedAt:     started,
		FinishedAt:    time.Now().Unix(),
	}, nil
}

// scanErrString 将可空错误统一转为字符串，便于审计字段写入。
func scanErrString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func precheckWritable(root string) error {
	testPath := filepath.Join(root, ".precheck_write_test")
	if err := os.WriteFile(testPath, []byte("ok"), 0o644); err != nil {
		return err
	}
	_ = os.Remove(testPath)
	return nil
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return raw
}

// writeInternalReport 生成内部 JSON 报告，并返回文件路径与哈希。
func writeInternalReport(dbPath, caseID, authOrder, privacyMode string, device model.Device, artifacts []model.Artifact, hits []model.RuleHit, warnings []string, prechecks []model.PrecheckResult) (path string, sha string, err error) {
	reportDir := filepath.Join(filepath.Dir(dbPath), "reports")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return "", "", err
	}

	type artifactSummary struct {
		ArtifactID   string `json:"artifact_id"`
		ArtifactType string `json:"artifact_type"`
		SourceRef    string `json:"source_ref"`
		SnapshotPath string `json:"snapshot_path"`
		SHA256       string `json:"sha256"`
		CollectedAt  int64  `json:"collected_at"`
		SizeBytes    int64  `json:"size_bytes"`
	}

	artifactRows := make([]artifactSummary, 0, len(artifacts))
	for _, a := range artifacts {
		artifactRows = append(artifactRows, artifactSummary{
			ArtifactID:   a.ID,
			ArtifactType: string(a.Type),
			SourceRef:    a.SourceRef,
			SnapshotPath: a.SnapshotPath,
			SHA256:       a.SHA256,
			CollectedAt:  a.CollectedAt,
			SizeBytes:    a.SizeBytes,
		})
	}

	payload := map[string]any{
		"case_id":             caseID,
		"authorization_order": authOrder,
		"privacy_mode":        privacyMode,
		"generated_at":        time.Now().Unix(),
		"device": map[string]any{
			"device_id":  device.ID,
			"name":       device.Name,
			"os":         device.OS,
			"identifier": device.Identifier,
		},
		"summary": map[string]any{
			"artifact_count": len(artifacts),
			"hit_count":      len(hits),
			"precheck_count": len(prechecks),
		},
		"prechecks": prechecks,
		"artifacts": artifactRows,
		"hits":      hits,
		"warnings":  warnings,
	}

	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", "", err
	}

	filename := fmt.Sprintf("%s_internal_%d.json", caseID, time.Now().Unix())
	path = filepath.Join(reportDir, filename)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return "", "", err
	}

	sum, _, err := hash.File(path)
	if err != nil {
		return "", "", err
	}
	return path, sum, nil
}
