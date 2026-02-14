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
	"crypto-inspector/internal/services/privacy"

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
		CheckName: "隐私开关（masked 时对报告做展示层脱敏）",
		Required:  false,
		Status:    model.PrecheckPassed,
		Message:   opts.PrivacyMode,
		DetailJSON: mustJSON(map[string]any{
			"implemented": true,
			"note":        "masked 仅影响报告展示内容，不修改原始证据快照文件",
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

	// 规则包留痕（best effort）：用于把“命中来自哪个规则文件版本/哈希”固化到 DB。
	// 如果留痕失败，不阻断内测扫描，但会写入 warnings 与审计日志。
	walletBundleID := ""
	exchangeBundleID := ""
	if id, err := store.EnsureRuleBundle(ctx, "wallet_signatures", loaded.Wallet.Version, loaded.WalletSHA256, opts.WalletRulePath); err == nil {
		walletBundleID = id
	} else {
		_ = store.AppendAudit(ctx, caseID, device.ID, "host_scan", "rule_bundle_wallet", "skipped", opts.Operator, "hostscan.Run", map[string]any{"error": err.Error()})
	}
	if id, err := store.EnsureRuleBundle(ctx, "exchange_domains", loaded.Exchange.Version, loaded.ExchangeSHA256, opts.ExchangeRulePath); err == nil {
		exchangeBundleID = id
	} else {
		_ = store.AppendAudit(ctx, caseID, device.ID, "host_scan", "rule_bundle_exchange", "skipped", opts.Operator, "hostscan.Run", map[string]any{"error": err.Error()})
	}

	matchResult, err := matcher.MatchHostArtifacts(loaded, artifacts)
	if err != nil {
		_ = store.AppendAudit(ctx, caseID, device.ID, "host_scan", "match_rules", "failed", opts.Operator, "hostscan.Run", map[string]any{"error": err.Error()})
		return nil, err
	}

	// 把 rule_bundle_id 回填到命中结果（与规则包留痕关联）。
	for i := range matchResult.Hits {
		switch matchResult.Hits[i].Type {
		case model.HitWalletInstalled:
			matchResult.Hits[i].RuleBundleID = walletBundleID
		case model.HitExchangeVisited:
			matchResult.Hits[i].RuleBundleID = exchangeBundleID
		}
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

	// 内部报告（JSON + HTML）
	jsonPath, jsonHash, jsonErr := writeInternalJSONReport(opts.DBPath, caseID, opts.AuthorizationOrder, opts.PrivacyMode, device, artifacts, matchResult.Hits, warnings, prechecks)
	jsonReportID := ""
	if jsonErr == nil {
		jsonReportID, _ = store.SaveReport(ctx, caseID, "internal_json", jsonPath, jsonHash, "hostscan-0.1.0", "ready")
	} else {
		warnings = append(warnings, "write internal_json report failed: "+jsonErr.Error())
	}

	htmlPath, htmlHash, htmlErr := writeInternalHTMLReport(opts.DBPath, caseID, opts.AuthorizationOrder, opts.PrivacyMode, device, artifacts, matchResult.Hits, warnings, prechecks)
	if htmlErr == nil {
		_, _ = store.SaveReport(ctx, caseID, "internal_html", htmlPath, htmlHash, "hostscan-0.1.0", "ready")
	} else {
		warnings = append(warnings, "write internal_html report failed: "+htmlErr.Error())
	}

	// 结束审计日志写入最终统计。
	_ = store.AppendAudit(ctx, caseID, device.ID, "host_scan", "scan_finish", status, opts.Operator, "hostscan.Run", map[string]any{
		"artifacts":            len(artifacts),
		"hits":                 len(matchResult.Hits),
		"warning":              scanErrString(scanErr),
		"report_internal_json": jsonPath,
		"report_internal_html": htmlPath,
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
		ReportID:      jsonReportID,
		ReportPath:    jsonPath,
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

// writeInternalJSONReport 生成内部 JSON 报告，并返回文件路径与哈希。
func writeInternalJSONReport(dbPath, caseID, authOrder, privacyMode string, device model.Device, artifacts []model.Artifact, hits []model.RuleHit, warnings []string, prechecks []model.PrecheckResult) (path string, sha string, err error) {
	reportDir := filepath.Join(filepath.Dir(dbPath), "reports")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return "", "", err
	}
	masked := strings.TrimSpace(strings.ToLower(privacyMode)) == "masked"

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
		snap := a.SnapshotPath
		if masked {
			snap = privacy.MaskSnapshotPath(snap)
		}
		artifactRows = append(artifactRows, artifactSummary{
			ArtifactID:   a.ID,
			ArtifactType: string(a.Type),
			SourceRef:    a.SourceRef,
			SnapshotPath: snap,
			SHA256:       a.SHA256,
			CollectedAt:  a.CollectedAt,
			SizeBytes:    a.SizeBytes,
		})
	}

	if masked {
		hits = privacy.MaskRuleHitsForReport(hits)
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

// writeInternalHTMLReport 生成内部 HTML 报告，并返回文件路径与哈希。
//
// 设计目标：
// - 让“内部查看”更直观（无需下载 PDF 就能快速浏览）
// - 同时保持可追溯字段（sha256/record_hash/审计链 hash 等）可被复制与复核
func writeInternalHTMLReport(dbPath, caseID, authOrder, privacyMode string, device model.Device, artifacts []model.Artifact, hits []model.RuleHit, warnings []string, prechecks []model.PrecheckResult) (path string, sha string, err error) {
	reportDir := filepath.Join(filepath.Dir(dbPath), "reports")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return "", "", err
	}
	masked := strings.TrimSpace(strings.ToLower(privacyMode)) == "masked"
	if masked {
		hits = privacy.MaskRuleHitsForReport(hits)
	}

	now := time.Now().Unix()
	filename := fmt.Sprintf("%s_internal_%d.html", caseID, now)
	path = filepath.Join(reportDir, filename)

	// 这里不追求复杂模板引擎，直接拼接 HTML（内测阶段够用，便于后续替换为更严格模板）。
	var b strings.Builder
	b.Grow(32 * 1024)
	b.WriteString("<!doctype html>\n<html lang=\"zh-CN\">\n<head>\n")
	b.WriteString("<meta charset=\"utf-8\"/>\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>\n")
	b.WriteString("<title>数字货币痕迹检测报告（内部）</title>\n")
	b.WriteString("<style>\n")
	b.WriteString("body{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,\"Liberation Mono\",monospace;background:#0b1220;color:#e8e8e8;margin:0;padding:24px;}\n")
	b.WriteString("h1{font-size:18px;margin:0 0 12px 0;}\n")
	b.WriteString("h2{font-size:14px;margin:20px 0 8px 0;color:#4fc3f7;border-bottom:1px solid #1f2937;padding-bottom:6px;}\n")
	b.WriteString(".muted{color:#b8bcc4;}\n")
	b.WriteString(".kv{display:grid;grid-template-columns:160px 1fr;gap:6px 12px;font-size:12px;}\n")
	b.WriteString(".box{border:1px solid #1f2937;background:#111827;padding:12px;border-radius:6px;}\n")
	b.WriteString("table{width:100%;border-collapse:collapse;font-size:12px;}\n")
	b.WriteString("th,td{border:1px solid #1f2937;padding:6px 8px;vertical-align:top;}\n")
	b.WriteString("th{background:#0d0f12;color:#b8bcc4;text-align:left;}\n")
	b.WriteString(".ok{color:#22c55e;}\n")
	b.WriteString(".warn{color:#ffa726;}\n")
	b.WriteString(".bad{color:#ff6b6b;}\n")
	b.WriteString(".mono{font-family:inherit;word-break:break-all;}\n")
	b.WriteString("a{color:#4fc3f7;text-decoration:none;}\n")
	b.WriteString("</style>\n</head>\n<body>\n")

	b.WriteString("<h1>数字货币痕迹检测报告（内部）</h1>\n")
	b.WriteString("<div class=\"box kv\">")
	b.WriteString("<div class=\"muted\">case_id</div><div class=\"mono\">" + htmlEscape(caseID) + "</div>")
	b.WriteString("<div class=\"muted\">generated_at</div><div class=\"mono\">" + htmlEscape(time.Unix(now, 0).Format("2006-01-02 15:04:05")) + "</div>")
	b.WriteString("<div class=\"muted\">authorization_order</div><div class=\"mono\">" + htmlEscape(authOrder) + "</div>")
	b.WriteString("<div class=\"muted\">privacy_mode</div><div class=\"mono\">" + htmlEscape(privacyMode) + "</div>")
	b.WriteString("</div>\n")

	b.WriteString("<h2>设备</h2>\n<div class=\"box kv\">")
	b.WriteString("<div class=\"muted\">device_id</div><div class=\"mono\">" + htmlEscape(device.ID) + "</div>")
	b.WriteString("<div class=\"muted\">name</div><div class=\"mono\">" + htmlEscape(device.Name) + "</div>")
	b.WriteString("<div class=\"muted\">os</div><div class=\"mono\">" + htmlEscape(string(device.OS)) + "</div>")
	b.WriteString("<div class=\"muted\">identifier</div><div class=\"mono\">" + htmlEscape(device.Identifier) + "</div>")
	b.WriteString("</div>\n")

	b.WriteString("<h2>摘要</h2>\n<div class=\"box kv\">")
	b.WriteString("<div class=\"muted\">artifact_count</div><div class=\"mono\">" + fmt.Sprintf("%d", len(artifacts)) + "</div>")
	b.WriteString("<div class=\"muted\">hit_count</div><div class=\"mono\">" + fmt.Sprintf("%d", len(hits)) + "</div>")
	b.WriteString("<div class=\"muted\">precheck_count</div><div class=\"mono\">" + fmt.Sprintf("%d", len(prechecks)) + "</div>")
	b.WriteString("</div>\n")

	b.WriteString("<h2>前置条件检查</h2>\n<div class=\"box\">")
	if len(prechecks) == 0 {
		b.WriteString("<div class=\"muted\">(empty)</div>")
	} else {
		b.WriteString("<table><thead><tr><th>scope</th><th>code</th><th>name</th><th>required</th><th>status</th><th>message</th><th>checked_at</th></tr></thead><tbody>")
		for _, c := range prechecks {
			statusClass := "muted"
			switch c.Status {
			case model.PrecheckPassed:
				statusClass = "ok"
			case model.PrecheckFailed:
				statusClass = "bad"
			case model.PrecheckSkipped:
				statusClass = "warn"
			}
			b.WriteString("<tr>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(c.ScanScope) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(c.CheckCode) + "</td>")
			b.WriteString("<td>" + htmlEscape(c.CheckName) + "</td>")
			if c.Required {
				b.WriteString("<td>yes</td>")
			} else {
				b.WriteString("<td>no</td>")
			}
			b.WriteString("<td class=\"" + statusClass + "\">" + htmlEscape(string(c.Status)) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(c.Message) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(time.Unix(c.CheckedAt, 0).Format("2006-01-02 15:04:05")) + "</td>")
			b.WriteString("</tr>")
		}
		b.WriteString("</tbody></table>")
	}
	b.WriteString("</div>\n")

	b.WriteString("<h2>命中</h2>\n<div class=\"box\">")
	if len(hits) == 0 {
		b.WriteString("<div class=\"muted\">(empty)</div>")
	} else {
		b.WriteString("<table><thead><tr><th>type</th><th>rule</th><th>value</th><th>confidence</th><th>verdict</th><th>artifacts</th></tr></thead><tbody>")
		for _, h := range hits {
			b.WriteString("<tr>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(string(h.Type)) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(h.RuleName) + " (" + htmlEscape(h.RuleID) + ")</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(h.MatchedValue) + "</td>")
			b.WriteString("<td class=\"mono\">" + fmt.Sprintf("%.2f", h.Confidence) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(h.Verdict) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(strings.Join(h.ArtifactIDs, ",")) + "</td>")
			b.WriteString("</tr>")
		}
		b.WriteString("</tbody></table>")
	}
	b.WriteString("</div>\n")

	b.WriteString("<h2>证据</h2>\n<div class=\"box\">")
	if len(artifacts) == 0 {
		b.WriteString("<div class=\"muted\">(empty)</div>")
	} else {
		b.WriteString("<table><thead><tr><th>artifact_id</th><th>type</th><th>source</th><th>sha256</th><th>snapshot_path</th><th>collected_at</th></tr></thead><tbody>")
		for _, a := range artifacts {
			snap := a.SnapshotPath
			if masked {
				snap = privacy.MaskSnapshotPath(snap)
			}
			b.WriteString("<tr>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(a.ID) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(string(a.Type)) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(a.SourceRef) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(a.SHA256) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(snap) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(time.Unix(a.CollectedAt, 0).Format("2006-01-02 15:04:05")) + "</td>")
			b.WriteString("</tr>")
		}
		b.WriteString("</tbody></table>")
	}
	b.WriteString("</div>\n")

	b.WriteString("<h2>Warnings</h2>\n<div class=\"box\">")
	if len(warnings) == 0 {
		b.WriteString("<div class=\"muted\">(none)</div>")
	} else {
		b.WriteString("<ul>")
		for _, w := range warnings {
			if strings.TrimSpace(w) == "" {
				continue
			}
			b.WriteString("<li class=\"mono\">" + htmlEscape(w) + "</li>")
		}
		b.WriteString("</ul>")
	}
	b.WriteString("</div>\n")

	b.WriteString("</body>\n</html>\n")

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return "", "", err
	}

	sum, _, err := hash.File(path)
	if err != nil {
		return "", "", err
	}
	return path, sum, nil
}

// htmlEscape 是极简 HTML 转义（只覆盖报告内可能出现的危险字符）。
func htmlEscape(s string) string {
	if s == "" {
		return ""
	}
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}
