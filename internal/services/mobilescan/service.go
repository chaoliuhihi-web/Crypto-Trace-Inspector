package mobilescan

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"crypto-inspector/internal/adapters/mobile"
	"crypto-inspector/internal/adapters/rules"
	sqliteadapter "crypto-inspector/internal/adapters/store/sqlite"
	"crypto-inspector/internal/app"
	"crypto-inspector/internal/domain/model"
	"crypto-inspector/internal/platform/hash"
	"crypto-inspector/internal/services/matcher"

	_ "modernc.org/sqlite"
)

// Options 定义一次移动端扫描的输入参数。
type Options struct {
	DBPath              string
	EvidenceRoot        string
	IOSBackupDir        string
	WalletRulePath      string
	ExchangeRulePath    string
	CaseID              string
	Operator            string
	Note                string
	AuthorizationOrder  string
	AuthorizationBasis  string
	RequireAuthOrder    bool
	RequireAuthorized   bool
	EnableIOSFullBackup bool
	// EnableAndroid/EnableIOS 用于控制移动端采集范围。
	// 注意：为兼容旧调用方（未设置该字段的情况），Run 内会把“两者都为 false”视为默认开启。
	EnableAndroid bool
	EnableIOS     bool
	PrivacyMode   string
}

// Result 定义一次移动端扫描的摘要输出。
type Result struct {
	CaseID        string   `json:"case_id"`
	DeviceCount   int      `json:"device_count"`
	AndroidCount  int      `json:"android_count"`
	IOSCount      int      `json:"ios_count"`
	ArtifactCount int      `json:"artifact_count"`
	HitCount      int      `json:"hit_count"`
	WalletHits    int      `json:"wallet_hits"`
	Warnings      []string `json:"warnings,omitempty"`
	ReportID      string   `json:"report_id,omitempty"`
	ReportPath    string   `json:"report_path,omitempty"`
	StartedAt     int64    `json:"started_at"`
	FinishedAt    int64    `json:"finished_at"`
}

// Run 执行移动端扫描主流程（Android ADB + iOS 备份接入骨架）。
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
	if opts.IOSBackupDir == "" {
		opts.IOSBackupDir = filepath.Join(opts.EvidenceRoot, "ios_backups")
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

	// 兼容策略：如果两个开关都没显式设置（零值 false/false），默认视为都开启。
	if !opts.EnableAndroid && !opts.EnableIOS {
		opts.EnableAndroid = true
		opts.EnableIOS = true
	}

	if err := os.MkdirAll(filepath.Dir(opts.DBPath), 0o755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}
	if err := os.MkdirAll(opts.EvidenceRoot, 0o755); err != nil {
		return nil, fmt.Errorf("create evidence directory: %w", err)
	}
	if err := os.MkdirAll(opts.IOSBackupDir, 0o755); err != nil {
		return nil, fmt.Errorf("create ios backup dir: %w", err)
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

	store := sqliteadapter.NewStore(db)
	title := "Mobile Scan"
	if strings.TrimSpace(opts.CaseID) != "" {
		// 避免覆盖 UI 侧已填写的案件标题（见 hostscan 同样逻辑说明）
		title = ""
	}
	caseID, err := store.EnsureCase(ctx, opts.CaseID, opts.AuthorizationOrder, title, opts.Operator, opts.Note)
	if err != nil {
		return nil, err
	}

	started := time.Now().Unix()
	_ = store.AppendAudit(ctx, caseID, "", "mobile_scan", "scan_start", "started", opts.Operator, "mobilescan.Run", map[string]any{
		"ios_backup_dir":        opts.IOSBackupDir,
		"enable_ios_backup":     opts.EnableIOSFullBackup,
		"enable_android":        opts.EnableAndroid,
		"enable_ios":            opts.EnableIOS,
		"privacy_mode_reserved": opts.PrivacyMode,
	})

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
		_ = store.AppendAudit(ctx, caseID, "", "mobile_scan", "precheck", "failed", opts.Operator, "mobilescan.Run", map[string]any{
			"reason": "authorization order required",
		})
		return nil, fmt.Errorf("mobile precheck failed: authorization order is required")
	}
	prechecks = append(prechecks, precheckTool(caseID, "mobile", "android_adb_available", "Android ADB 工具可用", false, "adb"))
	prechecks = append(prechecks, precheckTool(caseID, "mobile", "ios_idevice_id_available", "iOS 设备识别工具可用", false, "idevice_id"))
	prechecks = append(prechecks, precheckTool(caseID, "mobile", "ios_idevicepair_available", "iOS 配对验证工具可用", false, "idevicepair"))

	scanner := mobile.NewScanner(opts.EvidenceRoot, opts.IOSBackupDir, opts.EnableIOSFullBackup, opts.EnableAndroid, opts.EnableIOS)
	scanResult, err := scanner.Scan(ctx, caseID)
	if err != nil {
		prechecks = append(prechecks, model.PrecheckResult{
			CaseID:     caseID,
			ScanScope:  "mobile",
			CheckCode:  "mobile_scan_collect",
			CheckName:  "移动端采集执行",
			Required:   true,
			Status:     model.PrecheckFailed,
			Message:    err.Error(),
			CheckedAt:  time.Now().Unix(),
			DetailJSON: mustJSON(map[string]any{}),
		})
		_ = store.SavePrecheckResults(ctx, prechecks)
		_ = store.AppendAudit(ctx, caseID, "", "mobile_scan", "collect_mobile", "failed", opts.Operator, "mobilescan.Run", map[string]any{"error": err.Error()})
		return nil, err
	}

	if len(scanResult.Devices) == 0 {
		prechecks = append(prechecks, model.PrecheckResult{
			CaseID:     caseID,
			ScanScope:  "mobile",
			CheckCode:  "mobile_device_connected",
			CheckName:  "检测到移动设备连接",
			Required:   opts.RequireAuthorized,
			Status:     model.PrecheckFailed,
			Message:    "未检测到可采集设备",
			CheckedAt:  time.Now().Unix(),
			DetailJSON: mustJSON(map[string]any{"warnings": scanResult.Warnings}),
		})
		if opts.RequireAuthorized {
			_ = store.SavePrecheckResults(ctx, prechecks)
			_ = store.AppendAudit(ctx, caseID, "", "mobile_scan", "precheck", "failed", opts.Operator, "mobilescan.Run", map[string]any{"reason": "no device connected"})
			return nil, fmt.Errorf("mobile precheck failed: no device connected")
		}
	}

	androidCount := 0
	iosCount := 0
	hasAuthorized := false
	unauthorized := 0
	for _, d := range scanResult.Devices {
		switch d.Device.OS {
		case model.OSAndroid:
			androidCount++
		case model.OSIOS:
			iosCount++
		}

		checkCode := "mobile_device_authorized"
		checkName := "移动设备授权状态"
		switch d.Device.OS {
		case model.OSAndroid:
			checkCode = "android_usb_debug_authorized"
			checkName = "Android USB 调试授权"
		case model.OSIOS:
			checkCode = "ios_pair_validated"
			checkName = "iOS 设备配对授权"
		}
		status := model.PrecheckFailed
		if d.Authorized {
			status = model.PrecheckPassed
			hasAuthorized = true
		} else {
			unauthorized++
		}
		prechecks = append(prechecks, model.PrecheckResult{
			CaseID:    caseID,
			DeviceID:  d.Device.ID,
			ScanScope: "mobile",
			CheckCode: checkCode,
			CheckName: checkName,
			Required:  opts.RequireAuthorized,
			Status:    status,
			Message:   d.AuthNote,
			CheckedAt: time.Now().Unix(),
			DetailJSON: mustJSON(map[string]any{
				"device_os":  d.Device.OS,
				"identifier": d.Device.Identifier,
				"connection": d.ConnectionType,
				"authorized": d.Authorized,
			}),
		})

		if err := store.UpsertDeviceWithConnection(ctx, caseID, d.Device, d.ConnectionType, d.Authorized, d.AuthNote); err != nil {
			_ = store.AppendAudit(ctx, caseID, d.Device.ID, "mobile_scan", "upsert_device", "failed", opts.Operator, "mobilescan.Run", map[string]any{"error": err.Error()})
			return nil, err
		}
	}
	// 采集器层面的 prechecks（例如：浏览历史 best-effort 采集是否成功、为何 skipped）。
	if len(scanResult.Prechecks) > 0 {
		prechecks = append(prechecks, scanResult.Prechecks...)
	}
	if err := store.SavePrecheckResults(ctx, prechecks); err != nil {
		return nil, err
	}
	if opts.RequireAuthorized && !hasAuthorized {
		msg := "no authorized device; require Android USB debugging authorization or iOS pairing authorization"
		_ = store.AppendAudit(ctx, caseID, "", "mobile_scan", "precheck", "failed", opts.Operator, "mobilescan.Run", map[string]any{
			"require_authorized": opts.RequireAuthorized,
			"unauthorized_count": unauthorized,
		})
		return nil, fmt.Errorf("mobile precheck failed: %s", msg)
	}

	if err := store.SaveArtifacts(ctx, scanResult.Artifacts); err != nil {
		_ = store.AppendAudit(ctx, caseID, "", "mobile_scan", "save_artifacts", "failed", opts.Operator, "mobilescan.Run", map[string]any{"error": err.Error()})
		return nil, err
	}

	loader := rules.NewLoader(opts.WalletRulePath, opts.ExchangeRulePath)
	loaded, err := loader.Load(ctx)
	if err != nil {
		_ = store.AppendAudit(ctx, caseID, "", "mobile_scan", "load_rules", "failed", opts.Operator, "mobilescan.Run", map[string]any{"error": err.Error()})
		return nil, err
	}

	// 规则包留痕（best effort）：用于把“命中来自哪个规则文件版本/哈希”固化到 DB。
	walletBundleID := ""
	exchangeBundleID := ""
	if id, err := store.EnsureRuleBundle(ctx, "wallet_signatures", loaded.Wallet.Version, loaded.WalletSHA256, opts.WalletRulePath); err == nil {
		walletBundleID = id
	} else {
		_ = store.AppendAudit(ctx, caseID, "", "mobile_scan", "rule_bundle_wallet", "skipped", opts.Operator, "mobilescan.Run", map[string]any{"error": err.Error()})
	}
	if id, err := store.EnsureRuleBundle(ctx, "exchange_domains", loaded.Exchange.Version, loaded.ExchangeSHA256, opts.ExchangeRulePath); err == nil {
		exchangeBundleID = id
	} else {
		_ = store.AppendAudit(ctx, caseID, "", "mobile_scan", "rule_bundle_exchange", "skipped", opts.Operator, "mobilescan.Run", map[string]any{"error": err.Error()})
	}

	matchResult, err := matcher.MatchMobileArtifacts(loaded, scanResult.Artifacts)
	if err != nil {
		_ = store.AppendAudit(ctx, caseID, "", "mobile_scan", "match_rules", "failed", opts.Operator, "mobilescan.Run", map[string]any{"error": err.Error()})
		return nil, err
	}

	// 回填 rule_bundle_id：
	// - 钱包安装命中来自 wallet_signatures
	// - 交易所访问命中来自 exchange_domains（如果移动端后续也采集到浏览历史）
	for i := range matchResult.Hits {
		switch matchResult.Hits[i].Type {
		case model.HitWalletInstalled:
			matchResult.Hits[i].RuleBundleID = walletBundleID
		case model.HitExchangeVisited:
			matchResult.Hits[i].RuleBundleID = exchangeBundleID
		}
	}

	if err := store.SaveRuleHits(ctx, matchResult.Hits); err != nil {
		_ = store.AppendAudit(ctx, caseID, "", "mobile_scan", "save_hits", "failed", opts.Operator, "mobilescan.Run", map[string]any{"error": err.Error()})
		return nil, err
	}

	// 内部报告（JSON + HTML）
	jsonPath, jsonHash, jsonErr := writeInternalJSONReport(opts.DBPath, caseID, opts.AuthorizationOrder, opts.PrivacyMode, scanResult.Devices, scanResult.Artifacts, matchResult.Hits, scanResult.Warnings, prechecks)
	jsonReportID := ""
	if jsonErr == nil {
		jsonReportID, _ = store.SaveReport(ctx, caseID, "internal_json", jsonPath, jsonHash, "mobilescan-0.1.0", "ready")
	} else {
		scanResult.Warnings = append(scanResult.Warnings, "write internal_json report failed: "+jsonErr.Error())
	}

	htmlPath, htmlHash, htmlErr := writeInternalHTMLReport(opts.DBPath, caseID, opts.AuthorizationOrder, opts.PrivacyMode, scanResult.Devices, scanResult.Artifacts, matchResult.Hits, scanResult.Warnings, prechecks)
	if htmlErr == nil {
		_, _ = store.SaveReport(ctx, caseID, "internal_html", htmlPath, htmlHash, "mobilescan-0.1.0", "ready")
	} else {
		scanResult.Warnings = append(scanResult.Warnings, "write internal_html report failed: "+htmlErr.Error())
	}

	status := "success"
	if len(scanResult.Warnings) > 0 {
		status = "skipped"
	}
	_ = store.AppendAudit(ctx, caseID, "", "mobile_scan", "scan_finish", status, opts.Operator, "mobilescan.Run", map[string]any{
		"device_count":         len(scanResult.Devices),
		"artifact_count":       len(scanResult.Artifacts),
		"hit_count":            len(matchResult.Hits),
		"warnings":             scanResult.Warnings,
		"report_internal_json": jsonPath,
		"report_internal_html": htmlPath,
	})

	walletHits := 0
	for _, h := range matchResult.Hits {
		if h.Type == model.HitWalletInstalled {
			walletHits++
		}
	}

	return &Result{
		CaseID:        caseID,
		DeviceCount:   len(scanResult.Devices),
		AndroidCount:  androidCount,
		IOSCount:      iosCount,
		ArtifactCount: len(scanResult.Artifacts),
		HitCount:      len(matchResult.Hits),
		WalletHits:    walletHits,
		Warnings:      scanResult.Warnings,
		ReportID:      jsonReportID,
		ReportPath:    jsonPath,
		StartedAt:     started,
		FinishedAt:    time.Now().Unix(),
	}, nil
}

func precheckTool(caseID, scope, code, name string, required bool, binary string) model.PrecheckResult {
	result := model.PrecheckResult{
		CaseID:    caseID,
		ScanScope: scope,
		CheckCode: code,
		CheckName: name,
		Required:  required,
		CheckedAt: time.Now().Unix(),
	}
	if _, err := exec.LookPath(binary); err != nil {
		result.Status = model.PrecheckSkipped
		result.Message = fmt.Sprintf("%s not found", binary)
		result.DetailJSON = mustJSON(map[string]any{"binary": binary})
		return result
	}
	result.Status = model.PrecheckPassed
	result.Message = "ok"
	result.DetailJSON = mustJSON(map[string]any{"binary": binary})
	return result
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return raw
}

func writeInternalJSONReport(dbPath, caseID, authOrder, privacyMode string, devices []mobile.ConnectedDevice, artifacts []model.Artifact, hits []model.RuleHit, warnings []string, prechecks []model.PrecheckResult) (path string, sha string, err error) {
	reportDir := filepath.Join(filepath.Dir(dbPath), "reports")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return "", "", err
	}

	type deviceSummary struct {
		DeviceID      string       `json:"device_id"`
		Name          string       `json:"name"`
		OS            model.OSType `json:"os"`
		Identifier    string       `json:"identifier"`
		Connection    string       `json:"connection"`
		Authorized    bool         `json:"authorized"`
		Authorization string       `json:"authorization"`
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

	deviceRows := make([]deviceSummary, 0, len(devices))
	for _, d := range devices {
		deviceRows = append(deviceRows, deviceSummary{
			DeviceID:      d.Device.ID,
			Name:          d.Device.Name,
			OS:            d.Device.OS,
			Identifier:    d.Device.Identifier,
			Connection:    d.ConnectionType,
			Authorized:    d.Authorized,
			Authorization: d.AuthNote,
		})
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
		"devices":             deviceRows,
		"summary": map[string]any{
			"device_count":   len(devices),
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

	filename := fmt.Sprintf("%s_mobile_internal_%d.json", caseID, time.Now().Unix())
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

func writeInternalHTMLReport(dbPath, caseID, authOrder, privacyMode string, devices []mobile.ConnectedDevice, artifacts []model.Artifact, hits []model.RuleHit, warnings []string, prechecks []model.PrecheckResult) (path string, sha string, err error) {
	reportDir := filepath.Join(filepath.Dir(dbPath), "reports")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return "", "", err
	}

	now := time.Now().Unix()
	filename := fmt.Sprintf("%s_mobile_internal_%d.html", caseID, now)
	path = filepath.Join(reportDir, filename)

	var b strings.Builder
	b.Grow(32 * 1024)
	b.WriteString("<!doctype html>\n<html lang=\"zh-CN\">\n<head>\n")
	b.WriteString("<meta charset=\"utf-8\"/>\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>\n")
	b.WriteString("<title>数字货币痕迹检测报告（移动端，内部）</title>\n")
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
	b.WriteString("</style>\n</head>\n<body>\n")

	b.WriteString("<h1>数字货币痕迹检测报告（移动端，内部）</h1>\n")
	b.WriteString("<div class=\"box kv\">")
	b.WriteString("<div class=\"muted\">case_id</div><div class=\"mono\">" + htmlEscape(caseID) + "</div>")
	b.WriteString("<div class=\"muted\">generated_at</div><div class=\"mono\">" + htmlEscape(time.Unix(now, 0).Format("2006-01-02 15:04:05")) + "</div>")
	b.WriteString("<div class=\"muted\">authorization_order</div><div class=\"mono\">" + htmlEscape(authOrder) + "</div>")
	b.WriteString("<div class=\"muted\">privacy_mode</div><div class=\"mono\">" + htmlEscape(privacyMode) + "</div>")
	b.WriteString("</div>\n")

	b.WriteString("<h2>设备</h2>\n<div class=\"box\">")
	if len(devices) == 0 {
		b.WriteString("<div class=\"muted\">(empty)</div>")
	} else {
		b.WriteString("<table><thead><tr><th>os</th><th>name</th><th>identifier</th><th>connection</th><th>authorized</th><th>note</th></tr></thead><tbody>")
		for _, d := range devices {
			authText := "no"
			if d.Authorized {
				authText = "yes"
			}
			b.WriteString("<tr>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(string(d.Device.OS)) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(d.Device.Name) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(d.Device.Identifier) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(d.ConnectionType) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(authText) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(d.AuthNote) + "</td>")
			b.WriteString("</tr>")
		}
		b.WriteString("</tbody></table>")
	}
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
			b.WriteString("<tr>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(a.ID) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(string(a.Type)) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(a.SourceRef) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(a.SHA256) + "</td>")
			b.WriteString("<td class=\"mono\">" + htmlEscape(a.SnapshotPath) + "</td>")
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
