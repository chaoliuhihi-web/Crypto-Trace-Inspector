package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"crypto-inspector/internal/adapters/rules"
	sqliteadapter "crypto-inspector/internal/adapters/store/sqlite"
	"crypto-inspector/internal/app"
	"crypto-inspector/internal/domain/model"
	"crypto-inspector/internal/services/caseview"
	"crypto-inspector/internal/services/forensicexport"
	"crypto-inspector/internal/services/forensicpdf"
	"crypto-inspector/internal/services/hostscan"
	"crypto-inspector/internal/services/mobilescan"
	"crypto-inspector/internal/services/webapp"

	_ "modernc.org/sqlite"
)

// CLI 入口。所有子命令错误都统一输出到 stderr 并返回非 0 状态码。
func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// run 是一级命令路由：migrate / rules / scan。
func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "migrate":
		return runMigrate(ctx, args[1:])
	case "rules":
		return runRules(ctx, args[1:])
	case "scan":
		return runScan(ctx, args[1:])
	case "query":
		return runQuery(ctx, args[1:])
	case "export":
		return runExport(ctx, args[1:])
	case "verify":
		return runVerify(ctx, args[1:])
	case "serve":
		return runServe(ctx, args[1:])
	default:
		printUsage()
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

// runMigrate 执行 SQLite 迁移，确保数据库结构完整。
func runMigrate(ctx context.Context, args []string) error {
	cfg := app.DefaultConfig()

	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	dbPath := fs.String("db", cfg.DBPath, "sqlite database path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o755); err != nil {
		return fmt.Errorf("create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping sqlite: %w", err)
	}

	m := sqliteadapter.NewMigrator(db)
	if err := m.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	fmt.Printf("migrations applied successfully: db=%s\n", *dbPath)
	return nil
}

// runRules 是二级命令路由，目前支持 rules validate。
func runRules(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printRulesUsage()
		return nil
	}

	switch args[0] {
	case "validate":
		return runRulesValidate(ctx, args[1:])
	default:
		printRulesUsage()
		return fmt.Errorf("unknown rules command: %s", args[0])
	}
}

// runScan 是二级命令路由，目前支持 scan host / scan mobile。
func runScan(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printScanUsage()
		return nil
	}

	switch args[0] {
	case "host":
		return runScanHost(ctx, args[1:])
	case "mobile":
		return runScanMobile(ctx, args[1:])
	case "all":
		return runScanAll(ctx, args[1:])
	default:
		printScanUsage()
		return fmt.Errorf("unknown scan command: %s", args[0])
	}
}

// runScanHost 执行主机扫描全流程（采集 -> 匹配 -> 入库 -> 报告）。
func runScanHost(ctx context.Context, args []string) error {
	cfg := app.DefaultConfig()

	fs := flag.NewFlagSet("scan host", flag.ContinueOnError)
	dbPath := fs.String("db", cfg.DBPath, "sqlite database path")
	evidenceRoot := fs.String("evidence-dir", "data/evidence", "evidence output directory")
	walletPath := fs.String("wallet", cfg.WalletRulePath, "wallet rule file")
	exchangePath := fs.String("exchange", cfg.ExchangeRulePath, "exchange rule file")
	caseID := fs.String("case-id", "", "existing case id (optional)")
	operator := fs.String("operator", "system", "operator id or name")
	note := fs.String("note", "", "case note")
	authOrder := fs.String("auth-order", "", "authorization order/work ticket id (optional in internal mode)")
	authBasis := fs.String("auth-basis", "", "authorization legal basis reference (optional)")
	requireAuthOrder := fs.Bool("require-auth-order", false, "require auth order in this run (recommended for external mode)")
	privacyMode := fs.String("privacy-mode", "off", "privacy mode switch (reserved): off|masked")
	if err := fs.Parse(args); err != nil {
		return err
	}

	result, err := hostscan.Run(ctx, hostscan.Options{
		DBPath:             *dbPath,
		EvidenceRoot:       *evidenceRoot,
		WalletRulePath:     *walletPath,
		ExchangeRulePath:   *exchangePath,
		CaseID:             *caseID,
		Operator:           *operator,
		Note:               *note,
		AuthorizationOrder: *authOrder,
		AuthorizationBasis: *authBasis,
		RequireAuthOrder:   *requireAuthOrder,
		PrivacyMode:        *privacyMode,
	})
	if err != nil {
		return err
	}

	fmt.Println("host scan completed")
	fmt.Printf("case_id=%s\n", result.CaseID)
	fmt.Printf("device=%s (%s)\n", result.DeviceName, result.DeviceOS)
	fmt.Printf("artifacts=%d hits=%d wallet_hits=%d exchange_hits=%d\n",
		result.ArtifactCount, result.HitCount, result.WalletHits, result.ExchangeHits,
	)
	if result.ReportPath != "" {
		fmt.Printf("report=%s\n", result.ReportPath)
	}
	if len(result.Warnings) > 0 {
		fmt.Printf("warnings=%s\n", strings.Join(result.Warnings, " | "))
	}
	return nil
}

// runScanMobile 执行移动端扫描（Android + iOS 骨架）。
func runScanMobile(ctx context.Context, args []string) error {
	cfg := app.DefaultConfig()

	fs := flag.NewFlagSet("scan mobile", flag.ContinueOnError)
	dbPath := fs.String("db", cfg.DBPath, "sqlite database path")
	evidenceRoot := fs.String("evidence-dir", "data/evidence", "evidence output directory")
	iosBackupDir := fs.String("ios-backup-dir", "data/evidence/ios_backups", "ios backup root directory")
	walletPath := fs.String("wallet", cfg.WalletRulePath, "wallet rule file")
	exchangePath := fs.String("exchange", cfg.ExchangeRulePath, "exchange rule file")
	caseID := fs.String("case-id", "", "existing case id (optional)")
	operator := fs.String("operator", "system", "operator id or name")
	note := fs.String("note", "", "case note")
	authOrder := fs.String("auth-order", "", "authorization order/work ticket id (optional in internal mode)")
	authBasis := fs.String("auth-basis", "", "authorization legal basis reference (optional)")
	requireAuthOrder := fs.Bool("require-auth-order", false, "require auth order in this run (recommended for external mode)")
	requireAuthorized := fs.Bool("require-authorized", false, "require at least one authorized device (Android 调试授权 / iOS 配对授权)")
	enableIOSFullBackup := fs.Bool("ios-full-backup", true, "try full iOS backup when idevicebackup2 is available")
	privacyMode := fs.String("privacy-mode", "off", "privacy mode switch (reserved): off|masked")
	if err := fs.Parse(args); err != nil {
		return err
	}

	result, err := mobilescan.Run(ctx, mobilescan.Options{
		DBPath:              *dbPath,
		EvidenceRoot:        *evidenceRoot,
		IOSBackupDir:        *iosBackupDir,
		WalletRulePath:      *walletPath,
		ExchangeRulePath:    *exchangePath,
		CaseID:              *caseID,
		Operator:            *operator,
		Note:                *note,
		AuthorizationOrder:  *authOrder,
		AuthorizationBasis:  *authBasis,
		RequireAuthOrder:    *requireAuthOrder,
		RequireAuthorized:   *requireAuthorized,
		EnableIOSFullBackup: *enableIOSFullBackup,
		PrivacyMode:         *privacyMode,
	})
	if err != nil {
		return err
	}

	fmt.Println("mobile scan completed")
	fmt.Printf("case_id=%s\n", result.CaseID)
	fmt.Printf("devices=%d android=%d ios=%d artifacts=%d hits=%d wallet_hits=%d\n",
		result.DeviceCount, result.AndroidCount, result.IOSCount, result.ArtifactCount, result.HitCount, result.WalletHits,
	)
	if result.ReportPath != "" {
		fmt.Printf("report=%s\n", result.ReportPath)
	}
	if len(result.Warnings) > 0 {
		fmt.Printf("warnings=%s\n", strings.Join(result.Warnings, " | "))
	}
	return nil
}

// runScanAll 一次执行 host + mobile 扫描，默认内部试用模式（best effort）。
func runScanAll(ctx context.Context, args []string) error {
	cfg := app.DefaultConfig()

	fs := flag.NewFlagSet("scan all", flag.ContinueOnError)
	dbPath := fs.String("db", cfg.DBPath, "sqlite database path")
	evidenceRoot := fs.String("evidence-dir", "data/evidence", "evidence output directory")
	iosBackupDir := fs.String("ios-backup-dir", "data/evidence/ios_backups", "ios backup root directory")
	walletPath := fs.String("wallet", cfg.WalletRulePath, "wallet rule file")
	exchangePath := fs.String("exchange", cfg.ExchangeRulePath, "exchange rule file")
	caseID := fs.String("case-id", "", "existing case id (optional)")
	operator := fs.String("operator", "system", "operator id or name")
	note := fs.String("note", "", "case note")
	authOrder := fs.String("auth-order", "", "authorization order/work ticket id")
	authBasis := fs.String("auth-basis", "", "authorization legal basis reference")
	profile := fs.String("profile", "internal", "scan profile: internal|external")
	continueOnError := fs.Bool("continue-on-error", true, "continue mobile scan even if host scan fails")
	enableIOSFullBackup := fs.Bool("ios-full-backup", true, "try full iOS backup when idevicebackup2 is available")
	privacyMode := fs.String("privacy-mode", "off", "privacy mode switch (reserved): off|masked")
	if err := fs.Parse(args); err != nil {
		return err
	}

	mode := strings.ToLower(strings.TrimSpace(*profile))
	requireAuthOrder := false
	requireAuthorized := false
	switch mode {
	case "", "internal":
		mode = "internal"
	case "external":
		requireAuthOrder = true
		requireAuthorized = true
	default:
		return fmt.Errorf("invalid --profile: %s (expect internal|external)", *profile)
	}

	var hostRes *hostscan.Result
	var mobileRes *mobilescan.Result
	var hostErr error
	var mobileErr error

	hostRes, hostErr = hostscan.Run(ctx, hostscan.Options{
		DBPath:             *dbPath,
		EvidenceRoot:       *evidenceRoot,
		WalletRulePath:     *walletPath,
		ExchangeRulePath:   *exchangePath,
		CaseID:             *caseID,
		Operator:           *operator,
		Note:               *note,
		AuthorizationOrder: *authOrder,
		AuthorizationBasis: *authBasis,
		RequireAuthOrder:   requireAuthOrder,
		PrivacyMode:        *privacyMode,
	})
	if hostErr != nil && !*continueOnError {
		return fmt.Errorf("scan all host failed: %w", hostErr)
	}

	sharedCaseID := strings.TrimSpace(*caseID)
	if hostRes != nil && hostRes.CaseID != "" {
		sharedCaseID = hostRes.CaseID
	}
	mobileRes, mobileErr = mobilescan.Run(ctx, mobilescan.Options{
		DBPath:              *dbPath,
		EvidenceRoot:        *evidenceRoot,
		IOSBackupDir:        *iosBackupDir,
		WalletRulePath:      *walletPath,
		ExchangeRulePath:    *exchangePath,
		CaseID:              sharedCaseID,
		Operator:            *operator,
		Note:                *note,
		AuthorizationOrder:  *authOrder,
		AuthorizationBasis:  *authBasis,
		RequireAuthOrder:    requireAuthOrder,
		RequireAuthorized:   requireAuthorized,
		EnableIOSFullBackup: *enableIOSFullBackup,
		PrivacyMode:         *privacyMode,
	})

	fmt.Printf("scan all completed profile=%s\n", mode)
	if hostRes != nil {
		fmt.Printf("host: case_id=%s artifacts=%d hits=%d wallet_hits=%d exchange_hits=%d report=%s\n",
			hostRes.CaseID, hostRes.ArtifactCount, hostRes.HitCount, hostRes.WalletHits, hostRes.ExchangeHits, hostRes.ReportPath)
	}
	if hostErr != nil {
		fmt.Printf("host_error=%v\n", hostErr)
	}
	if mobileRes != nil {
		fmt.Printf("mobile: case_id=%s devices=%d artifacts=%d hits=%d wallet_hits=%d report=%s\n",
			mobileRes.CaseID, mobileRes.DeviceCount, mobileRes.ArtifactCount, mobileRes.HitCount, mobileRes.WalletHits, mobileRes.ReportPath)
		if len(mobileRes.Warnings) > 0 {
			fmt.Printf("mobile_warnings=%s\n", strings.Join(mobileRes.Warnings, " | "))
		}
	}
	if mobileErr != nil {
		fmt.Printf("mobile_error=%v\n", mobileErr)
	}

	if hostErr != nil && mobileErr != nil {
		return fmt.Errorf("scan all failed: host=%v; mobile=%v", hostErr, mobileErr)
	}
	return nil
}

// runQuery 是查询命令路由（命中明细/报告展示）。
func runQuery(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printQueryUsage()
		return nil
	}
	switch args[0] {
	case "host-hits":
		return runQueryHostHits(ctx, args[1:])
	case "report":
		return runQueryReport(ctx, args[1:])
	default:
		printQueryUsage()
		return fmt.Errorf("unknown query command: %s", args[0])
	}
}

// runExport 是导出命令路由：用于生成司法导出包/取证报告等产物。
func runExport(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printExportUsage()
		return nil
	}
	switch args[0] {
	case "forensic-zip":
		return runExportForensicZip(ctx, args[1:])
	case "forensic-pdf":
		return runExportForensicPDF(ctx, args[1:])
	default:
		printExportUsage()
		return fmt.Errorf("unknown export command: %s", args[0])
	}
}

func runExportForensicZip(ctx context.Context, args []string) error {
	cfg := app.DefaultConfig()

	fs := flag.NewFlagSet("export forensic-zip", flag.ContinueOnError)
	dbPath := fs.String("db", cfg.DBPath, "sqlite database path")
	evidenceRoot := fs.String("evidence-dir", "data/evidence", "evidence output directory")
	walletPath := fs.String("wallet", cfg.WalletRulePath, "wallet rule file")
	exchangePath := fs.String("exchange", cfg.ExchangeRulePath, "exchange rule file")
	caseID := fs.String("case-id", "", "case id (required)")
	operator := fs.String("operator", "system", "operator id or name")
	note := fs.String("note", "", "export note")
	outDir := fs.String("out-dir", "", "export output directory (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*caseID) == "" {
		return fmt.Errorf("--case-id is required")
	}

	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o755); err != nil {
		return fmt.Errorf("create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		return fmt.Errorf("set busy_timeout: %w", err)
	}

	migrator := sqliteadapter.NewMigrator(db)
	if err := migrator.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	store := sqliteadapter.NewStore(db)
	res, err := forensicexport.GenerateForensicZip(ctx, store, forensicexport.ZipOptions{
		CaseID:           strings.TrimSpace(*caseID),
		DBPath:           *dbPath,
		EvidenceRoot:     *evidenceRoot,
		WalletRulePath:   *walletPath,
		ExchangeRulePath: *exchangePath,
		Operator:         strings.TrimSpace(*operator),
		Note:             strings.TrimSpace(*note),
		ExportDir:        strings.TrimSpace(*outDir),
	})
	if err != nil {
		return err
	}

	fmt.Println("forensic zip export completed")
	fmt.Printf("case_id=%s report_id=%s\n", res.CaseID, res.ReportID)
	fmt.Printf("zip=%s\n", res.ZipPath)
	fmt.Printf("zip_sha256=%s\n", res.ZipSHA256)
	if len(res.Warnings) > 0 {
		fmt.Printf("warnings=%s\n", strings.Join(res.Warnings, " | "))
	}
	return nil
}

func runExportForensicPDF(ctx context.Context, args []string) error {
	cfg := app.DefaultConfig()

	fs := flag.NewFlagSet("export forensic-pdf", flag.ContinueOnError)
	dbPath := fs.String("db", cfg.DBPath, "sqlite database path")
	caseID := fs.String("case-id", "", "case id (required)")
	operator := fs.String("operator", "system", "operator id or name")
	note := fs.String("note", "", "export note")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*caseID) == "" {
		return fmt.Errorf("--case-id is required")
	}

	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o755); err != nil {
		return fmt.Errorf("create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		return fmt.Errorf("set busy_timeout: %w", err)
	}

	migrator := sqliteadapter.NewMigrator(db)
	if err := migrator.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	store := sqliteadapter.NewStore(db)
	res, err := forensicpdf.GenerateForensicPDF(ctx, store, forensicpdf.Options{
		CaseID:   strings.TrimSpace(*caseID),
		DBPath:   *dbPath,
		Operator: strings.TrimSpace(*operator),
		Note:     strings.TrimSpace(*note),
	})
	if err != nil {
		return err
	}

	fmt.Println("forensic pdf export completed")
	fmt.Printf("case_id=%s report_id=%s\n", strings.TrimSpace(*caseID), res.ReportID)
	fmt.Printf("pdf=%s\n", res.PDFPath)
	fmt.Printf("pdf_sha256=%s\n", res.PDFSHA256)
	if len(res.Warnings) > 0 {
		fmt.Printf("warnings=%s\n", strings.Join(res.Warnings, " | "))
	}
	return nil
}

// runServe 启动内置 Web UI + API，便于“安装即用”的内测体验。
func runServe(ctx context.Context, args []string) error {
	cfg := app.DefaultConfig()

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	dbPath := fs.String("db", cfg.DBPath, "sqlite database path")
	evidenceRoot := fs.String("evidence-dir", "data/evidence", "evidence output directory")
	iosBackupDir := fs.String("ios-backup-dir", "data/evidence/ios_backups", "ios backup root directory")
	walletPath := fs.String("wallet", cfg.WalletRulePath, "wallet rule file")
	exchangePath := fs.String("exchange", cfg.ExchangeRulePath, "exchange rule file")
	listen := fs.String("listen", "127.0.0.1:8787", "listen address")
	enableIOSFullBackup := fs.Bool("ios-full-backup", true, "try full iOS backup when idevicebackup2 is available")
	privacyMode := fs.String("privacy-mode", "off", "privacy mode switch (reserved): off|masked")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// 支持 Ctrl+C 优雅退出。
	sigCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	return webapp.Run(sigCtx, webapp.Options{
		DBPath:              *dbPath,
		EvidenceRoot:        *evidenceRoot,
		IOSBackupDir:        *iosBackupDir,
		WalletRulePath:      *walletPath,
		ExchangeRulePath:    *exchangePath,
		ListenAddr:          *listen,
		EnableIOSFullBackup: *enableIOSFullBackup,
		PrivacyMode:         *privacyMode,
	})
}

// runQueryHostHits 查询案件命中明细，适合 UI 列表页。
func runQueryHostHits(ctx context.Context, args []string) error {
	cfg := app.DefaultConfig()

	fs := flag.NewFlagSet("query host-hits", flag.ContinueOnError)
	dbPath := fs.String("db", cfg.DBPath, "sqlite database path")
	caseID := fs.String("case-id", "", "case id (required)")
	hitType := fs.String("hit-type", "", "optional hit type filter")
	asJSON := fs.Bool("json", true, "print as json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*caseID) == "" {
		return fmt.Errorf("--case-id is required")
	}

	view, err := caseview.GetHostHitView(ctx, *dbPath, *caseID, strings.TrimSpace(*hitType))
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(view)
	}

	fmt.Printf("case_id=%s hit_count=%d\n", view.Overview.CaseID, len(view.Hits))
	for _, h := range view.Hits {
		fmt.Printf("hit_id=%s type=%s rule=%s matched=%s confidence=%.2f verdict=%s\n",
			h.HitID, h.HitType, h.RuleID, h.MatchedValue, h.Confidence, h.Verdict)
	}
	return nil
}

// runQueryReport 查询案件报告索引与内容，适合 UI 报告页。
func runQueryReport(ctx context.Context, args []string) error {
	cfg := app.DefaultConfig()

	fs := flag.NewFlagSet("query report", flag.ContinueOnError)
	dbPath := fs.String("db", cfg.DBPath, "sqlite database path")
	caseID := fs.String("case-id", "", "case id (required)")
	reportID := fs.String("report-id", "", "optional report id")
	includeContent := fs.Bool("content", true, "include report file content")
	asJSON := fs.Bool("json", true, "print as json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*caseID) == "" {
		return fmt.Errorf("--case-id is required")
	}

	view, err := caseview.GetReportView(ctx, *dbPath, *caseID, strings.TrimSpace(*reportID), *includeContent)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(view)
	}

	if view.Report == nil {
		fmt.Printf("case_id=%s no report found\n", view.Overview.CaseID)
		return nil
	}
	fmt.Printf("case_id=%s report_id=%s type=%s path=%s generated_at=%d\n",
		view.Report.CaseID, view.Report.ReportID, view.Report.ReportType, view.Report.FilePath, view.Report.GeneratedAt)
	if *includeContent {
		fmt.Printf("content_length=%d\n", view.ContentLength)
		fmt.Println(view.Content)
	}
	return nil
}

// runRulesValidate 用于规则文件合法性检查，输出规则版本与哈希摘要。
func runRulesValidate(ctx context.Context, args []string) error {
	cfg := app.DefaultConfig()

	fs := flag.NewFlagSet("rules validate", flag.ContinueOnError)
	walletPath := fs.String("wallet", cfg.WalletRulePath, "wallet rule file")
	exchangePath := fs.String("exchange", cfg.ExchangeRulePath, "exchange rule file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	loader := rules.NewLoader(*walletPath, *exchangePath)
	loaded, err := loader.Load(ctx)
	if err != nil {
		return err
	}

	fmt.Println("rule validation passed")
	fmt.Printf("wallet: version=%s total=%d enabled=%d sha256=%s\n",
		loaded.Wallet.Version,
		len(loaded.Wallet.Wallets),
		countEnabledWallets(loaded.Wallet.Wallets),
		loaded.WalletSHA256,
	)
	fmt.Printf("exchange: version=%s total=%d enabled=%d sha256=%s\n",
		loaded.Exchange.Version,
		len(loaded.Exchange.Exchanges),
		countEnabledExchanges(loaded.Exchange.Exchanges),
		loaded.ExchangeSHA256,
	)

	return nil
}

// 统计启用的钱包规则数量，便于启动时快速确认规则是否生效。
func countEnabledWallets(wallets []model.WalletSignature) int {
	total := 0
	for _, w := range wallets {
		if w.Enabled {
			total++
		}
	}
	return total
}

// 统计启用的交易所规则数量。
func countEnabledExchanges(exchanges []model.ExchangeDomain) int {
	total := 0
	for _, ex := range exchanges {
		if ex.Enabled {
			total++
		}
	}
	return total
}

// printUsage 输出一级命令帮助。
func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  inspector-cli migrate [--db data/inspector.db]")
	fmt.Println("  inspector-cli rules validate [--wallet rules/wallet_signatures.template.yaml] [--exchange rules/exchange_domains.template.yaml]")
	fmt.Println("  inspector-cli scan host [--db data/inspector.db] [--evidence-dir data/evidence] [--case-id CASE_ID] [--auth-order TICKET]")
	fmt.Println("  inspector-cli scan mobile [--db data/inspector.db] [--evidence-dir data/evidence] [--ios-backup-dir data/evidence/ios_backups] [--case-id CASE_ID] [--auth-order TICKET]")
	fmt.Println("  inspector-cli scan all [--db data/inspector.db] [--evidence-dir data/evidence] [--profile internal|external] [--privacy-mode off|masked]")
	fmt.Println("  inspector-cli query host-hits --case-id CASE_ID [--hit-type wallet_installed|exchange_visited]")
	fmt.Println("  inspector-cli query report --case-id CASE_ID [--report-id REPORT_ID]")
	fmt.Println("  inspector-cli export forensic-zip --case-id CASE_ID [--db data/inspector.db] [--evidence-dir data/evidence]")
	fmt.Println("  inspector-cli export forensic-pdf --case-id CASE_ID [--db data/inspector.db]")
	fmt.Println("  inspector-cli verify forensic-zip --zip PATH_TO_ZIP")
	fmt.Println("  inspector-cli verify artifacts --case-id CASE_ID [--db data/inspector.db] [--artifact-id ART_ID]")
	fmt.Println("  inspector-cli serve [--listen 127.0.0.1:8787] [--db data/inspector.db]")
}

// printRulesUsage 输出 rules 子命令帮助。
func printRulesUsage() {
	fmt.Println("Usage:")
	fmt.Println("  inspector-cli rules validate [--wallet path] [--exchange path]")
}

// printScanUsage 输出 scan 子命令帮助。
func printScanUsage() {
	fmt.Println("Usage:")
	fmt.Println("  inspector-cli scan host [--db path] [--evidence-dir path] [--wallet path] [--exchange path] [--case-id id] [--operator name] [--note text] [--auth-order TICKET] [--auth-basis text] [--require-auth-order] [--privacy-mode off|masked]")
	fmt.Println("  inspector-cli scan mobile [--db path] [--evidence-dir path] [--ios-backup-dir path] [--wallet path] [--exchange path] [--case-id id] [--operator name] [--note text] [--auth-order TICKET] [--auth-basis text] [--require-auth-order] [--require-authorized] [--ios-full-backup] [--privacy-mode off|masked]")
	fmt.Println("  inspector-cli scan all [--db path] [--evidence-dir path] [--ios-backup-dir path] [--wallet path] [--exchange path] [--case-id id] [--operator name] [--note text] [--auth-order TICKET] [--auth-basis text] [--profile internal|external] [--continue-on-error] [--ios-full-backup] [--privacy-mode off|masked]")
}

// printQueryUsage 输出 query 子命令帮助。
func printQueryUsage() {
	fmt.Println("Usage:")
	fmt.Println("  inspector-cli query host-hits --case-id id [--db path] [--hit-type type] [--json=true]")
	fmt.Println("  inspector-cli query report --case-id id [--report-id id] [--db path] [--content=true] [--json=true]")
}

func printExportUsage() {
	fmt.Println("Usage:")
	fmt.Println("  inspector-cli export forensic-zip --case-id CASE_ID [--db path] [--evidence-dir path] [--wallet path] [--exchange path] [--out-dir path]")
	fmt.Println("  inspector-cli export forensic-pdf --case-id CASE_ID [--db path] [--operator name] [--note text]")
}

func printJSON(v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(raw))
	return nil
}
