package webapp

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"

	sqliteadapter "crypto-inspector/internal/adapters/store/sqlite"
	"crypto-inspector/internal/app"

	_ "modernc.org/sqlite"
)

// 注意：
// - go:embed 的路径必须相对当前包目录，且不能包含 ".."
// - 我们把前端 build 输出拷贝到 internal/services/webapp/ui_dist/，这样二进制即可离线分发（解压即用）。
// - ui_dist/ 至少要有一个文件（本仓库已放置占位 index.html），否则 go:embed 会因“无匹配文件”而编译失败。
//
//go:embed ui_dist
var uiFS embed.FS

// Options 定义 Web UI + API 服务启动参数。
// 目标：内部试用优先，好用优先（默认不做鉴权、不做隐私脱敏）。
type Options struct {
	DBPath           string
	EvidenceRoot     string
	IOSBackupDir     string
	WalletRulePath   string
	ExchangeRulePath string

	ListenAddr          string
	EnableIOSFullBackup bool
	PrivacyMode         string // 预留：off|masked（当前仅记录，不做脱敏）
}

// Run 启动内置 Web UI：
// - 提供案件列表、命中、证据、审计、报告浏览接口
// - 提供“一键 scan all”后台任务接口（内测用）
func Run(ctx context.Context, opts Options) error {
	defaults := app.DefaultConfig()
	if opts.DBPath == "" {
		opts.DBPath = defaults.DBPath
	}
	if opts.EvidenceRoot == "" {
		opts.EvidenceRoot = "data/evidence"
	}
	if opts.IOSBackupDir == "" {
		opts.IOSBackupDir = filepath.Join(opts.EvidenceRoot, "ios_backups")
	}
	if opts.WalletRulePath == "" {
		opts.WalletRulePath = defaults.WalletRulePath
	}
	if opts.ExchangeRulePath == "" {
		opts.ExchangeRulePath = defaults.ExchangeRulePath
	}
	if opts.ListenAddr == "" {
		opts.ListenAddr = "127.0.0.1:8787"
	}
	if opts.PrivacyMode == "" {
		opts.PrivacyMode = "off"
	}

	if err := os.MkdirAll(filepath.Dir(opts.DBPath), 0o755); err != nil {
		return fmt.Errorf("create db directory: %w", err)
	}
	if err := os.MkdirAll(opts.EvidenceRoot, 0o755); err != nil {
		return fmt.Errorf("create evidence directory: %w", err)
	}
	if err := os.MkdirAll(opts.IOSBackupDir, 0o755); err != nil {
		return fmt.Errorf("create ios backup dir: %w", err)
	}

	db, err := sql.Open("sqlite", opts.DBPath)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		return fmt.Errorf("set busy_timeout: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping sqlite: %w", err)
	}

	migrator := sqliteadapter.NewMigrator(db)
	if err := migrator.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	sub, err := fs.Sub(uiFS, "ui_dist")
	if err != nil {
		return fmt.Errorf("sub ui fs: %w", err)
	}

	s := &Server{
		opts:  opts,
		db:    db,
		store: sqliteadapter.NewStore(db),
		ui:    sub,
		jobs:  newJobManager(),
	}

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	httpServer := &http.Server{
		Addr:              opts.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	fmt.Printf("webapp listening: http://%s\n", opts.ListenAddr)
	err = httpServer.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
