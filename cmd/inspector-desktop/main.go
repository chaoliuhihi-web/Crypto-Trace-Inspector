package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"crypto-inspector/internal/app"
	"crypto-inspector/internal/services/webapp"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// 这个“desktop”入口的目标是降低内测门槛：
// - 一键启动内置 Web UI/API（本地端口监听）
// - 自动打开浏览器到工作台页面
//
// 这里不引入 Wails/webview 等 GUI 依赖，避免 CGO/打包复杂度；
// 后续如确有需要，再把该入口替换为真正的桌面壳即可。
func run(ctx context.Context, args []string) error {
	cfg := app.DefaultConfig()

	fs := flag.NewFlagSet("inspector-desktop", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8787", "listen address")
	dbPath := fs.String("db", cfg.DBPath, "sqlite database path")
	evidenceRoot := fs.String("evidence-dir", "data/evidence", "evidence output directory")
	iosBackupDir := fs.String("ios-backup-dir", "data/evidence/ios_backups", "ios backup root directory")
	walletPath := fs.String("wallet", cfg.WalletRulePath, "wallet rule file")
	exchangePath := fs.String("exchange", cfg.ExchangeRulePath, "exchange rule file")
	enableIOSFullBackup := fs.Bool("ios-full-backup", true, "try full iOS backup when idevicebackup2 is available")
	privacyMode := fs.String("privacy-mode", "off", "privacy mode switch (reserved): off|masked")
	noOpen := fs.Bool("no-open", false, "do not auto-open browser")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Ctrl+C 优雅退出：给 http.Server.Shutdown 一个机会释放端口、刷完日志。
	sigCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- webapp.Run(sigCtx, webapp.Options{
			DBPath:              *dbPath,
			EvidenceRoot:        *evidenceRoot,
			IOSBackupDir:        *iosBackupDir,
			WalletRulePath:      *walletPath,
			ExchangeRulePath:    *exchangePath,
			ListenAddr:          *listen,
			EnableIOSFullBackup: *enableIOSFullBackup,
			PrivacyMode:         *privacyMode,
		})
	}()

	uiURL := "http://" + normalizeListenForBrowser(*listen)
	healthURL := uiURL + "/api/health"

	// 等服务起来再打开浏览器（减少“空白页/加载失败”的概率）
	if !*noOpen {
		_ = waitForHTTP(sigCtx, healthURL, 12*time.Second)
		_ = openBrowser(uiURL)
	}

	// 阻塞等待 server 退出（或报错）
	return <-serverErrCh
}

func normalizeListenForBrowser(listen string) string {
	// listen 常见形态：127.0.0.1:8787 / 0.0.0.0:8787 / :8787 / [::]:8787
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		// fallback：不做复杂解析，直接返回原始字符串
		return listen
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func waitForHTTP(ctx context.Context, url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return fmt.Errorf("timeout waiting for %s", url)
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		// cmd /c start "" "http://..."
		cmd = exec.Command("cmd", "/c", "start", "", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	// 不阻塞主流程：浏览器打开与否不影响服务运行。
	return cmd.Start()
}
