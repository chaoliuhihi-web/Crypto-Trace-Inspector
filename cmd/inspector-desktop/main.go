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
	"strings"
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
// - 自动打开 UI（默认 browser；macOS 可选 webview 内嵌窗口）
//
// 说明：
// - 我们不引入 Wails 等“全家桶”框架，先把核心闭环做扎实；
// - 在 macOS 上提供一个可选的 WebView 模式（--ui webview），用于内测体验；
// - Windows 仍默认走打开系统浏览器（更利于跨平台交付与 CI）。
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
	uiMode := fs.String("ui", "browser", "ui mode: browser|webview|none (webview only on macOS+cgo)")
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

	// 等服务起来再打开 UI（减少“空白页/加载失败”的概率）
	if !*noOpen && strings.ToLower(strings.TrimSpace(*uiMode)) != "none" {
		_ = waitForHTTP(sigCtx, healthURL, 12*time.Second)
	}

	switch strings.ToLower(strings.TrimSpace(*uiMode)) {
	case "", "browser":
		if !*noOpen {
			_ = openBrowser(uiURL)
		}
		// 阻塞等待 server 退出（或报错）
		return <-serverErrCh
	case "webview":
		if *noOpen {
			// no-open 用于 CI/测试：既不打开浏览器，也不弹 WebView 窗口。
			return <-serverErrCh
		}
		w, err := newWebViewWindow(uiURL, "Crypto Trace Inspector")
		if err != nil {
			return err
		}
		defer w.Destroy()

		// 如果服务异常退出，尽量关闭窗口，避免“窗口卡住但服务已死”的体验。
		serverForwardCh := make(chan error, 1)
		go func() {
			err := <-serverErrCh
			serverForwardCh <- err
			w.Terminate()
		}()

		// Run 阻塞直到用户关闭窗口。
		w.Run()

		// 用户关闭窗口后，优雅退出服务（触发 http.Server.Shutdown）。
		cancel()

		// 等待服务退出（给点超时，避免异常情况下卡住）
		select {
		case err := <-serverForwardCh:
			return err
		case <-time.After(6 * time.Second):
			return nil
		}
	case "none":
		// 仅启动服务，不打开任何 UI（适合 CI 或希望手工访问 URL 的场景）。
		return <-serverErrCh
	default:
		return fmt.Errorf("invalid --ui: %s (expected browser|webview|none)", *uiMode)
	}
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

// uiWindow 是“桌面壳”的最小抽象。
//
// - browser 模式：不需要 window
// - webview 模式：需要一个可运行/可被终止的窗口
//
// 注意：webview 通常要求 Run 在 UI 线程执行；Terminate 允许后台调用。
type uiWindow interface {
	Run()
	Terminate()
	Destroy()
}
