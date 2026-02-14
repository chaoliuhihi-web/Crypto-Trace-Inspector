//go:build darwin && cgo

package main

import (
	"fmt"

	webview "github.com/webview/webview_go"
)

// newWebViewWindow 创建一个内嵌 WebView 窗口，用于替代“打开系统浏览器”的体验。
//
// 说明：
// - 仅在 macOS 且启用 CGO 时可用（依赖系统 WebKit）
// - 该窗口只负责展示 UI；后端服务仍由 inspector-desktop 内部启动并监听本地端口
func newWebViewWindow(url, title string) (uiWindow, error) {
	if url == "" {
		return nil, fmt.Errorf("webview url is empty")
	}
	w := webview.New(false)
	w.SetTitle(title)
	// 初始窗口尺寸：偏桌面工作台，避免过窄导致表格不可读
	w.SetSize(1280, 820, webview.HintNone)
	w.Navigate(url)
	return w, nil
}

