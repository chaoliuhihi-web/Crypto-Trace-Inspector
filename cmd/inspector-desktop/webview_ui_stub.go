//go:build !darwin || !cgo

package main

import "fmt"

func newWebViewWindow(url, title string) (uiWindow, error) {
	return nil, fmt.Errorf("webview ui not supported on this build (need darwin+cgo)")
}

