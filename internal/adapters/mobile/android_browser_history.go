package mobile

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"crypto-inspector/internal/domain/model"
)

// AndroidHistoryAttempt 记录一次 Android 浏览历史“可达性/可解析性”的尝试结果。
// 目的是把“为何拿不到数据”这件事固化为可追溯的结构化信息（用于 prechecks 展示）。
type AndroidHistoryAttempt struct {
	URI         string `json:"uri"`
	Status      string `json:"status"` // ok/empty/error
	ParsedCount int    `json:"parsed_count"`
	Error       string `json:"error,omitempty"`
}

// AndroidHistoryCollectResult 是 Android 浏览历史采集的 best-effort 输出。
type AndroidHistoryCollectResult struct {
	Visits    []model.VisitRecord     `json:"-"`
	SourceRef string                  `json:"source_ref"`
	Method    string                  `json:"method"`
	UsedURI   string                  `json:"used_uri,omitempty"`
	Attempts  []AndroidHistoryAttempt `json:"attempts,omitempty"`
}

// collectAndroidBrowserHistory 通过 ADB 在 Android 设备上尝试采集浏览历史（best effort）。
//
// 重要说明：
//   - 不做“破解/绕过/提权”，仅尝试系统允许 shell 访问的接口。
//   - 现代 Android 普遍限制浏览历史访问，因此该函数可能经常返回空结果或权限错误；
//     上层应把此类情况记录为 precheck=skipped 并告知原因。
func collectAndroidBrowserHistory(ctx context.Context, serial string) (AndroidHistoryCollectResult, error) {
	serial = strings.TrimSpace(serial)
	if serial == "" {
		return AndroidHistoryCollectResult{}, fmt.Errorf("android serial is empty")
	}

	candidates := []struct {
		URI     string
		Browser string
		Profile string
	}{
		// AOSP/旧系统：标准 Browser provider
		{URI: "content://browser/bookmarks", Browser: "android_browser", Profile: "adb_content"},
		{URI: "content://com.android.browser/bookmarks", Browser: "aosp_browser", Profile: "adb_content"},

		// 部分系统/旧版本 Chrome/Samsung Browser 可能存在兼容 provider（可能被权限拦截）
		{URI: "content://com.android.chrome.browser/bookmarks", Browser: "chrome", Profile: "adb_content"},
		{URI: "content://com.sec.android.app.sbrowser.browser/bookmarks", Browser: "samsung_browser", Profile: "adb_content"},
	}

	var attempts []AndroidHistoryAttempt
	for _, c := range candidates {
		raw, err := runCmd(ctx, "adb", "-s", serial, "shell", "content", "query", "--uri", c.URI)
		if err != nil {
			attempts = append(attempts, AndroidHistoryAttempt{
				URI:    c.URI,
				Status: "error",
				Error:  err.Error(),
			})
			continue
		}

		visits := parseAndroidContentQueryVisits(raw, c.Browser, c.Profile, 5000)
		status := "empty"
		if len(visits) > 0 {
			status = "ok"
		}
		attempts = append(attempts, AndroidHistoryAttempt{
			URI:         c.URI,
			Status:      status,
			ParsedCount: len(visits),
		})

		if len(visits) > 0 {
			return AndroidHistoryCollectResult{
				Visits:    visits,
				SourceRef: "android_browser_history",
				Method:    "adb_shell_content_query",
				UsedURI:   c.URI,
				Attempts:  attempts,
			}, nil
		}
	}

	return AndroidHistoryCollectResult{
		SourceRef: "android_browser_history",
		Method:    "adb_shell_content_query",
		Attempts:  attempts,
	}, fmt.Errorf("no browser history extracted via content providers (may be unsupported or permission denied)")
}

func parseAndroidContentQueryVisits(raw, browser, profile string, limit int) []model.VisitRecord {
	// 解析策略：尽量只依赖 url= 字段（URL 不包含空格，最稳）。
	// title/date 字段在不同 ROM/浏览器里差异很大，不作为强依赖。
	s := bufio.NewScanner(strings.NewReader(raw))
	out := make([]model.VisitRecord, 0, 256)
	seen := map[string]struct{}{}

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		u := extractKVToken(line, "url")
		if u == "" {
			continue
		}
		host := urlHostname(u)
		if host == "" {
			continue
		}

		visitedAt := parseUnixTimeFromLine(line, []string{"date", "created", "visited", "time"})
		key := fmt.Sprintf("%s|%d", u, visitedAt)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		out = append(out, model.VisitRecord{
			Browser:   browser,
			Profile:   profile,
			URL:       u,
			Domain:    host,
			Title:     "",
			VisitedAt: visitedAt,
		})
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func extractKVToken(line string, key string) string {
	// content query 输出常见形态："... url=https://example.com title=..."
	// 我们只取 key= 后的“下一个空白字符之前”的内容。
	pat := key + "="
	idx := strings.Index(line, pat)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(pat):]
	if rest == "" {
		return ""
	}
	end := strings.IndexAny(rest, " \t\r\n")
	if end < 0 {
		end = len(rest)
	}
	v := strings.TrimSpace(rest[:end])
	v = strings.Trim(v, "'\"")
	return v
}

func urlHostname(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// 正常 URL
	if pu, err := url.Parse(raw); err == nil {
		if h := strings.TrimSpace(pu.Hostname()); h != "" {
			return h
		}
	}
	// 无 scheme 的兜底（例如 example.com/path）
	if pu, err := url.Parse("http://" + raw); err == nil {
		return strings.TrimSpace(pu.Hostname())
	}
	return ""
}

func parseUnixTimeFromLine(line string, keys []string) int64 {
	for _, k := range keys {
		v := extractKVToken(line, k)
		if v == "" {
			continue
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			continue
		}
		return normalizeUnixSeconds(n)
	}
	return 0
}

func normalizeUnixSeconds(v int64) int64 {
	if v <= 0 {
		return 0
	}
	// us
	if v > 1e15 {
		return v / 1e6
	}
	// ms
	if v > 1e12 {
		return v / 1e3
	}
	// sec
	return v
}
