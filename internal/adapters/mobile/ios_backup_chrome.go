package mobile

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"crypto-inspector/internal/domain/model"

	_ "modernc.org/sqlite"
)

// extractIOSChromeHistoryFromBackup 从 iOS “未加密/可读”备份中提取 Chrome 浏览历史（best effort）。
//
// 说明：
// - Chrome 在 iOS 备份中的路径/表结构可能随版本变化，这里用“候选路径 + 常见 Chrome History 表”的方式做 best effort。
// - 不做任何破解/绕过：只有在备份目录已可读时才解析。
func extractIOSChromeHistoryFromBackup(ctx context.Context, backupRoot string) ([]model.VisitRecord, error) {
	backupRoot = strings.TrimSpace(backupRoot)
	if backupRoot == "" {
		return nil, fmt.Errorf("backup_root is empty")
	}

	manifestPath := filepath.Join(backupRoot, "Manifest.db")
	if _, err := os.Stat(manifestPath); err != nil {
		return nil, fmt.Errorf("manifest db not found: %w", err)
	}

	// iOS Chrome 常见候选路径（不同版本/渠道可能略有差异）。
	candidates := []string{
		"Library/Application Support/Google/Chrome/Default/History",
		"Library/Application Support/Google/Chrome/Default/History.db",
		"Library/Application Support/Google/Chrome/Default/History.sqlite",
	}

	var lastErr error
	for _, rel := range candidates {
		fileID, domain, err := findFileIDInManifest(ctx, manifestPath, rel)
		if err != nil {
			// Manifest 没有该文件：继续尝试下一个候选
			if strings.Contains(err.Error(), "manifest missing file:") {
				lastErr = err
				continue
			}
			return nil, err
		}

		historyPath := locateBackupFile(backupRoot, fileID)
		if historyPath == "" {
			lastErr = fmt.Errorf("chrome history file not found in backup: file_id=%s domain=%s rel=%s", fileID, domain, rel)
			continue
		}

		visits, err := readChromeHistoryDB(ctx, historyPath)
		if err != nil {
			lastErr = err
			continue
		}
		return visits, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("chrome history not found in manifest")
	}
	return nil, lastErr
}

func readChromeHistoryDB(ctx context.Context, historyDBPath string) ([]model.VisitRecord, error) {
	db, err := sql.Open("sqlite", historyDBPath)
	if err != nil {
		return nil, fmt.Errorf("open chrome history db: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	// Chrome History：urls + visits（与桌面 Chrome 类似）。
	rows, err := db.QueryContext(ctx, `
		SELECT
			u.url,
			COALESCE(u.title, ''),
			v.visit_time
		FROM urls u
		JOIN visits v ON v.url = u.id
		ORDER BY v.visit_time DESC
		LIMIT 5000
	`)
	if err != nil {
		return nil, fmt.Errorf("query chrome history: %w", err)
	}
	defer rows.Close()

	out := make([]model.VisitRecord, 0, 1024)
	for rows.Next() {
		var u string
		var title string
		var vt any
		if err := rows.Scan(&u, &title, &vt); err != nil {
			return nil, fmt.Errorf("scan chrome history: %w", err)
		}
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		host := ""
		if pu, err := url.Parse(u); err == nil {
			host = strings.TrimSpace(pu.Hostname())
		}
		if host == "" {
			continue
		}

		vtNum, ok := anyToFloat64(vt)
		visitedAt := int64(0)
		if ok && vtNum > 0 {
			visitedAt = chromeVisitTimeToUnix(vtNum)
		}

		out = append(out, model.VisitRecord{
			Browser:   "chrome",
			Profile:   "ios_backup",
			URL:       u,
			Domain:    host,
			Title:     strings.TrimSpace(title),
			VisitedAt: visitedAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate chrome history: %w", err)
	}
	return out, nil
}

func chromeVisitTimeToUnix(v float64) int64 {
	// Chrome/WebKit time on desktop:
	// - microseconds since 1601-01-01 00:00:00 UTC
	// 参考 delta：1601 -> 1970
	const chromeEpochDelta = 11644473600.0

	sec := v
	// 量级兜底：部分实现可能是 ms/us/s
	if sec > 1e14 {
		sec = sec / 1e6
	} else if sec > 1e12 {
		sec = sec / 1e3
	}

	// 理论上应为：unix = chrome_seconds - delta
	return int64(sec - chromeEpochDelta)
}
