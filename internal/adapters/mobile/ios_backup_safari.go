package mobile

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"crypto-inspector/internal/domain/model"

	_ "modernc.org/sqlite"
)

// extractIOSSafariHistoryFromBackup 从 iOS “未加密/可读”备份中提取 Safari 浏览历史（best effort）。
//
// 数据来源（iTunes backup 结构）：
// - Manifest.db：记录 (domain, relativePath) -> fileID 的映射
// - 实际文件通常存放为：<backupRoot>/<fileID>（有的备份工具也会用 <backupRoot>/<fileID[:2]>/<fileID>）
//
// 重要说明：
// - iOS 备份是否能拿到历史，取决于：设备信任配对、备份授权、是否启用备份加密、以及工具链能力。
// - 本函数不做“破解/绕过”，只在备份已可读的前提下解析。
func extractIOSSafariHistoryFromBackup(ctx context.Context, backupRoot string) ([]model.VisitRecord, error) {
	backupRoot = strings.TrimSpace(backupRoot)
	if backupRoot == "" {
		return nil, fmt.Errorf("backup_root is empty")
	}

	manifestPath := filepath.Join(backupRoot, "Manifest.db")
	if _, err := os.Stat(manifestPath); err != nil {
		return nil, fmt.Errorf("manifest db not found: %w", err)
	}

	fileID, domain, err := findFileIDInManifest(ctx, manifestPath, "Library/Safari/History.db")
	if err != nil {
		return nil, err
	}

	historyPath := locateBackupFile(backupRoot, fileID)
	if historyPath == "" {
		return nil, fmt.Errorf("history db file not found in backup: file_id=%s domain=%s", fileID, domain)
	}

	return readSafariHistoryDB(ctx, historyPath)
}

func findFileIDInManifest(ctx context.Context, manifestPath string, relativePath string) (fileID string, domain string, err error) {
	db, err := sql.Open("sqlite", manifestPath)
	if err != nil {
		return "", "", fmt.Errorf("open manifest db: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	// 兜底策略：不强依赖 domain，先按 relativePath 定位。
	row := db.QueryRowContext(ctx, `
		SELECT fileID, domain
		FROM Files
		WHERE relativePath = ?
		ORDER BY domain ASC
		LIMIT 1
	`, relativePath)
	if err := row.Scan(&fileID, &domain); err != nil {
		if err == sql.ErrNoRows {
			return "", "", fmt.Errorf("manifest missing file: %s", relativePath)
		}
		return "", "", fmt.Errorf("query manifest: %w", err)
	}
	fileID = strings.TrimSpace(fileID)
	domain = strings.TrimSpace(domain)
	if fileID == "" {
		return "", "", fmt.Errorf("manifest returned empty file_id for %s", relativePath)
	}
	return fileID, domain, nil
}

func locateBackupFile(backupRoot, fileID string) string {
	fileID = strings.TrimSpace(fileID)
	if fileID == "" {
		return ""
	}

	// 常见形态：<backupRoot>/<fileID>
	p1 := filepath.Join(backupRoot, fileID)
	if st, err := os.Stat(p1); err == nil && !st.IsDir() {
		return p1
	}

	// 部分工具会按前两位分目录：<backupRoot>/<fileID[:2]>/<fileID>
	if len(fileID) >= 2 {
		p2 := filepath.Join(backupRoot, fileID[:2], fileID)
		if st, err := os.Stat(p2); err == nil && !st.IsDir() {
			return p2
		}
	}
	return ""
}

func readSafariHistoryDB(ctx context.Context, historyDBPath string) ([]model.VisitRecord, error) {
	db, err := sql.Open("sqlite", historyDBPath)
	if err != nil {
		return nil, fmt.Errorf("open history db: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	// Safari History：history_items + history_visits
	// 注意：不同 iOS 版本表结构可能略有差异；这里先覆盖常见字段。
	rows, err := db.QueryContext(ctx, `
		SELECT
			i.url,
			COALESCE(i.title, ''),
			v.visit_time
		FROM history_items i
		JOIN history_visits v ON v.history_item = i.id
		ORDER BY v.visit_time DESC
		LIMIT 5000
	`)
	if err != nil {
		return nil, fmt.Errorf("query safari history: %w", err)
	}
	defer rows.Close()

	out := make([]model.VisitRecord, 0, 1024)
	for rows.Next() {
		var u string
		var title string
		var vt any
		if err := rows.Scan(&u, &title, &vt); err != nil {
			return nil, fmt.Errorf("scan safari history: %w", err)
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
			visitedAt = safariVisitTimeToUnix(vtNum)
		}

		out = append(out, model.VisitRecord{
			Browser:   "safari",
			Profile:   "ios_backup",
			URL:       u,
			Domain:    host,
			Title:     strings.TrimSpace(title),
			VisitedAt: visitedAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate safari history: %w", err)
	}
	return out, nil
}

func anyToFloat64(v any) (float64, bool) {
	switch x := v.(type) {
	case nil:
		return 0, false
	case float64:
		return x, true
	case int64:
		return float64(x), true
	case []byte:
		s := strings.TrimSpace(string(x))
		if s == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(s, 64)
		return f, err == nil
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(s, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func safariVisitTimeToUnix(v float64) int64 {
	// Apple "Mac Absolute Time" epoch: 2001-01-01 00:00:00 UTC
	const macEpochDelta = 978307200.0

	sec := v
	// 一些实现可能把 visit_time 存成 ms/us，这里做一个简单的量级兜底。
	if sec > 1e12 {
		sec = sec / 1e6
	} else if sec > 1e10 {
		sec = sec / 1e3
	}

	return int64(sec + macEpochDelta)
}
