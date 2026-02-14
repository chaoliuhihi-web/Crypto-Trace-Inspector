package mobile

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestExtractIOSSafariHistoryFromBackup_OK(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()

	manifestPath := filepath.Join(root, "Manifest.db")
	createManifestDB(t, manifestPath)

	fileID := "safari_history_fileid_0001"
	insertManifestFile(t, manifestPath, fileID, "HomeDomain", "Library/Safari/History.db")

	historyPath := filepath.Join(root, fileID)
	createSafariHistoryDB(t, historyPath, []safariRow{
		{URL: "https://www.binance.com/en", Title: "Binance", VisitTime: 1000},
		{URL: "https://example.com/", Title: "Example", VisitTime: 2000},
	})

	visits, err := extractIOSSafariHistoryFromBackup(ctx, root)
	if err != nil {
		t.Fatalf("extract safari history: %v", err)
	}
	if len(visits) == 0 {
		t.Fatalf("expected visits, got 0")
	}
	if visits[0].Domain == "" || visits[0].URL == "" {
		t.Fatalf("expected domain/url, got %+v", visits[0])
	}
	// 2001 epoch delta + visit_time
	if visits[0].VisitedAt != 978307200+2000 {
		t.Fatalf("unexpected visited_at: %d", visits[0].VisitedAt)
	}
}

func TestExtractIOSSafariHistoryFromBackup_LocateSubdir(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()

	manifestPath := filepath.Join(root, "Manifest.db")
	createManifestDB(t, manifestPath)

	fileID := "aabbccddeeff00112233445566778899aabbccdd"
	insertManifestFile(t, manifestPath, fileID, "HomeDomain", "Library/Safari/History.db")

	// 按前两位分目录
	subdir := filepath.Join(root, fileID[:2])
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	historyPath := filepath.Join(subdir, fileID)
	createSafariHistoryDB(t, historyPath, []safariRow{
		{URL: "https://www.okx.com/", Title: "OKX", VisitTime: 3000},
	})

	visits, err := extractIOSSafariHistoryFromBackup(ctx, root)
	if err != nil {
		t.Fatalf("extract safari history: %v", err)
	}
	if len(visits) != 1 {
		t.Fatalf("expected 1 visit, got %d", len(visits))
	}
	if visits[0].Domain != "www.okx.com" {
		t.Fatalf("unexpected domain: %s", visits[0].Domain)
	}
}

func TestExtractIOSChromeHistoryFromBackup_OK(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()

	manifestPath := filepath.Join(root, "Manifest.db")
	createManifestDB(t, manifestPath)

	fileID := "chrome_history_fileid_0001"
	insertManifestFile(t, manifestPath, fileID, "AppDomain-com.google.chrome", "Library/Application Support/Google/Chrome/Default/History")

	historyPath := filepath.Join(root, fileID)
	unixSec := int64(1700000000)
	createChromeHistoryDB(t, historyPath, []chromeRow{
		{URL: "https://www.huobi.com/", Title: "Huobi", VisitTimeChromeMicros: (unixSec + 11644473600) * 1_000_000},
	})

	visits, err := extractIOSChromeHistoryFromBackup(ctx, root)
	if err != nil {
		t.Fatalf("extract chrome history: %v", err)
	}
	if len(visits) != 1 {
		t.Fatalf("expected 1 visit, got %d", len(visits))
	}
	if visits[0].Domain != "www.huobi.com" {
		t.Fatalf("unexpected domain: %s", visits[0].Domain)
	}
	if visits[0].VisitedAt != unixSec {
		t.Fatalf("unexpected visited_at: %d", visits[0].VisitedAt)
	}
}

type safariRow struct {
	URL       string
	Title     string
	VisitTime float64
}

type chromeRow struct {
	URL                   string
	Title                 string
	VisitTimeChromeMicros int64
}

func createManifestDB(t *testing.T, path string) {
	t.Helper()
	db := openSQLite(t, path)
	defer db.Close()

	mustExec(t, db, `CREATE TABLE IF NOT EXISTS Files(fileID TEXT, domain TEXT, relativePath TEXT)`)
}

func insertManifestFile(t *testing.T, manifestPath, fileID, domain, relativePath string) {
	t.Helper()
	db := openSQLite(t, manifestPath)
	defer db.Close()

	mustExec(t, db, `INSERT INTO Files(fileID, domain, relativePath) VALUES(?, ?, ?)`, fileID, domain, relativePath)
}

func createSafariHistoryDB(t *testing.T, path string, rows []safariRow) {
	t.Helper()
	db := openSQLite(t, path)
	defer db.Close()

	mustExec(t, db, `CREATE TABLE IF NOT EXISTS history_items(id INTEGER PRIMARY KEY, url TEXT, title TEXT)`)
	mustExec(t, db, `CREATE TABLE IF NOT EXISTS history_visits(id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL)`)

	for i, r := range rows {
		itemID := int64(i + 1)
		visitID := int64(i + 1)
		mustExec(t, db, `INSERT INTO history_items(id, url, title) VALUES(?, ?, ?)`, itemID, r.URL, r.Title)
		mustExec(t, db, `INSERT INTO history_visits(id, history_item, visit_time) VALUES(?, ?, ?)`, visitID, itemID, r.VisitTime)
	}
}

func createChromeHistoryDB(t *testing.T, path string, rows []chromeRow) {
	t.Helper()
	db := openSQLite(t, path)
	defer db.Close()

	mustExec(t, db, `CREATE TABLE IF NOT EXISTS urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT)`)
	mustExec(t, db, `CREATE TABLE IF NOT EXISTS visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)`)

	for i, r := range rows {
		urlID := int64(i + 1)
		visitID := int64(i + 1)
		mustExec(t, db, `INSERT INTO urls(id, url, title) VALUES(?, ?, ?)`, urlID, r.URL, r.Title)
		mustExec(t, db, `INSERT INTO visits(id, url, visit_time) VALUES(?, ?, ?)`, visitID, urlID, r.VisitTimeChromeMicros)
	}
}

func openSQLite(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	return db
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}
