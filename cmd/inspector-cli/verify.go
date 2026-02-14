package main

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	sqliteadapter "crypto-inspector/internal/adapters/store/sqlite"
	"crypto-inspector/internal/app"
	"crypto-inspector/internal/domain/model"
	"crypto-inspector/internal/platform/hash"
	"crypto-inspector/internal/services/auditverify"

	_ "modernc.org/sqlite"
)

// runVerify 是 verify 子命令路由：
// - verify forensic-zip：校验司法导出包 ZIP 内的 hashes.sha256
// - verify artifacts：复核 artifacts.snapshot_path 文件哈希（与入库 sha256 对比）
func runVerify(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printVerifyUsage()
		return nil
	}

	switch args[0] {
	case "forensic-zip":
		return runVerifyForensicZip(ctx, args[1:])
	case "artifacts":
		return runVerifyArtifacts(ctx, args[1:])
	case "audits":
		return runVerifyAudits(ctx, args[1:])
	default:
		printVerifyUsage()
		return fmt.Errorf("unknown verify command: %s", args[0])
	}
}

func printVerifyUsage() {
	fmt.Println("Usage:")
	fmt.Println("  inspector-cli verify forensic-zip --zip PATH_TO_ZIP")
	fmt.Println("  inspector-cli verify artifacts --case-id CASE_ID [--db data/inspector.db] [--artifact-id ART_ID]")
	fmt.Println("  inspector-cli verify audits --case-id CASE_ID [--db data/inspector.db] [--limit 5000]")
}

type zipVerifyItem struct {
	Path       string
	Expected   string
	Actual     string
	Status     string // ok|missing|mismatch|error
	ErrMessage string
}

func runVerifyForensicZip(ctx context.Context, args []string) error {
	_ = ctx // 当前实现不需要 ctx，预留用于后续添加超时/取消。

	fs := flag.NewFlagSet("verify forensic-zip", flag.ContinueOnError)
	zipPath := fs.String("zip", "", "path to forensic zip (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*zipPath) == "" {
		return fmt.Errorf("--zip is required")
	}

	total, okCount, failedCount, items, auditRes, err := verifyForensicZip(*zipPath)
	if err != nil {
		return err
	}

	fmt.Println("forensic zip verify completed")
	fmt.Printf("zip=%s\n", *zipPath)
	fmt.Printf("files_total=%d ok=%d failed=%d\n", total, okCount, failedCount)

	if failedCount > 0 {
		for _, it := range items {
			if it.Status == "ok" {
				continue
			}
			if it.ErrMessage != "" {
				fmt.Printf("FAIL %s status=%s expected=%s actual=%s error=%s\n", it.Path, it.Status, it.Expected, it.Actual, it.ErrMessage)
			} else {
				fmt.Printf("FAIL %s status=%s expected=%s actual=%s\n", it.Path, it.Status, it.Expected, it.Actual)
			}
		}
		return fmt.Errorf("forensic zip verify failed: %d files mismatch/missing", failedCount)
	}

	if auditRes != nil {
		fmt.Printf("audit_chain_total=%d failed=%d prev_hash_failed=%d chain_hash_failed=%d\n", auditRes.Total, auditRes.Failed, auditRes.PrevHashFailed, auditRes.ChainHashFailed)
		if !auditRes.OK {
			for _, f := range auditRes.Failures {
				fmt.Printf("FAIL audit_chain index=%d event_id=%s message=%s expected_prev=%s actual_prev=%s expected_hash=%s actual_hash=%s\n",
					f.Index, f.EventID, f.Message, f.ExpectedPrevHash, f.ActualPrevHash, f.ExpectedChainHash, f.ActualChainHash,
				)
			}
			return fmt.Errorf("forensic zip verify failed: audit chain mismatch")
		}
	}
	return nil
}

func verifyForensicZip(path string) (total int, okCount int, failedCount int, items []zipVerifyItem, auditRes *auditverify.Result, err error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	// 建立 zip 内文件索引：name -> *zip.File
	files := make(map[string]*zip.File, len(r.File))
	for _, f := range r.File {
		files[f.Name] = f
	}

	hashListFile, ok := files["hashes.sha256"]
	if !ok {
		return 0, 0, 0, nil, nil, fmt.Errorf("hashes.sha256 not found in zip")
	}
	rc, err := hashListFile.Open()
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("open hashes.sha256: %w", err)
	}
	defer rc.Close()

	expected := make([]struct {
		SHA  string
		Path string
	}, 0, 256)

	sc := bufio.NewScanner(rc)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// hashes.sha256 中允许包含注释行（以 "#" 开头）
		if strings.HasPrefix(line, "#") {
			continue
		}
		// sha256sum 格式：<sha256><two spaces><path>
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		sha := strings.TrimSpace(parts[0])
		p := strings.TrimSpace(strings.Join(parts[1:], " "))
		if sha == "" || p == "" {
			continue
		}
		// 防御：sha256 必须是 64 位 hex（否则跳过，避免把异常行当成校验项）
		if len(sha) != 64 {
			continue
		}
		expected = append(expected, struct {
			SHA  string
			Path string
		}{SHA: sha, Path: p})
	}
	if err := sc.Err(); err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("read hashes.sha256: %w", err)
	}

	items = make([]zipVerifyItem, 0, len(expected))
	for _, e := range expected {
		total++
		f, ok := files[e.Path]
		if !ok {
			failedCount++
			items = append(items, zipVerifyItem{
				Path:     e.Path,
				Expected: e.SHA,
				Actual:   "",
				Status:   "missing",
			})
			continue
		}

		sum, err := sha256OfZipFile(f)
		if err != nil {
			failedCount++
			items = append(items, zipVerifyItem{
				Path:       e.Path,
				Expected:   e.SHA,
				Actual:     "",
				Status:     "error",
				ErrMessage: err.Error(),
			})
			continue
		}

		if strings.EqualFold(strings.TrimSpace(sum), strings.TrimSpace(e.SHA)) {
			okCount++
			items = append(items, zipVerifyItem{
				Path:     e.Path,
				Expected: e.SHA,
				Actual:   sum,
				Status:   "ok",
			})
			continue
		}

		failedCount++
		items = append(items, zipVerifyItem{
			Path:     e.Path,
			Expected: e.SHA,
			Actual:   sum,
			Status:   "mismatch",
		})
	}

	// 额外强校验：manifest.json 内 audit 链（best effort；不影响 hashes.sha256 的校验结果统计）。
	if mf, ok := files["manifest.json"]; ok {
		data, readErr := readZipFileAll(mf)
		if readErr == nil {
			var payload struct {
				Audits []model.AuditLog `json:"audits"`
			}
			if err := json.Unmarshal(data, &payload); err == nil {
				r := auditverify.VerifyAuditLogs(payload.Audits)
				auditRes = &r
			}
		}
	}

	return total, okCount, failedCount, items, auditRes, nil
}

func sha256OfZipFile(f *zip.File) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()

	h := sha256.New()
	if _, err := io.Copy(h, rc); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readZipFileAll(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

type artifactVerifyItem struct {
	ArtifactID     string
	SnapshotPath   string
	ExpectedSHA256 string
	ActualSHA256   string
	ExpectedSize   int64
	ActualSize     int64
	Status         string // ok|missing|mismatch|error
	Error          string
}

func runVerifyArtifacts(ctx context.Context, args []string) error {
	cfg := app.DefaultConfig()

	fs := flag.NewFlagSet("verify artifacts", flag.ContinueOnError)
	dbPath := fs.String("db", cfg.DBPath, "sqlite database path")
	caseID := fs.String("case-id", "", "case id (required)")
	artifactID := fs.String("artifact-id", "", "verify a single artifact id (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*caseID) == "" {
		return fmt.Errorf("--case-id is required")
	}

	if err := os.MkdirAll(filepathDir(*dbPath), 0o755); err != nil {
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

	// 取需要校验的 artifact 列表
	var targets []struct {
		ID           string
		SnapshotPath string
		SHA256       string
		SizeBytes    int64
	}
	if strings.TrimSpace(*artifactID) != "" {
		info, err := store.GetArtifactInfo(ctx, strings.TrimSpace(*artifactID))
		if err != nil {
			return err
		}
		if info == nil {
			return fmt.Errorf("artifact not found: %s", strings.TrimSpace(*artifactID))
		}
		targets = append(targets, struct {
			ID           string
			SnapshotPath string
			SHA256       string
			SizeBytes    int64
		}{
			ID:           info.ArtifactID,
			SnapshotPath: info.SnapshotPath,
			SHA256:       info.SHA256,
			SizeBytes:    info.SizeBytes,
		})
	} else {
		rows, err := store.ListArtifactsByCase(ctx, strings.TrimSpace(*caseID))
		if err != nil {
			return err
		}
		for _, r := range rows {
			targets = append(targets, struct {
				ID           string
				SnapshotPath string
				SHA256       string
				SizeBytes    int64
			}{
				ID:           r.ArtifactID,
				SnapshotPath: r.SnapshotPath,
				SHA256:       r.SHA256,
				SizeBytes:    r.SizeBytes,
			})
		}
	}

	// 逐个复算
	results := make([]artifactVerifyItem, 0, len(targets))
	okCount := 0
	failCount := 0
	for _, t := range targets {
		item := artifactVerifyItem{
			ArtifactID:     t.ID,
			SnapshotPath:   t.SnapshotPath,
			ExpectedSHA256: t.SHA256,
			ExpectedSize:   t.SizeBytes,
		}

		sum, size, err := hash.File(t.SnapshotPath)
		if err != nil {
			// 常见：文件被删除/移动；权限不足
			item.Status = "missing"
			item.Error = err.Error()
			failCount++
			results = append(results, item)
			continue
		}
		item.ActualSHA256 = sum
		item.ActualSize = size

		if !strings.EqualFold(strings.TrimSpace(sum), strings.TrimSpace(t.SHA256)) || size != t.SizeBytes {
			item.Status = "mismatch"
			failCount++
			results = append(results, item)
			continue
		}

		item.Status = "ok"
		okCount++
		results = append(results, item)
	}

	fmt.Println("artifact sha256 verify completed")
	fmt.Printf("case_id=%s total=%d ok=%d failed=%d\n", strings.TrimSpace(*caseID), len(results), okCount, failCount)
	for _, r := range results {
		if r.Status == "ok" {
			continue
		}
		if r.Error != "" {
			fmt.Printf("FAIL artifact_id=%s status=%s expected=%s actual=%s path=%s error=%s\n", r.ArtifactID, r.Status, r.ExpectedSHA256, r.ActualSHA256, r.SnapshotPath, r.Error)
		} else {
			fmt.Printf("FAIL artifact_id=%s status=%s expected=%s actual=%s path=%s\n", r.ArtifactID, r.Status, r.ExpectedSHA256, r.ActualSHA256, r.SnapshotPath)
		}
	}

	if failCount > 0 {
		return fmt.Errorf("artifact sha256 verify failed: %d items mismatch/missing", failCount)
	}
	return nil
}

func runVerifyAudits(ctx context.Context, args []string) error {
	cfg := app.DefaultConfig()

	fs := flag.NewFlagSet("verify audits", flag.ContinueOnError)
	dbPath := fs.String("db", cfg.DBPath, "sqlite database path")
	caseID := fs.String("case-id", "", "case id (required)")
	limit := fs.Int("limit", 5000, "max audit logs to verify (default 5000)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*caseID) == "" {
		return fmt.Errorf("--case-id is required")
	}

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, _ = db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`)

	store := sqliteadapter.NewStore(db)
	logs, err := store.ListAuditLogs(ctx, strings.TrimSpace(*caseID), *limit)
	if err != nil {
		return err
	}

	res := auditverify.VerifyAuditLogs(logs)
	fmt.Println("audit chain verify completed")
	fmt.Printf("case_id=%s total=%d failed=%d prev_hash_failed=%d chain_hash_failed=%d\n", *caseID, res.Total, res.Failed, res.PrevHashFailed, res.ChainHashFailed)
	if !res.OK {
		for _, f := range res.Failures {
			fmt.Printf("FAIL index=%d event_id=%s message=%s expected_prev=%s actual_prev=%s expected_hash=%s actual_hash=%s\n",
				f.Index, f.EventID, f.Message, f.ExpectedPrevHash, f.ActualPrevHash, f.ExpectedChainHash, f.ActualChainHash,
			)
		}
		return fmt.Errorf("audit chain verify failed")
	}
	return nil
}

func filepathDir(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "."
	}
	// 用最小实现避免再引入 path/filepath 在该文件顶部的 import（保持依赖集中）。
	// 这里的 dbPath 传入通常为 "data/inspector.db"，分隔符兼容即可。
	if i := strings.LastIndexAny(p, "/\\"); i > 0 {
		return p[:i]
	}
	return "."
}
