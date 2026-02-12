package forensicexport

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	sqliteadapter "crypto-inspector/internal/adapters/store/sqlite"
	"crypto-inspector/internal/app"
	"crypto-inspector/internal/domain/model"
	"crypto-inspector/internal/platform/hash"
)

// ZipOptions 定义“司法导出包（ZIP）”生成参数。
//
// 设计目标（内测阶段）：
// - 尽量把案件相关的“证据快照 + 报告产物 + 规则文件 + 清单(manifest) + hash 列表”打包到一个 ZIP
// - 先满足内部流转/复核；后续再增强到更严格的司法取证格式（包含签名/时间戳/不可抵赖存证等）
type ZipOptions struct {
	CaseID string

	// DBPath 用于决定导出文件落盘目录（默认写入 db 同级目录下 exports/）。
	DBPath string

	// EvidenceRoot 用于把 snapshot_path 归一化到 ZIP 内的 evidence/ 路径。
	EvidenceRoot string

	WalletRulePath   string
	ExchangeRulePath string

	// Operator/Note 用于审计日志。
	Operator string
	Note     string

	// ExportDir 可选：显式指定导出目录。
	ExportDir string
}

type FileHashEntry struct {
	Path      string `json:"path"`       // ZIP 内路径（使用 "/" 分隔）
	SHA256    string `json:"sha256"`     // 文件内容 SHA-256
	SizeBytes int64  `json:"size_bytes"` // 原始字节数
	Kind      string `json:"kind"`       // artifact|report|rule|manifest
}

type ManifestArtifact struct {
	Artifact model.ArtifactInfo `json:"artifact"`
	ZipPath  string             `json:"zip_path"`
}

type ManifestReport struct {
	Report  model.ReportInfo `json:"report"`
	ZipPath string           `json:"zip_path"`
}

type ZipManifest struct {
	Schema      string `json:"schema"`
	GeneratedAt int64  `json:"generated_at"`

	App struct {
		Version   string `json:"version"`
		Commit    string `json:"commit"`
		BuildTime string `json:"build_time"`
	} `json:"app"`

	Case      *model.CaseOverview    `json:"case"`
	Devices   []model.CaseDevice     `json:"devices"`
	Artifacts []ManifestArtifact     `json:"artifacts"`
	Hits      []model.HitDetail      `json:"hits"`
	Prechecks []model.PrecheckResult `json:"prechecks"`
	Audits    []model.AuditLog       `json:"audits"`
	Reports   []ManifestReport       `json:"reports"`
	Files     []FileHashEntry        `json:"files"`
	Warnings  []string               `json:"warnings,omitempty"`
	Note      string                 `json:"note,omitempty"`
	Extra     map[string]any         `json:"extra,omitempty"`
	Stats     map[string]any         `json:"stats,omitempty"`
}

// ZipResult 是一次 ZIP 导出任务的摘要输出。
type ZipResult struct {
	CaseID     string   `json:"case_id"`
	ReportID   string   `json:"report_id"`
	ZipPath    string   `json:"zip_path"`
	ZipSHA256  string   `json:"zip_sha256"`
	Warnings   []string `json:"warnings,omitempty"`
	StartedAt  int64    `json:"started_at"`
	FinishedAt int64    `json:"finished_at"`
}

const (
	manifestSchemaV1 = "crypto_inspector.forensic_export_manifest.v1"
	zipGeneratorVer  = "forensic-exportzip-0.1.0"
)

// GenerateForensicZip 生成“司法导出包（ZIP）”并在 reports 表中登记为 report_type=forensic_zip。
//
// 输出 ZIP 内容（v1）：
// - manifest.json：案件/证据/命中/审计/报告的结构化清单
// - hashes.sha256：ZIP 内各文件（除自身）sha256 列表（sha256sum 兼容格式）
// - evidence/..：证据快照文件（原始 snapshot JSON）
// - reports/..：报告产物文件（internal_json/forensic_pdf 等，不包含 forensic_zip 以避免递归）
// - rules/..：规则文件（wallet/exchange）
func GenerateForensicZip(ctx context.Context, store *sqliteadapter.Store, opts ZipOptions) (*ZipResult, error) {
	startedAt := time.Now().Unix()

	caseID := strings.TrimSpace(opts.CaseID)
	if caseID == "" {
		return nil, fmt.Errorf("case_id is required")
	}

	dbPath := strings.TrimSpace(opts.DBPath)
	if dbPath == "" {
		dbPath = app.DefaultConfig().DBPath
	}
	evidenceRoot := strings.TrimSpace(opts.EvidenceRoot)
	if evidenceRoot == "" {
		evidenceRoot = "data/evidence"
	}
	operator := strings.TrimSpace(opts.Operator)
	if operator == "" {
		operator = "system"
	}

	exportDir := strings.TrimSpace(opts.ExportDir)
	if exportDir == "" {
		// 默认写到 db 同级目录（通常是 data/exports）。
		exportDir = filepath.Join(filepath.Dir(dbPath), "exports")
	}
	if err := os.MkdirAll(exportDir, 0o755); err != nil {
		return nil, fmt.Errorf("create export dir: %w", err)
	}

	overview, err := store.GetCaseOverview(ctx, caseID)
	if err != nil {
		return nil, err
	}
	if overview == nil {
		return nil, fmt.Errorf("case not found: %s", caseID)
	}

	// --- 拉取案件数据（全部用于 manifest；文件内容只打包快照/报告/规则） ---
	devices, err := store.ListCaseDevices(ctx, caseID)
	if err != nil {
		return nil, err
	}
	artifacts, err := store.ListArtifactsByCase(ctx, caseID)
	if err != nil {
		return nil, err
	}
	hits, err := store.ListCaseHitDetails(ctx, caseID, "")
	if err != nil {
		return nil, err
	}
	prechecks, err := store.ListPrecheckResults(ctx, caseID)
	if err != nil {
		return nil, err
	}
	audits, err := store.ListAuditLogs(ctx, caseID, 5000)
	if err != nil {
		return nil, err
	}
	allReports, err := store.ListReportsByCase(ctx, caseID)
	if err != nil {
		return nil, err
	}

	// --- 组织需要打进 ZIP 的磁盘文件清单 ---
	type includeSpec struct {
		SrcPath string
		ZipPath string
		Kind    string
	}

	var warnings []string
	var includes []includeSpec

	// evidence snapshots
	evidenceBaseAbs := mustAbs(evidenceRoot)
	manifestArtifacts := make([]ManifestArtifact, 0, len(artifacts))
	for _, a := range artifacts {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		src := strings.TrimSpace(a.SnapshotPath)
		if src == "" {
			warnings = append(warnings, fmt.Sprintf("artifact %s snapshot_path empty", a.ArtifactID))
			continue
		}
		rel := safeRel(evidenceBaseAbs, mustAbs(src))
		if rel == "" {
			// 兜底：尽量保证 ZIP 内路径稳定且不包含本机绝对路径。
			rel = filepath.Join(a.DeviceID, filepath.Base(src))
		}
		zipPath := filepath.ToSlash(filepath.Join("evidence", rel))
		includes = append(includes, includeSpec{
			SrcPath: src,
			ZipPath: zipPath,
			Kind:    "artifact",
		})
		manifestArtifacts = append(manifestArtifacts, ManifestArtifact{
			Artifact: a,
			ZipPath:  zipPath,
		})
	}

	// reports (skip forensic_zip itself to avoid "zip in zip" recursion)
	reportsBaseAbs := mustAbs(filepath.Join(filepath.Dir(dbPath), "reports"))
	manifestReports := make([]ManifestReport, 0, len(allReports))
	for _, r := range allReports {
		if strings.TrimSpace(r.ReportType) == "forensic_zip" {
			continue
		}
		src := strings.TrimSpace(r.FilePath)
		if src == "" {
			continue
		}
		rel := safeRel(reportsBaseAbs, mustAbs(src))
		if rel == "" {
			rel = filepath.Base(src)
		}
		zipPath := filepath.ToSlash(filepath.Join("reports", rel))
		includes = append(includes, includeSpec{
			SrcPath: src,
			ZipPath: zipPath,
			Kind:    "report",
		})
		manifestReports = append(manifestReports, ManifestReport{
			Report:  r,
			ZipPath: zipPath,
		})
	}

	// rules (可追溯：把用于本次识别的规则文件一并带走)
	walletRule := strings.TrimSpace(opts.WalletRulePath)
	if walletRule == "" {
		walletRule = app.DefaultConfig().WalletRulePath
	}
	exchangeRule := strings.TrimSpace(opts.ExchangeRulePath)
	if exchangeRule == "" {
		exchangeRule = app.DefaultConfig().ExchangeRulePath
	}
	includes = append(includes, includeSpec{
		SrcPath: walletRule,
		ZipPath: filepath.ToSlash(filepath.Join("rules", filepath.Base(walletRule))),
		Kind:    "rule",
	})
	includes = append(includes, includeSpec{
		SrcPath: exchangeRule,
		ZipPath: filepath.ToSlash(filepath.Join("rules", filepath.Base(exchangeRule))),
		Kind:    "rule",
	})

	// --- 开始写 ZIP ---
	zipName := fmt.Sprintf("%s_forensic_export_%d.zip", caseID, time.Now().Unix())
	zipPath := filepath.Join(exportDir, zipName)
	f, err := os.Create(zipPath)
	if err != nil {
		return nil, fmt.Errorf("create zip: %w", err)
	}
	defer func() { _ = f.Close() }()

	zw := zip.NewWriter(f)
	defer func() { _ = zw.Close() }()

	var fileHashes []FileHashEntry

	addDiskFile := func(srcPath, zipPath, kind string) {
		if strings.TrimSpace(srcPath) == "" || strings.TrimSpace(zipPath) == "" {
			return
		}
		select {
		case <-ctx.Done():
			warnings = append(warnings, "context cancelled")
			return
		default:
		}

		sum, size, err := writeZipFileFromDisk(zw, srcPath, zipPath)
		if err != nil {
			// 内测阶段走 best-effort：缺失文件不阻断导出，但必须在 manifest 里留下痕迹。
			warnings = append(warnings, fmt.Sprintf("skip file %s -> %s: %v", srcPath, zipPath, err))
			return
		}
		fileHashes = append(fileHashes, FileHashEntry{
			Path:      zipPath,
			SHA256:    sum,
			SizeBytes: size,
			Kind:      kind,
		})
	}

	for _, it := range includes {
		addDiskFile(it.SrcPath, it.ZipPath, it.Kind)
	}

	// manifest.json（先写入，再把它的 hash 也记录进 hashes.sha256）
	manifest := ZipManifest{
		Schema:      manifestSchemaV1,
		GeneratedAt: time.Now().Unix(),
		Case:        overview,
		Devices:     devices,
		Artifacts:   manifestArtifacts,
		Hits:        hits,
		Prechecks:   prechecks,
		Audits:      audits,
		Reports:     manifestReports,
		Warnings:    warnings,
		Note:        strings.TrimSpace(opts.Note),
		Extra: map[string]any{
			"evidence_root": evidenceRoot,
		},
		Stats: map[string]any{
			"device_count":   len(devices),
			"artifact_count": len(artifacts),
			"hit_count":      len(hits),
			"precheck_count": len(prechecks),
			"audit_count":    len(audits),
			"report_count":   len(allReports),
		},
	}
	manifest.App.Version = app.Version
	manifest.App.Commit = app.Commit
	manifest.App.BuildTime = app.BuildTime

	// 排序：让 manifest 与 hashes.sha256 尽量稳定（便于对比）。
	sort.Slice(fileHashes, func(i, j int) bool { return fileHashes[i].Path < fileHashes[j].Path })
	manifest.Files = fileHashes

	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	manifestZipPath := "manifest.json"
	manifestSum, manifestSize, err := writeZipFileFromBytes(zw, manifestZipPath, manifestRaw)
	if err != nil {
		return nil, fmt.Errorf("write manifest to zip: %w", err)
	}
	fileHashes = append(fileHashes, FileHashEntry{
		Path:      manifestZipPath,
		SHA256:    manifestSum,
		SizeBytes: manifestSize,
		Kind:      "manifest",
	})

	// hashes.sha256（sha256sum 兼容格式，默认不包含自身）
	sort.Slice(fileHashes, func(i, j int) bool { return fileHashes[i].Path < fileHashes[j].Path })
	hashLines := make([]string, 0, len(fileHashes)+4)
	hashLines = append(hashLines, "# crypto-inspector forensic export hash list")
	hashLines = append(hashLines, fmt.Sprintf("# generated_at=%d", time.Now().Unix()))
	hashLines = append(hashLines, "# format: <sha256><two spaces><path>")
	for _, fh := range fileHashes {
		hashLines = append(hashLines, fmt.Sprintf("%s  %s", fh.SHA256, fh.Path))
	}
	hashLines = append(hashLines, "")
	hashRaw := []byte(strings.Join(hashLines, "\n"))
	if _, _, err := writeZipFileFromBytes(zw, "hashes.sha256", hashRaw); err != nil {
		return nil, fmt.Errorf("write hashes.sha256 to zip: %w", err)
	}

	// flush/close zip
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("close zip writer: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close zip file: %w", err)
	}

	zipSum, _, err := hash.File(zipPath)
	if err != nil {
		return nil, fmt.Errorf("hash zip: %w", err)
	}

	// 入库登记（reports 表）+ 审计留痕（audit_logs）
	reportID, err := store.SaveReport(ctx, caseID, "forensic_zip", zipPath, zipSum, zipGeneratorVer, "ready")
	if err != nil {
		return nil, err
	}
	_ = store.AppendAudit(ctx, caseID, "", "export", "forensic_zip", "success", operator, "forensicexport.GenerateForensicZip", map[string]any{
		"zip_path":   zipPath,
		"zip_sha256": zipSum,
		"warnings":   warnings,
	})

	return &ZipResult{
		CaseID:     caseID,
		ReportID:   reportID,
		ZipPath:    zipPath,
		ZipSHA256:  zipSum,
		Warnings:   warnings,
		StartedAt:  startedAt,
		FinishedAt: time.Now().Unix(),
	}, nil
}

func mustAbs(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return abs
}

// safeRel 返回 target 相对 base 的相对路径；如果无法计算（不同盘符/不在 base 下）则返回空字符串。
func safeRel(baseAbs, targetAbs string) string {
	if baseAbs == "" || targetAbs == "" {
		return ""
	}
	rel, err := filepath.Rel(baseAbs, targetAbs)
	if err != nil {
		return ""
	}
	rel = filepath.Clean(rel)
	if rel == "." || strings.HasPrefix(rel, "..") || strings.HasPrefix(rel, string(filepath.Separator)+"..") {
		return ""
	}
	return rel
}

func writeZipFileFromDisk(zw *zip.Writer, srcPath, zipPath string) (sum string, size int64, err error) {
	fi, err := os.Stat(srcPath)
	if err != nil {
		return "", 0, err
	}
	if fi.IsDir() {
		return "", 0, fmt.Errorf("is a directory")
	}

	hdr, err := zip.FileInfoHeader(fi)
	if err != nil {
		return "", 0, err
	}
	hdr.Name = zipPath
	hdr.Method = zip.Deflate

	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return "", 0, err
	}

	f, err := os.Open(srcPath)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	hasher := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, hasher), f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), n, nil
}

func writeZipFileFromBytes(zw *zip.Writer, zipPath string, b []byte) (sum string, size int64, err error) {
	hdr := &zip.FileHeader{
		Name:     zipPath,
		Method:   zip.Deflate,
		Modified: time.Now(),
	}
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return "", 0, err
	}
	hasher := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, hasher), bytes.NewReader(b))
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), n, nil
}
