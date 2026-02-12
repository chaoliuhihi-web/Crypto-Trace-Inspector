package forensicpdf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	sqliteadapter "crypto-inspector/internal/adapters/store/sqlite"
	"crypto-inspector/internal/domain/model"
	"crypto-inspector/internal/platform/hash"

	"github.com/phpdave11/gofpdf"
)

// 取证 PDF 报告（forensic_pdf）
//
// 设计目标（当前版本：内部试用优先）：
// - 先“能用”：输出一个可下载、可长期归档的 PDF 文件
// - 先“可追溯”：报告入库登记到 reports 表，并写入 audit_logs 留痕
// - 先“可扩展”：后续可逐步强化为司法/审计取证格式（模板、签章、页眉页脚、编号、链路摘要等）
//
// 注意：
// - PDF 属于二进制产物，不走 report?content=true 的内联预览，必须通过 /api/reports/{id}/download 获取。

type Options struct {
	CaseID   string
	DBPath   string
	Operator string
	Note     string
}

type Result struct {
	ReportID    string   `json:"report_id"`
	PDFPath     string   `json:"pdf_path"`
	PDFSHA256   string   `json:"pdf_sha256"`
	Warnings    []string `json:"warnings,omitempty"`
	GeneratedAt int64    `json:"generated_at"`
}

const pdfGeneratorVer = "forensicpdf-0.1.0"

// GenerateForensicPDF 生成“取证 PDF 报告”，并在 reports 表中登记为 report_type=forensic_pdf。
func GenerateForensicPDF(ctx context.Context, store *sqliteadapter.Store, opts Options) (*Result, error) {
	caseID := strings.TrimSpace(opts.CaseID)
	if caseID == "" {
		return nil, fmt.Errorf("case_id is required")
	}
	dbPath := strings.TrimSpace(opts.DBPath)
	if dbPath == "" {
		return nil, fmt.Errorf("db_path is required")
	}
	operator := strings.TrimSpace(opts.Operator)
	if operator == "" {
		operator = "system"
	}

	ov, err := store.GetCaseOverview(ctx, caseID)
	if err != nil {
		return nil, fmt.Errorf("get case overview: %w", err)
	}
	if ov == nil {
		return nil, fmt.Errorf("case not found: %s", caseID)
	}

	warnings := []string{}

	// 数据准备：尽量从 DB 直接取，避免依赖 internal_json 报告文件的存在与顺序。
	devices, err := store.ListCaseDevices(ctx, caseID)
	if err != nil {
		warnings = append(warnings, "list devices failed: "+err.Error())
		devices = []model.CaseDevice{}
	}
	artifacts, err := store.ListArtifactsByCase(ctx, caseID)
	if err != nil {
		warnings = append(warnings, "list artifacts failed: "+err.Error())
		artifacts = []model.ArtifactInfo{}
	}
	hits, err := store.ListCaseHitDetails(ctx, caseID, "")
	if err != nil {
		warnings = append(warnings, "list hits failed: "+err.Error())
		hits = []model.HitDetail{}
	}
	prechecks, err := store.ListPrecheckResults(ctx, caseID)
	if err != nil {
		warnings = append(warnings, "list prechecks failed: "+err.Error())
		prechecks = []model.PrecheckResult{}
	}
	audits, err := store.ListAuditLogs(ctx, caseID, 5000)
	if err != nil {
		warnings = append(warnings, "list audits failed: "+err.Error())
		audits = []model.AuditLog{}
	}

	// 为了避免 PDF 过大，这里只展示部分列表（内部试用先够用）。
	const (
		maxDevices   = 100
		maxArtifacts = 200
		maxHits      = 300
		maxPrechecks = 200
	)

	deviceRows := devices
	if len(deviceRows) > maxDevices {
		deviceRows = deviceRows[:maxDevices]
	}
	artifactRows := artifacts
	if len(artifactRows) > maxArtifacts {
		artifactRows = artifactRows[:maxArtifacts]
	}
	hitRows := hits
	if len(hitRows) > maxHits {
		hitRows = hitRows[:maxHits]
	}
	precheckRows := prechecks
	if len(precheckRows) > maxPrechecks {
		precheckRows = precheckRows[:maxPrechecks]
	}

	// 统计摘要
	walletHits := 0
	exchangeHits := 0
	for _, h := range hits {
		switch strings.TrimSpace(h.HitType) {
		case string(model.HitWalletInstalled):
			walletHits++
		case string(model.HitExchangeVisited):
			exchangeHits++
		}
	}

	lastAuditHash := ""
	if len(audits) > 0 {
		lastAuditHash = audits[len(audits)-1].ChainHash
	}

	now := time.Now().Unix()
	reportDir := filepath.Join(filepath.Dir(dbPath), "reports")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir reports: %w", err)
	}
	pdfPath := filepath.Join(reportDir, fmt.Sprintf("%s_forensic_%d.pdf", caseID, now))

	pdf, utf8OK, err := buildPDF(*ov, deviceRows, artifactRows, hitRows, precheckRows, operator, opts.Note, walletHits, exchangeHits, lastAuditHash, warnings, now)
	if err != nil {
		return nil, err
	}
	if !utf8OK {
		// 不支持 UTF-8 字体时，为了保证“不会失败”，会把非 ASCII 字符替换为 '?'。
		// 这里将该事实写入 warnings，避免用户误解为“报告内容丢失”。
		warnings = append(warnings, "pdf utf8 font not available; non-ascii text may be replaced with '?'")
	}
	if err := pdf.OutputFileAndClose(pdfPath); err != nil {
		return nil, fmt.Errorf("write pdf: %w", err)
	}

	sum, _, err := hash.File(pdfPath)
	if err != nil {
		return nil, fmt.Errorf("sha256 pdf: %w", err)
	}

	reportID, err := store.SaveReport(ctx, caseID, "forensic_pdf", pdfPath, sum, pdfGeneratorVer, "ready")
	if err != nil {
		return nil, fmt.Errorf("save report: %w", err)
	}

	// 审计留痕：export/forensic_pdf
	_ = store.AppendAudit(ctx, caseID, "", "export", "forensic_pdf", "success", operator, "forensicpdf.GenerateForensicPDF", map[string]any{
		"pdf":            pdfPath,
		"pdf_sha256":     sum,
		"device_count":   ov.DeviceCount,
		"artifact_count": ov.ArtifactCount,
		"hit_count":      ov.HitCount,
		"report_count":   ov.ReportCount,
		"note":           strings.TrimSpace(opts.Note),
		"warnings":       warnings,
	})

	return &Result{
		ReportID:    reportID,
		PDFPath:     pdfPath,
		PDFSHA256:   sum,
		Warnings:    warnings,
		GeneratedAt: now,
	}, nil
}

func buildPDF(
	ov model.CaseOverview,
	devices []model.CaseDevice,
	artifacts []model.ArtifactInfo,
	hits []model.HitDetail,
	prechecks []model.PrecheckResult,
	operator string,
	note string,
	walletHits int,
	exchangeHits int,
	lastAuditHash string,
	warnings []string,
	generatedAt int64,
) (*gofpdf.Fpdf, bool, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(14, 14, 14)
	pdf.SetAutoPageBreak(true, 14)
	pdf.SetTitle("Crypto Trace Inspector - Forensic Report", false)

	fontFamily, utf8OK := initPDFUnicodeFont(pdf)

	pdf.AddPage()

	// 标题
	pdf.SetFont(fontFamily, "B", 16)
	pdf.CellFormat(0, 9, "Crypto Trace Inspector - Forensic PDF Report", "", 1, "L", false, 0, "")

	pdf.SetFont(fontFamily, "", 10)
	pdf.SetTextColor(60, 60, 60)
	pdf.CellFormat(0, 6, fmt.Sprintf("Generated at: %s", fmtTime(generatedAt)), "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 6, fmt.Sprintf("Operator: %s", safeText(operator, utf8OK)), "", 1, "L", false, 0, "")
	if strings.TrimSpace(note) != "" {
		pdf.MultiCell(0, 5, fmt.Sprintf("Note: %s", safeText(note, utf8OK)), "", "L", false)
	}
	pdf.Ln(2)

	// Overview
	sectionTitle(pdf, fontFamily, "1. Case Overview")
	kv(pdf, fontFamily, utf8OK, "Case ID", ov.CaseID)
	kv(pdf, fontFamily, utf8OK, "Case No", ov.CaseNo)
	kv(pdf, fontFamily, utf8OK, "Title", ov.Title)
	kv(pdf, fontFamily, utf8OK, "Status", ov.Status)
	kv(pdf, fontFamily, utf8OK, "Created By", ov.CreatedBy)
	kv(pdf, fontFamily, utf8OK, "Created At", fmtTime(ov.CreatedAt))
	kv(pdf, fontFamily, utf8OK, "Updated At", fmtTime(ov.UpdatedAt))
	kv(pdf, fontFamily, utf8OK, "Device Count", fmt.Sprintf("%d", ov.DeviceCount))
	kv(pdf, fontFamily, utf8OK, "Artifact Count", fmt.Sprintf("%d", ov.ArtifactCount))
	kv(pdf, fontFamily, utf8OK, "Hit Count", fmt.Sprintf("%d (wallet=%d, exchange=%d)", ov.HitCount, walletHits, exchangeHits))
	kv(pdf, fontFamily, utf8OK, "Report Count", fmt.Sprintf("%d", ov.ReportCount))
	if strings.TrimSpace(lastAuditHash) != "" {
		kv(pdf, fontFamily, utf8OK, "Audit Chain Last Hash", lastAuditHash)
	}
	pdf.Ln(2)

	// Warnings（用于把“缺数据/回退行为”显式写到 PDF）
	localWarnings := append([]string{}, warnings...)
	if !utf8OK {
		localWarnings = append(localWarnings, "pdf utf8 font not available; non-ascii text may be replaced with '?'")
	}
	if len(localWarnings) > 0 {
		sectionTitle(pdf, fontFamily, "Warnings")
		pdf.SetFont(fontFamily, "", 9)
		pdf.SetTextColor(120, 80, 0)
		for _, w := range localWarnings {
			pdf.MultiCell(0, 4.5, "- "+safeText(w, utf8OK), "", "L", false)
		}
		pdf.Ln(2)
	}

	// Devices
	sectionTitle(pdf, fontFamily, "2. Devices (Top List)")
	if len(devices) == 0 {
		pdf.SetFont(fontFamily, "", 10)
		pdf.SetTextColor(90, 90, 90)
		pdf.MultiCell(0, 5, "(empty)", "", "L", false)
	} else {
		for i, d := range devices {
			pdf.SetFont(fontFamily, "B", 11)
			pdf.SetTextColor(20, 20, 20)
			pdf.CellFormat(0, 6, fmt.Sprintf("Device #%d", i+1), "", 1, "L", false, 0, "")
			pdf.SetFont(fontFamily, "", 10)
			pdf.SetTextColor(30, 30, 30)
			kv(pdf, fontFamily, utf8OK, "Device ID", d.DeviceID)
			kv(pdf, fontFamily, utf8OK, "OS", d.OSType)
			kv(pdf, fontFamily, utf8OK, "Name", d.DeviceName)
			kv(pdf, fontFamily, utf8OK, "Identifier", d.Identifier)
			kv(pdf, fontFamily, utf8OK, "Connection", d.ConnectionType)
			kv(pdf, fontFamily, utf8OK, "Authorized", fmt.Sprintf("%v", d.Authorized))
			kv(pdf, fontFamily, utf8OK, "Auth Note", d.AuthNote)
			kv(pdf, fontFamily, utf8OK, "First Seen", fmtTime(d.FirstSeenAt))
			kv(pdf, fontFamily, utf8OK, "Last Seen", fmtTime(d.LastSeenAt))
			pdf.Ln(1)
		}
	}
	pdf.Ln(2)

	// Prechecks
	sectionTitle(pdf, fontFamily, "3. Prechecks (Top List)")
	if len(prechecks) == 0 {
		pdf.SetFont(fontFamily, "", 10)
		pdf.SetTextColor(90, 90, 90)
		pdf.MultiCell(0, 5, "(empty)", "", "L", false)
	} else {
		for _, c := range prechecks {
			line := fmt.Sprintf("[%s] %s (%s/%s) - %s",
				strings.ToUpper(string(c.Status)),
				safeText(c.CheckName, utf8OK),
				safeText(c.ScanScope, utf8OK),
				safeText(c.CheckCode, utf8OK),
				safeText(c.Message, utf8OK),
			)
			pdf.SetFont(fontFamily, "", 9)
			pdf.SetTextColor(30, 30, 30)
			pdf.MultiCell(0, 4.5, line, "", "L", false)
		}
	}
	pdf.Ln(2)

	// Hits
	sectionTitle(pdf, fontFamily, "4. Rule Hits (Top List)")
	if len(hits) == 0 {
		pdf.SetFont(fontFamily, "", 10)
		pdf.SetTextColor(90, 90, 90)
		pdf.MultiCell(0, 5, "(empty)", "", "L", false)
	} else {
		// 为了让输出更稳定：按 hit_type + rule_name + matched_value 排序。
		sort.Slice(hits, func(i, j int) bool {
			a, b := hits[i], hits[j]
			if a.HitType != b.HitType {
				return a.HitType < b.HitType
			}
			if a.RuleName != b.RuleName {
				return a.RuleName < b.RuleName
			}
			return a.MatchedValue < b.MatchedValue
		})
		for _, h := range hits {
			pdf.SetFont(fontFamily, "B", 10)
			pdf.SetTextColor(20, 20, 20)
			pdf.MultiCell(0, 5, fmt.Sprintf("%s | %s | conf=%.2f | verdict=%s",
				safeText(h.HitType, utf8OK),
				safeText(firstNonEmpty(h.RuleName, h.RuleID), utf8OK),
				h.Confidence,
				safeText(h.Verdict, utf8OK),
			), "", "L", false)
			pdf.SetFont(fontFamily, "", 9)
			pdf.SetTextColor(40, 40, 40)
			pdf.MultiCell(0, 4.5, fmt.Sprintf("matched: %s", safeText(h.MatchedValue, utf8OK)), "", "L", false)
			pdf.MultiCell(0, 4.5, fmt.Sprintf("device_id: %s", safeText(h.DeviceID, utf8OK)), "", "L", false)
			pdf.MultiCell(0, 4.5, fmt.Sprintf("first_seen: %s | last_seen: %s", fmtTime(h.FirstSeenAt), fmtTime(h.LastSeenAt)), "", "L", false)
			if len(h.ArtifactIDs) > 0 {
				ids := append([]string{}, h.ArtifactIDs...)
				sort.Strings(ids)
				pdf.MultiCell(0, 4.5, fmt.Sprintf("artifacts: %s", safeText(strings.Join(ids, ", "), utf8OK)), "", "L", false)
			}
			pdf.Ln(1)
		}
	}
	pdf.Ln(2)

	// Artifacts
	sectionTitle(pdf, fontFamily, "5. Evidence Artifacts (Top List)")
	if len(artifacts) == 0 {
		pdf.SetFont(fontFamily, "", 10)
		pdf.SetTextColor(90, 90, 90)
		pdf.MultiCell(0, 5, "(empty)", "", "L", false)
	} else {
		// artifacts 已按 collected_at DESC 排序（来自 store），这里直接输出即可。
		for _, a := range artifacts {
			pdf.SetFont(fontFamily, "B", 10)
			pdf.SetTextColor(20, 20, 20)
			pdf.MultiCell(0, 5, fmt.Sprintf("%s | %s | %s", safeText(a.ArtifactType, utf8OK), safeText(a.ArtifactID, utf8OK), fmtTime(a.CollectedAt)), "", "L", false)
			pdf.SetFont(fontFamily, "", 9)
			pdf.SetTextColor(40, 40, 40)
			if strings.TrimSpace(a.SourceRef) != "" {
				pdf.MultiCell(0, 4.5, fmt.Sprintf("source: %s", safeText(a.SourceRef, utf8OK)), "", "L", false)
			}
			pdf.MultiCell(0, 4.5, fmt.Sprintf("snapshot: %s", safeText(a.SnapshotPath, utf8OK)), "", "L", false)
			pdf.MultiCell(0, 4.5, fmt.Sprintf("sha256: %s", safeText(a.SHA256, utf8OK)), "", "L", false)
			pdf.Ln(1)
		}
	}

	// 尾注
	pdf.Ln(2)
	pdf.SetFont(fontFamily, "", 9)
	pdf.SetTextColor(90, 90, 90)
	pdf.MultiCell(0, 4.5, "Note: This PDF is an internal-forensics artifact. For full evidence chain, use the Forensic ZIP export (manifest.json + hashes.sha256).", "", "L", false)

	return pdf, utf8OK, nil
}

func sectionTitle(pdf *gofpdf.Fpdf, fontFamily string, title string) {
	pdf.SetFont(fontFamily, "B", 12)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 7, title, "", 1, "L", false, 0, "")
	pdf.SetDrawColor(200, 200, 200)
	pdf.Line(pdf.GetX(), pdf.GetY(), 200, pdf.GetY())
	pdf.Ln(2)
}

func kv(pdf *gofpdf.Fpdf, fontFamily string, utf8OK bool, key string, value string) {
	if strings.TrimSpace(value) == "" {
		value = "-"
	}
	pdf.SetFont(fontFamily, "B", 10)
	pdf.SetTextColor(30, 30, 30)
	pdf.CellFormat(36, 5.2, key+":", "", 0, "L", false, 0, "")
	pdf.SetFont(fontFamily, "", 10)
	pdf.SetTextColor(20, 20, 20)
	pdf.MultiCell(0, 5.2, safeText(value, utf8OK), "", "L", false)
}

func fmtTime(ts int64) string {
	if ts <= 0 {
		return "-"
	}
	return time.Unix(ts, 0).Format("2006-01-02 15:04:05")
}

func safeText(s string, utf8OK bool) string {
	// gofpdf 的内置字体对 ASCII/Latin 表现最好；
	// 如果未成功加载 UTF-8 字体，则把非 ASCII 字符替换为 '?'，确保 PDF 一定能生成（内部试用优先）。
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.TrimSpace(s)
	if utf8OK {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= 32 && r <= 126 {
			b.WriteRune(r)
		} else {
			b.WriteRune('?')
		}
	}
	return b.String()
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// initPDFUnicodeFont 尝试加载 UTF-8 字体（TrueType），以支持中文等非 ASCII 字符。
//
// 规则：
// 1) 如果设置了环境变量 CRYPTO_INSPECTOR_PDF_FONT，优先使用该文件路径。
// 2) 否则按常见系统字体路径探测（macOS/Windows/Linux）。
// 3) 加载失败则回退到核心字体（Helvetica），并通过 safeText() 兜底替换非 ASCII 字符。
func initPDFUnicodeFont(pdf *gofpdf.Fpdf) (family string, utf8OK bool) {
	const familyName = "unicode"
	candidates := []string{}

	if v := strings.TrimSpace(os.Getenv("CRYPTO_INSPECTOR_PDF_FONT")); v != "" {
		candidates = append(candidates, v)
	}

	switch runtime.GOOS {
	case "darwin":
		candidates = append(candidates,
			"/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
			"/System/Library/Fonts/Supplemental/AppleMyungjo.ttf",
			"/System/Library/Fonts/Supplemental/AppleGothic.ttf",
			"/System/Library/Fonts/Hiragino Sans GB.ttc",
			"/System/Library/Fonts/PingFang.ttc",
		)
	case "windows":
		candidates = append(candidates,
			`C:\Windows\Fonts\arialuni.ttf`,
			`C:\Windows\Fonts\simhei.ttf`,
			`C:\Windows\Fonts\simsun.ttc`,
			`C:\Windows\Fonts\msyh.ttc`,
		)
	default:
		// Linux (best effort)
		candidates = append(candidates,
			"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
			"/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
			"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
			"/usr/share/fonts/truetype/arphic/uming.ttc",
		)
	}

	for _, p := range candidates {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			continue
		}

		// 即使只有一个字体文件，这里也注册 B 样式，避免 SetFont(...,"B",...) 报错。
		pdf.AddUTF8Font(familyName, "", p)
		if pdf.Err() {
			pdf.ClearError()
			continue
		}
		pdf.AddUTF8Font(familyName, "B", p)
		if pdf.Err() {
			// bold 失败也不致命：清错后仍可用 regular
			pdf.ClearError()
		}
		return familyName, true
	}

	return "Helvetica", false
}
