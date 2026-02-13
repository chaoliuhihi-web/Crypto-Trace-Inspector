package webapp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"crypto-inspector/internal/domain/model"
	"crypto-inspector/internal/platform/hash"
	"crypto-inspector/internal/services/forensicexport"
	"crypto-inspector/internal/services/forensicpdf"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"service": "webapp",
		"time":    time.Now().Unix(),
	})
}

func (s *Server) handleCases(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		limit := parseInt(r.URL.Query().Get("limit"), 50)
		offset := parseInt(r.URL.Query().Get("offset"), 0)

		rows, err := s.store.ListCases(r.Context(), limit, offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"cases": rows})
	case http.MethodPost:
		// UI 侧“先建案再采集”的低门槛入口：
		// - 允许不传 case_id（服务端自动生成）
		// - case_no 可作为工单/文书编号（也可为空，内测模式不强制）
		type createCaseRequest struct {
			CaseID   string `json:"case_id,omitempty"`
			CaseNo   string `json:"case_no,omitempty"`
			Title    string `json:"title,omitempty"`
			Operator string `json:"operator,omitempty"`
			Note     string `json:"note,omitempty"`
		}

		var req createCaseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
			return
		}
		operator := strings.TrimSpace(req.Operator)
		if operator == "" {
			operator = "system"
		}
		caseID, err := s.store.EnsureCase(r.Context(),
			strings.TrimSpace(req.CaseID),
			strings.TrimSpace(req.CaseNo),
			strings.TrimSpace(req.Title),
			operator,
			strings.TrimSpace(req.Note),
		)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		ov, err := s.store.GetCaseOverview(r.Context(), caseID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"case_id":  caseID,
			"overview": ov,
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleCaseRoutes(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/cases/")
	rest = strings.Trim(rest, "/")
	if rest == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	parts := strings.Split(rest, "/")
	caseID := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch action {
	case "overview":
		s.handleCaseOverview(w, r, caseID)
	case "devices":
		s.handleCaseDevices(w, r, caseID)
	case "hits":
		s.handleCaseHits(w, r, caseID)
	case "chain":
		// /api/cases/{case_id}/chain/{action}
		//
		// - POST /api/cases/{case_id}/chain/balance
		restParts := []string{}
		if len(parts) > 2 {
			restParts = parts[2:]
		}
		s.handleCaseChain(w, r, caseID, restParts)
	case "reports":
		s.handleCaseReports(w, r, caseID)
	case "report":
		s.handleCaseReport(w, r, caseID)
	case "exports":
		// /api/cases/{case_id}/exports/{kind}
		//
		// 目前支持：
		// - POST /api/cases/{case_id}/exports/forensic-zip
		// - POST /api/cases/{case_id}/exports/forensic-pdf
		restParts := []string{}
		if len(parts) > 2 {
			restParts = parts[2:]
		}
		s.handleCaseExports(w, r, caseID, restParts)
	case "verify":
		// /api/cases/{case_id}/verify/{kind}
		//
		// - POST /api/cases/{case_id}/verify/artifacts
		restParts := []string{}
		if len(parts) > 2 {
			restParts = parts[2:]
		}
		s.handleCaseVerify(w, r, caseID, restParts)
	case "prechecks":
		s.handleCasePrechecks(w, r, caseID)
	case "audits":
		s.handleCaseAudits(w, r, caseID)
	case "artifacts":
		s.handleCaseArtifacts(w, r, caseID)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *Server) handleCaseVerify(w http.ResponseWriter, r *http.Request, caseID string, parts []string) {
	if len(parts) < 1 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	kind := strings.TrimSpace(parts[0])
	switch kind {
	case "artifacts":
		s.handleCaseVerifyArtifacts(w, r, caseID)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// handleCaseVerifyArtifacts 对案件下的证据快照进行 sha256 复核：
// - 复算 snapshot_path 文件 sha256
// - 对比入库 sha256/size_bytes
// - 输出 ok/mismatch/missing/error 明细
//
// 该接口用于内测阶段快速发现“证据目录被清理/被改动”的情况。
func (s *Server) handleCaseVerifyArtifacts(w http.ResponseWriter, r *http.Request, caseID string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	type reqBody struct {
		Operator   string `json:"operator,omitempty"`
		ArtifactID string `json:"artifact_id,omitempty"`
		Note       string `json:"note,omitempty"`
	}
	var req reqBody
	_ = json.NewDecoder(r.Body).Decode(&req)

	operator := strings.TrimSpace(req.Operator)
	if operator == "" {
		operator = "system"
	}
	artifactID := strings.TrimSpace(req.ArtifactID)

	type item struct {
		ArtifactID     string `json:"artifact_id"`
		SnapshotPath   string `json:"snapshot_path"`
		ExpectedSHA256 string `json:"expected_sha256"`
		ActualSHA256   string `json:"actual_sha256,omitempty"`
		ExpectedSize   int64  `json:"expected_size_bytes"`
		ActualSize     int64  `json:"actual_size_bytes,omitempty"`
		Status         string `json:"status"` // ok|mismatch|missing|error
		Error          string `json:"error,omitempty"`
	}

	// 构造校验目标
	var targets []model.ArtifactInfo
	if artifactID != "" {
		info, err := s.store.GetArtifactInfo(r.Context(), artifactID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if info == nil || strings.TrimSpace(info.ArtifactID) == "" {
			writeError(w, http.StatusNotFound, fmt.Errorf("artifact not found: %s", artifactID))
			return
		}
		if strings.TrimSpace(info.CaseID) != strings.TrimSpace(caseID) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("artifact %s not in case %s", artifactID, caseID))
			return
		}
		targets = append(targets, *info)
	} else {
		rows, err := s.store.ListArtifactsByCase(r.Context(), caseID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		targets = rows
	}

	out := make([]item, 0, len(targets))
	okCount := 0
	mismatchCount := 0
	missingCount := 0
	errorCount := 0
	for _, t := range targets {
		it := item{
			ArtifactID:     t.ArtifactID,
			SnapshotPath:   t.SnapshotPath,
			ExpectedSHA256: t.SHA256,
			ExpectedSize:   t.SizeBytes,
		}

		sum, size, err := hash.File(t.SnapshotPath)
		if err != nil {
			it.Status = "missing"
			it.Error = err.Error()
			missingCount++
			out = append(out, it)
			continue
		}
		it.ActualSHA256 = sum
		it.ActualSize = size
		if !strings.EqualFold(strings.TrimSpace(sum), strings.TrimSpace(t.SHA256)) || size != t.SizeBytes {
			it.Status = "mismatch"
			mismatchCount++
			out = append(out, it)
			continue
		}
		it.Status = "ok"
		okCount++
		out = append(out, it)
	}

	status := "success"
	if mismatchCount > 0 || missingCount > 0 || errorCount > 0 {
		status = "failed"
	}
	_ = s.store.AppendAudit(r.Context(), caseID, "", "verify", "artifacts_sha256", status, operator, "webapp.handleCaseVerifyArtifacts", map[string]any{
		"note":            strings.TrimSpace(req.Note),
		"total":           len(out),
		"ok":              okCount,
		"mismatch":        mismatchCount,
		"missing":         missingCount,
		"error":           errorCount,
		"single_artifact": artifactID,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             status == "success",
		"case_id":        caseID,
		"total":          len(out),
		"ok_count":       okCount,
		"mismatch_count": mismatchCount,
		"missing_count":  missingCount,
		"error_count":    errorCount,
		"results":        out,
	})
}

func (s *Server) handleCaseDevices(w http.ResponseWriter, r *http.Request, caseID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rows, err := s.store.ListCaseDevices(r.Context(), caseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": rows})
}

func (s *Server) handleCaseOverview(w http.ResponseWriter, r *http.Request, caseID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ov, err := s.store.GetCaseOverview(r.Context(), caseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if ov == nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("case not found: %s", caseID))
		return
	}
	writeJSON(w, http.StatusOK, ov)
}

func (s *Server) handleCaseHits(w http.ResponseWriter, r *http.Request, caseID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	hitType := strings.TrimSpace(r.URL.Query().Get("hit_type"))
	rows, err := s.store.ListCaseHitDetails(r.Context(), caseID, hitType)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hits": rows})
}

func (s *Server) handleCaseReports(w http.ResponseWriter, r *http.Request, caseID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rows, err := s.store.ListReportsByCase(r.Context(), caseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": rows})
}

func (s *Server) handleCaseReport(w http.ResponseWriter, r *http.Request, caseID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	reportID := strings.TrimSpace(r.URL.Query().Get("report_id"))
	includeContent := parseBool(r.URL.Query().Get("content"), true)

	var report *model.ReportInfo
	var err error
	if reportID != "" {
		report, err = s.store.GetReportByID(r.Context(), reportID)
	} else {
		report, err = s.store.GetLatestReportByCase(r.Context(), caseID)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if report == nil {
		writeJSON(w, http.StatusOK, map[string]any{"report": nil})
		return
	}

	out := map[string]any{"report": report}
	// 只有文本类报告才允许内联内容。ZIP/PDF 属于二进制产物，只能走 download。
	if includeContent && (report.ReportType == "internal_json" || report.ReportType == "internal_html") {
		raw, err := os.ReadFile(report.FilePath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		out["content"] = string(raw)
		out["content_length"] = len(raw)
		out["content_available"] = true
	} else {
		out["content_available"] = false
		if includeContent {
			out["content_omitted_reason"] = "binary_report_or_not_supported"
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleCaseExports 负责导出/取证产物生成入口（内测模式先走同步生成，后续可升级为后台任务）。
func (s *Server) handleCaseExports(w http.ResponseWriter, r *http.Request, caseID string, parts []string) {
	if len(parts) < 1 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	kind := strings.TrimSpace(parts[0])

	switch kind {
	case "forensic-zip":
		s.handleCaseExportForensicZip(w, r, caseID)
	case "forensic-pdf":
		s.handleCaseExportForensicPDF(w, r, caseID)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *Server) handleCaseExportForensicZip(w http.ResponseWriter, r *http.Request, caseID string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	type reqBody struct {
		Operator string `json:"operator,omitempty"`
		Note     string `json:"note,omitempty"`
	}
	var req reqBody
	_ = json.NewDecoder(r.Body).Decode(&req) // 允许空 body

	operator := strings.TrimSpace(req.Operator)
	if operator == "" {
		operator = "system"
	}

	res, err := forensicexport.GenerateForensicZip(r.Context(), s.store, forensicexport.ZipOptions{
		CaseID:           caseID,
		DBPath:           s.opts.DBPath,
		EvidenceRoot:     s.opts.EvidenceRoot,
		WalletRulePath:   s.opts.WalletRulePath,
		ExchangeRulePath: s.opts.ExchangeRulePath,
		Operator:         operator,
		Note:             strings.TrimSpace(req.Note),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	info, err := s.store.GetReportByID(r.Context(), res.ReportID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"case_id":    caseID,
		"report_id":  res.ReportID,
		"zip_path":   res.ZipPath,
		"zip_sha256": res.ZipSHA256,
		"warnings":   res.Warnings,
		"report":     info,
	})
}

func (s *Server) handleCaseExportForensicPDF(w http.ResponseWriter, r *http.Request, caseID string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	type reqBody struct {
		Operator string `json:"operator,omitempty"`
		Note     string `json:"note,omitempty"`
	}
	var req reqBody
	_ = json.NewDecoder(r.Body).Decode(&req) // 允许空 body

	operator := strings.TrimSpace(req.Operator)
	if operator == "" {
		operator = "system"
	}

	res, err := forensicpdf.GenerateForensicPDF(r.Context(), s.store, forensicpdf.Options{
		CaseID:   caseID,
		DBPath:   s.opts.DBPath,
		Operator: operator,
		Note:     strings.TrimSpace(req.Note),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	info, err := s.store.GetReportByID(r.Context(), res.ReportID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"case_id":    caseID,
		"report_id":  res.ReportID,
		"pdf_path":   res.PDFPath,
		"pdf_sha256": res.PDFSHA256,
		"warnings":   res.Warnings,
		"report":     info,
	})
}

func (s *Server) handleCasePrechecks(w http.ResponseWriter, r *http.Request, caseID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rows, err := s.store.ListPrecheckResults(r.Context(), caseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"prechecks": rows})
}

func (s *Server) handleCaseAudits(w http.ResponseWriter, r *http.Request, caseID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	limit := parseInt(r.URL.Query().Get("limit"), 500)
	rows, err := s.store.ListAuditLogs(r.Context(), caseID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audits": rows})
}

func (s *Server) handleCaseArtifacts(w http.ResponseWriter, r *http.Request, caseID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rows, err := s.store.ListArtifactsByCase(r.Context(), caseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"artifacts": rows})
}

func (s *Server) handleReportRoutes(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/reports/")
	rest = strings.Trim(rest, "/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	reportID := parts[0]
	action := parts[1]
	if action != "download" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	info, err := s.store.GetReportByID(r.Context(), reportID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if info == nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("report not found: %s", reportID))
		return
	}
	serveFile(w, r, info.FilePath, "report_"+reportID)
}

func (s *Server) handleArtifactRoutes(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/artifacts/")
	rest = strings.Trim(rest, "/")
	parts := strings.Split(rest, "/")
	if len(parts) < 1 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	artifactID := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch action {
	case "":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// 证据索引 + 可选内容（默认不读内容，避免大文件阻塞）
		includeContent := parseBool(r.URL.Query().Get("content"), false)
		info, err := s.store.GetArtifactInfo(r.Context(), artifactID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if info == nil {
			writeError(w, http.StatusNotFound, fmt.Errorf("artifact not found: %s", artifactID))
			return
		}
		out := map[string]any{"artifact": info}
		if includeContent {
			raw, err := os.ReadFile(info.SnapshotPath)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			out["content"] = string(raw)
			out["content_length"] = len(raw)
		}
		writeJSON(w, http.StatusOK, out)
	case "download":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		info, err := s.store.GetArtifactInfo(r.Context(), artifactID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if info == nil {
			writeError(w, http.StatusNotFound, fmt.Errorf("artifact not found: %s", artifactID))
			return
		}
		serveFile(w, r, info.SnapshotPath, "artifact_"+artifactID)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{
		"error": err.Error(),
	})
}

func parseInt(s string, def int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func parseBool(s string, def bool) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return def
	}
	switch s {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return def
	}
}
