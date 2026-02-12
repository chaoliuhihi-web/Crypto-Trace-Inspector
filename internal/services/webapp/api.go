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
	case "reports":
		s.handleCaseReports(w, r, caseID)
	case "report":
		s.handleCaseReport(w, r, caseID)
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
	if includeContent {
		raw, err := os.ReadFile(report.FilePath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		out["content"] = string(raw)
		out["content_length"] = len(raw)
	}
	writeJSON(w, http.StatusOK, out)
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
