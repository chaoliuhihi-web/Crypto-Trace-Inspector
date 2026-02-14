package webapp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"crypto-inspector/internal/platform/id"
	"crypto-inspector/internal/services/hostscan"
	"crypto-inspector/internal/services/mobilescan"
)

type jobManager struct {
	mu   sync.Mutex
	jobs map[string]*scanAllJob
}

func newJobManager() *jobManager {
	return &jobManager{jobs: make(map[string]*scanAllJob)}
}

type scanAllJob struct {
	JobID      string `json:"job_id"`
	Kind       string `json:"kind"`
	Status     string `json:"status"` // running|success|failed
	CreatedAt  int64  `json:"created_at"`
	StartedAt  int64  `json:"started_at"`
	FinishedAt int64  `json:"finished_at"`

	// Stage/Progress/Logs 是给前端“控制台”用的轻量字段：
	// - 不追求特别精细的进度（目前 scan all 是串行执行 host -> mobile）
	// - 但至少能让 UI 展示：当前阶段、百分比、以及实时日志
	Stage    string       `json:"stage,omitempty"`    // host_scan|mobile_scan|finished
	Progress int          `json:"progress,omitempty"` // 0-100
	Logs     []jobLogLine `json:"logs,omitempty"`

	CaseID string `json:"case_id,omitempty"`

	Host      *hostscan.Result `json:"host,omitempty"`
	HostError string           `json:"host_error,omitempty"`

	Mobile      *mobilescan.Result `json:"mobile,omitempty"`
	MobileError string             `json:"mobile_error,omitempty"`

	Error string `json:"error,omitempty"`
}

type jobLogLine struct {
	Time    int64  `json:"time"`
	Message string `json:"message"`
}

func (m *jobManager) put(job *scanAllJob) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs[job.JobID] = job
}

func (m *jobManager) getCopy(jobID string) (scanAllJob, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[jobID]
	if !ok || j == nil {
		return scanAllJob{}, false
	}
	cpy := *j
	// 深拷贝 slice，避免解锁后后台 goroutine append 导致 data race。
	if len(cpy.Logs) > 0 {
		tmp := make([]jobLogLine, len(cpy.Logs))
		copy(tmp, cpy.Logs)
		cpy.Logs = tmp
	}
	return cpy, true
}

func (m *jobManager) listCopies() []scanAllJob {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]scanAllJob, 0, len(m.jobs))
	for _, j := range m.jobs {
		if j == nil {
			continue
		}
		cpy := *j
		if len(cpy.Logs) > 0 {
			tmp := make([]jobLogLine, len(cpy.Logs))
			copy(tmp, cpy.Logs)
			cpy.Logs = tmp
		}
		out = append(out, cpy)
	}
	return out
}

type scanAllRequest struct {
	Operator      string `json:"operator"`
	Note          string `json:"note"`
	Profile       string `json:"profile"` // internal|external
	CaseID        string `json:"case_id,omitempty"`
	AuthOrder     string `json:"auth_order,omitempty"`
	AuthBasis     string `json:"auth_basis,omitempty"`
	PrivacyMode   string `json:"privacy_mode,omitempty"` // off|masked（预留）
	IOSFullBackup *bool  `json:"ios_full_backup,omitempty"`

	// 采集范围控制（UI 勾选项对齐）
	EnableHost    *bool `json:"enable_host,omitempty"`
	EnableMobile  *bool `json:"enable_mobile,omitempty"`
	EnableAndroid *bool `json:"enable_android,omitempty"`
	EnableIOS     *bool `json:"enable_ios,omitempty"`
}

func (s *Server) handleJobScanAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req scanAllRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
		return
	}

	operator := strings.TrimSpace(req.Operator)
	if operator == "" {
		operator = "system"
	}
	profile := strings.ToLower(strings.TrimSpace(req.Profile))
	if profile == "" {
		profile = "internal"
	}
	requireAuthOrder := false
	requireAuthorized := false
	switch profile {
	case "internal":
		// 内测模式：尽量跑完，最大化采集（best effort）
	case "external":
		requireAuthOrder = true
		requireAuthorized = true
	default:
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid profile: %s", req.Profile))
		return
	}

	enableBackup := s.opts.EnableIOSFullBackup
	if req.IOSFullBackup != nil {
		enableBackup = *req.IOSFullBackup
	}
	privacyMode := strings.ToLower(strings.TrimSpace(req.PrivacyMode))
	if privacyMode == "" {
		privacyMode = s.opts.PrivacyMode
	}
	if privacyMode != "off" && privacyMode != "masked" {
		privacyMode = "off"
	}

	jobID := id.New("job")
	now := time.Now().Unix()
	job := &scanAllJob{
		JobID:     jobID,
		Kind:      "scan_all",
		Status:    "running",
		CreatedAt: now,
		StartedAt: now,
		Stage:     "host_scan",
		Progress:  1,
		Logs: []jobLogLine{{
			Time:    now,
			Message: "job created",
		}},
	}
	s.jobs.put(job)

	// 先返回一份拷贝，避免后台 goroutine 修改同一对象导致数据竞争。
	resp := *job

	go func() {
		ctx := context.Background()

		// 每个 job 启动时读取一次“当前启用的规则文件路径”，保证：
		// - UI 中导入/切换规则后，下一次扫描能立刻生效
		// - 扫描过程内保持一致（避免中途切换导致同一次扫描前后规则不一致）
		walletRulePath, exchangeRulePath := s.activeRulePaths(ctx)

		// --- request defaults ---
		enableHost := true
		if req.EnableHost != nil {
			enableHost = *req.EnableHost
		}
		enableMobile := true
		if req.EnableMobile != nil {
			enableMobile = *req.EnableMobile
		}
		enableAndroid := true
		if req.EnableAndroid != nil {
			enableAndroid = *req.EnableAndroid
		}
		enableIOS := true
		if req.EnableIOS != nil {
			enableIOS = *req.EnableIOS
		}

		// 内部辅助：追加一条 job 日志并更新 stage/progress（带锁，避免 data race）
		update := func(stage string, progress int, msg string) {
			s.jobs.mu.Lock()
			defer s.jobs.mu.Unlock()
			if stage != "" {
				job.Stage = stage
			}
			if progress >= 0 {
				job.Progress = progress
			}
			if strings.TrimSpace(msg) != "" {
				job.Logs = append(job.Logs, jobLogLine{
					Time:    time.Now().Unix(),
					Message: msg,
				})
			}
		}

		caseID := strings.TrimSpace(req.CaseID)

		// --- host scan ---
		var hostRes *hostscan.Result
		var hostErr error
		if enableHost {
			update("host_scan", 5, "host scan starting")
			hostRes, hostErr = hostscan.Run(ctx, hostscan.Options{
				DBPath:             s.opts.DBPath,
				EvidenceRoot:       s.opts.EvidenceRoot,
				WalletRulePath:     walletRulePath,
				ExchangeRulePath:   exchangeRulePath,
				CaseID:             caseID,
				Operator:           operator,
				Note:               strings.TrimSpace(req.Note),
				AuthorizationOrder: strings.TrimSpace(req.AuthOrder),
				AuthorizationBasis: strings.TrimSpace(req.AuthBasis),
				RequireAuthOrder:   requireAuthOrder,
				PrivacyMode:        privacyMode,
			})
			if hostRes != nil && strings.TrimSpace(hostRes.CaseID) != "" {
				caseID = strings.TrimSpace(hostRes.CaseID)
			}
			s.jobs.mu.Lock()
			job.Host = hostRes
			if hostErr != nil {
				job.HostError = hostErr.Error()
				job.Logs = append(job.Logs, jobLogLine{Time: time.Now().Unix(), Message: "host scan failed: " + hostErr.Error()})
			} else {
				job.Logs = append(job.Logs, jobLogLine{Time: time.Now().Unix(), Message: "host scan finished"})
			}
			job.CaseID = caseID
			job.Progress = 50
			s.jobs.mu.Unlock()
		} else {
			update("host_scan", 10, "host scan skipped")
		}

		// --- mobile scan ---
		var mobileRes *mobilescan.Result
		var mobileErr error
		if enableMobile {
			update("mobile_scan", 60, "mobile scan starting")
			mobileRes, mobileErr = mobilescan.Run(ctx, mobilescan.Options{
				DBPath:              s.opts.DBPath,
				EvidenceRoot:        s.opts.EvidenceRoot,
				IOSBackupDir:        s.opts.IOSBackupDir,
				WalletRulePath:      walletRulePath,
				ExchangeRulePath:    exchangeRulePath,
				CaseID:              caseID,
				Operator:            operator,
				Note:                strings.TrimSpace(req.Note),
				AuthorizationOrder:  strings.TrimSpace(req.AuthOrder),
				AuthorizationBasis:  strings.TrimSpace(req.AuthBasis),
				RequireAuthOrder:    requireAuthOrder,
				RequireAuthorized:   requireAuthorized,
				EnableIOSFullBackup: enableBackup,
				EnableAndroid:       enableAndroid,
				EnableIOS:           enableIOS,
				PrivacyMode:         privacyMode,
			})
			if mobileRes != nil && strings.TrimSpace(mobileRes.CaseID) != "" {
				caseID = strings.TrimSpace(mobileRes.CaseID)
			}
			s.jobs.mu.Lock()
			job.Mobile = mobileRes
			if mobileErr != nil {
				job.MobileError = mobileErr.Error()
				job.Logs = append(job.Logs, jobLogLine{Time: time.Now().Unix(), Message: "mobile scan failed: " + mobileErr.Error()})
			} else {
				job.Logs = append(job.Logs, jobLogLine{Time: time.Now().Unix(), Message: "mobile scan finished"})
			}
			job.CaseID = caseID
			job.Progress = 90
			s.jobs.mu.Unlock()
		} else {
			update("mobile_scan", 60, "mobile scan skipped")
		}

		// --- finalize ---
		s.jobs.mu.Lock()
		defer s.jobs.mu.Unlock()
		job.CaseID = caseID
		job.Stage = "finished"
		job.Progress = 100
		job.FinishedAt = time.Now().Unix()

		if enableHost && hostErr != nil && enableMobile && mobileErr != nil {
			job.Status = "failed"
			job.Error = fmt.Sprintf("host=%v; mobile=%v", hostErr, mobileErr)
			job.Logs = append(job.Logs, jobLogLine{Time: time.Now().Unix(), Message: "job failed"})
			return
		}
		// best effort：只要有一个成功就算 success
		job.Status = "success"
		job.Logs = append(job.Logs, jobLogLine{Time: time.Now().Unix(), Message: "job success"})
	}()

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleJobRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/api/jobs/")
	rest = strings.Trim(rest, "/")
	if rest == "" {
		// 简单返回全部 job（内测用，后续可加 limit/排序）
		writeJSON(w, http.StatusOK, map[string]any{
			"jobs": s.jobs.listCopies(),
		})
		return
	}

	job, ok := s.jobs.getCopy(rest)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("job not found: %s", rest))
		return
	}
	writeJSON(w, http.StatusOK, job)
}
