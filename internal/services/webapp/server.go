package webapp

import (
	"database/sql"
	"io/fs"
	"net/http"
	"strings"

	sqliteadapter "crypto-inspector/internal/adapters/store/sqlite"
)

// Server 是内置 Web UI/API 的运行时对象。
type Server struct {
	opts  Options
	db    *sql.DB
	store *sqliteadapter.Store

	ui   fs.FS
	jobs *jobManager
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	// API
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/meta", s.handleMeta)
	mux.HandleFunc("/api/cases", s.handleCases)
	mux.HandleFunc("/api/cases/", s.handleCaseRoutes)
	mux.HandleFunc("/api/reports/", s.handleReportRoutes)
	mux.HandleFunc("/api/artifacts/", s.handleArtifactRoutes)
	mux.HandleFunc("/api/jobs/scan-all", s.handleJobScanAll)
	mux.HandleFunc("/api/jobs/", s.handleJobRoutes)

	// UI（单页应用 + 静态资源）
	//
	// 规则：
	// - 先尝试按路径返回静态文件（/assets/*、/favicon.ico、/index.html ...）
	// - 如果文件不存在且看起来像“前端路由”（无扩展名），回落到 index.html（支持刷新/直达路由）
	// - 如果是缺失的静态资源（有扩展名），返回 404（避免把错误资源也回落到 index.html）
	uiFileServer := http.FileServer(http.FS(s.ui))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.handleUI(w, r, uiFileServer)
	})
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request, uiFileServer http.Handler) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// API 路由已在上方注册；这里再兜底一次，避免误把 /api/* 当静态资源处理。
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// "/" 直接返回入口页
	if r.URL.Path == "/" || r.URL.Path == "" {
		// 这里不要改写到 /index.html：
		// net/http 的 FileServer 会把 "/index.html" 规范化重定向到 "./"（即目录），
		// 反而造成 301 循环。直接让 FileServer 处理 "/"，它会自动尝试目录下的 index.html。
		uiFileServer.ServeHTTP(w, r)
		return
	}

	// 先尝试按静态文件返回
	reqPath := strings.TrimPrefix(r.URL.Path, "/")
	if reqPath != "" {
		if info, err := fs.Stat(s.ui, reqPath); err == nil && !info.IsDir() {
			uiFileServer.ServeHTTP(w, r)
			return
		}
	}

	// 缺失的资源：有扩展名 -> 404；无扩展名 -> SPA 回落 index.html
	if strings.Contains(reqPath, ".") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	r2 := r.Clone(r.Context())
	// SPA 路由回落到 "/"（由 FileServer 自动返回 index.html），避免 /index.html 的 301 规范化重定向。
	r2.URL.Path = "/"
	uiFileServer.ServeHTTP(w, r2)
}
