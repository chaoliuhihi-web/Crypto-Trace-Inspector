package webapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"crypto-inspector/internal/adapters/rules"

	"gopkg.in/yaml.v3"
)

const (
	metaActiveWalletRulePath   = "active_wallet_rule_path"
	metaActiveExchangeRulePath = "active_exchange_rule_path"
)

type ruleFileInfo struct {
	Path       string `json:"path"`
	Filename   string `json:"filename"`
	BundleType string `json:"bundle_type"`
	Version    string `json:"version,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Active     bool   `json:"active"`
}

func (s *Server) rulesDir() string {
	// 与 DB 同级的 data/rules，适配“安装器模式”（应用目录只读，运行数据落在 data/）。
	return filepath.Join(filepath.Dir(s.opts.DBPath), "rules")
}

func (s *Server) activeRulePaths(ctx context.Context) (walletPath, exchangePath string) {
	walletPath = s.opts.WalletRulePath
	exchangePath = s.opts.ExchangeRulePath

	if v, _ := s.store.GetSchemaMetaValue(ctx, metaActiveWalletRulePath); strings.TrimSpace(v) != "" {
		walletPath = strings.TrimSpace(v)
	}
	if v, _ := s.store.GetSchemaMetaValue(ctx, metaActiveExchangeRulePath); strings.TrimSpace(v) != "" {
		exchangePath = strings.TrimSpace(v)
	}
	return walletPath, exchangePath
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleRulesList(w, r)
	case http.MethodPost:
		// /api/rules (POST) 作为一个简化路由：根据 action 分发
		s.handleRulesPost(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRulesList(w http.ResponseWriter, r *http.Request) {
	rulesDir := s.rulesDir()
	_ = os.MkdirAll(rulesDir, 0o755)

	walletPath, exchangePath := s.activeRulePaths(r.Context())

	// 收集候选文件：
	// - 启动参数指定的两个路径（允许用户“切回默认模板”）
	// - 当前 active 的两个路径
	// - rulesDir 下的 *.yaml/*.yml
	candidates := map[string]struct{}{}
	for _, p := range []string{s.opts.WalletRulePath, s.opts.ExchangeRulePath, walletPath, exchangePath} {
		p = strings.TrimSpace(p)
		if p != "" {
			candidates[p] = struct{}{}
		}
	}
	for _, pat := range []string{"*.yaml", "*.yml"} {
		files, _ := filepath.Glob(filepath.Join(rulesDir, pat))
		for _, f := range files {
			candidates[f] = struct{}{}
		}
	}

	var walletFiles []ruleFileInfo
	var exchangeFiles []ruleFileInfo
	for p := range candidates {
		info, err := inspectRuleFile(p)
		if err != nil {
			continue
		}
		info.Active = (p == walletPath) || (p == exchangePath)
		switch info.BundleType {
		case "wallet_signatures":
			info.Active = (p == walletPath)
			walletFiles = append(walletFiles, info)
		case "exchange_domains":
			info.Active = (p == exchangePath)
			exchangeFiles = append(exchangeFiles, info)
		}
	}

	sort.Slice(walletFiles, func(i, j int) bool { return walletFiles[i].Filename < walletFiles[j].Filename })
	sort.Slice(exchangeFiles, func(i, j int) bool { return exchangeFiles[i].Filename < exchangeFiles[j].Filename })

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"active": map[string]any{
			"wallet_path":   walletPath,
			"exchange_path": exchangePath,
		},
		"rules_dir": rulesDir,
		"wallet":    walletFiles,
		"exchange":  exchangeFiles,
	})
}

func (s *Server) handleRulesPost(w http.ResponseWriter, r *http.Request) {
	// 约定：POST /api/rules?action=import|activate
	action := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("action")))
	switch action {
	case "import":
		s.handleRulesImport(w, r)
	case "activate":
		s.handleRulesActivate(w, r)
	default:
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid action: %s", action))
	}
}

// handleRulesImport 接收 YAML 文本并落盘到 rulesDir，然后把该文件设为 active。
func (s *Server) handleRulesImport(w http.ResponseWriter, r *http.Request) {
	type reqBody struct {
		Kind     string `json:"kind"`               // wallet|exchange
		Filename string `json:"filename,omitempty"` // 可选
		Content  string `json:"content"`            // YAML 原文
	}
	var req reqBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
		return
	}

	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	if kind != "wallet" && kind != "exchange" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid kind: %s", req.Kind))
		return
	}
	content := strings.TrimSpace(req.Content)
	if content == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("empty content"))
		return
	}

	rulesDir := s.rulesDir()
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("create rules dir: %w", err))
		return
	}

	now := time.Now().Unix()
	name := strings.TrimSpace(req.Filename)
	name = filepath.Base(name)
	name = sanitizeRuleFilename(name)
	if name == "" {
		name = fmt.Sprintf("%s_import_%d.yaml", kind, now)
	}
	if !strings.HasSuffix(strings.ToLower(name), ".yaml") && !strings.HasSuffix(strings.ToLower(name), ".yml") {
		name += ".yaml"
	}
	dst := filepath.Join(rulesDir, fmt.Sprintf("%s_%d_%s", kind, now, name))
	if err := os.WriteFile(dst, []byte(content), 0o644); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("write file: %w", err))
		return
	}

	// 校验 bundle_type 是否匹配 kind
	info, err := inspectRuleFile(dst)
	if err != nil {
		_ = os.Remove(dst)
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid rule file: %w", err))
		return
	}
	wantBundleType := "wallet_signatures"
	if kind == "exchange" {
		wantBundleType = "exchange_domains"
	}
	if info.BundleType != wantBundleType {
		_ = os.Remove(dst)
		writeError(w, http.StatusBadRequest, fmt.Errorf("bundle_type mismatch: got %s want %s", info.BundleType, wantBundleType))
		return
	}

	// 用 loader 做一次完整校验（wallet/exchange 需要成对存在）
	activeWallet, activeExchange := s.activeRulePaths(r.Context())
	if kind == "wallet" {
		activeWallet = dst
	} else {
		activeExchange = dst
	}
	loader := rules.NewLoader(activeWallet, activeExchange)
	if _, err := loader.Load(r.Context()); err != nil {
		_ = os.Remove(dst)
		writeError(w, http.StatusBadRequest, fmt.Errorf("rule validation failed: %w", err))
		return
	}

	// 设为 active
	if kind == "wallet" {
		if err := s.store.UpsertSchemaMetaValue(r.Context(), metaActiveWalletRulePath, dst); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	} else {
		if err := s.store.UpsertSchemaMetaValue(r.Context(), metaActiveExchangeRulePath, dst); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"kind": kind,
		"file": info,
	})
}

func (s *Server) handleRulesActivate(w http.ResponseWriter, r *http.Request) {
	type reqBody struct {
		WalletPath   string `json:"wallet_path,omitempty"`
		ExchangePath string `json:"exchange_path,omitempty"`
	}
	var req reqBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
		return
	}

	walletPath, exchangePath := s.activeRulePaths(r.Context())
	if strings.TrimSpace(req.WalletPath) != "" {
		walletPath = strings.TrimSpace(req.WalletPath)
	}
	if strings.TrimSpace(req.ExchangePath) != "" {
		exchangePath = strings.TrimSpace(req.ExchangePath)
	}

	// 校验 & 载入
	loader := rules.NewLoader(walletPath, exchangePath)
	if _, err := loader.Load(r.Context()); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("rule validation failed: %w", err))
		return
	}

	if strings.TrimSpace(req.WalletPath) != "" {
		if err := s.store.UpsertSchemaMetaValue(r.Context(), metaActiveWalletRulePath, walletPath); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	if strings.TrimSpace(req.ExchangePath) != "" {
		if err := s.store.UpsertSchemaMetaValue(r.Context(), metaActiveExchangeRulePath, exchangePath); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"active": map[string]any{
			"wallet_path":   walletPath,
			"exchange_path": exchangePath,
		},
	})
}

func sanitizeRuleFilename(in string) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return ""
	}
	in = strings.ReplaceAll(in, " ", "_")
	in = strings.ReplaceAll(in, string(os.PathSeparator), "_")
	in = strings.ReplaceAll(in, "..", "_")
	return in
}

func inspectRuleFile(path string) (ruleFileInfo, error) {
	if strings.TrimSpace(path) == "" {
		return ruleFileInfo{}, fmt.Errorf("empty path")
	}
	if _, err := os.Stat(path); err != nil {
		return ruleFileInfo{}, err
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return ruleFileInfo{}, err
	}
	sum := sha256.Sum256(raw)
	sha := hex.EncodeToString(sum[:])

	var meta struct {
		Version    string `yaml:"version"`
		BundleType string `yaml:"bundle_type"`
	}
	if err := yaml.Unmarshal(raw, &meta); err != nil {
		return ruleFileInfo{}, err
	}

	return ruleFileInfo{
		Path:       path,
		Filename:   filepath.Base(path),
		BundleType: strings.TrimSpace(meta.BundleType),
		Version:    strings.TrimSpace(meta.Version),
		SHA256:     sha,
	}, nil
}
