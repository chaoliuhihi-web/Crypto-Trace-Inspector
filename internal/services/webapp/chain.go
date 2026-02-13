package webapp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"crypto-inspector/internal/adapters/host"
	"crypto-inspector/internal/app"
	"crypto-inspector/internal/domain/model"
	"crypto-inspector/internal/platform/hash"
	"crypto-inspector/internal/platform/id"
	"crypto-inspector/internal/services/chainbalance"
)

// handleChainRoutes 提供“链上余额查询”相关接口。
//
// 说明：
// - 内测阶段：强调“开箱即用”，允许缺省使用公共数据源（EVM RPC / BTC API）。
// - 对外/正式阶段：建议强制要求私有数据源（私有 RPC / 自建 BTC 节点网关），并配合访问控制与审计。
//
// 当前支持：
// - EVM 原生币余额：eth_getBalance
// - EVM ERC20 余额：eth_call balanceOf(address)
// - BTC 地址余额：Blockstream API（可配置 base_url）
func (s *Server) handleChainRoutes(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/chain/")
	rest = strings.Trim(rest, "/")
	if rest == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	parts := strings.Split(rest, "/")

	switch parts[0] {
	case "evm":
		if len(parts) < 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch parts[1] {
		case "balances":
			s.handleChainEVMBalances(w, r)
		case "erc20":
			// /api/chain/evm/erc20/balances
			if len(parts) >= 3 && parts[2] == "balances" {
				s.handleChainEVMERC20Balances(w, r)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	case "btc":
		// /api/chain/btc/balances
		if len(parts) >= 2 && parts[1] == "balances" {
			s.handleChainBTCBalances(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// handleCaseChain 提供“带证据留痕”的链上查询接口（写入 artifacts + rule_hits）。
//
// 路由：
// - POST /api/cases/{case_id}/chain/balance
func (s *Server) handleCaseChain(w http.ResponseWriter, r *http.Request, caseID string, parts []string) {
	if len(parts) < 1 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	action := strings.TrimSpace(parts[0])
	switch action {
	case "balance":
		s.handleCaseChainBalance(w, r, caseID)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *Server) handleChainEVMBalances(w http.ResponseWriter, r *http.Request) {
	// 统一用 POST，避免地址列表太长导致 URL 超长。
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	type reqBody struct {
		RPCURL    string   `json:"rpc_url,omitempty"`
		Symbol    string   `json:"symbol,omitempty"`
		Addresses []string `json:"addresses,omitempty"`
	}
	var req reqBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
		return
	}

	rpcURL := strings.TrimSpace(req.RPCURL)
	warnings := []string{}
	if rpcURL == "" {
		// 内部试用默认走公共 RPC，方便开箱即用。
		// 对外/正式环境建议改为“强制配置私有 RPC”，并做访问控制与审计。
		rpcURL = chainbalance.DefaultPublicEVMRPC
		warnings = append(warnings, "rpc_url not provided; fallback to default public rpc")
	}
	symbol := strings.TrimSpace(req.Symbol)
	if symbol == "" {
		symbol = "ETH"
	}

	// 清洗地址列表：去空、去重、限流。
	addrSet := map[string]struct{}{}
	addrs := make([]string, 0, len(req.Addresses))
	for _, a := range req.Addresses {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if _, ok := addrSet[a]; ok {
			continue
		}
		addrSet[a] = struct{}{}
		addrs = append(addrs, a)
	}
	const maxAddrs = 50
	if len(addrs) > maxAddrs {
		warnings = append(warnings, fmt.Sprintf("addresses truncated: max=%d", maxAddrs))
		addrs = addrs[:maxAddrs]
	}

	p := chainbalance.NewEVMProvider(rpcURL)
	p.Symbol = symbol

	bal, err := p.QueryBalances(r.Context(), addrs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"chain":      "evm",
		"rpc_url":    rpcURL,
		"symbol":     symbol,
		"balances":   bal,
		"warnings":   warnings,
		"addr_count": len(addrs),
	})
}

func (s *Server) handleChainEVMERC20Balances(w http.ResponseWriter, r *http.Request) {
	// 统一用 POST，避免地址列表太长导致 URL 超长。
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	type reqBody struct {
		RPCURL    string   `json:"rpc_url,omitempty"`
		Symbol    string   `json:"symbol,omitempty"`
		Contract  string   `json:"contract,omitempty"`
		Decimals  int      `json:"decimals,omitempty"`
		Addresses []string `json:"addresses,omitempty"`
	}
	var req reqBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
		return
	}

	rpcURL := strings.TrimSpace(req.RPCURL)
	warnings := []string{}
	if rpcURL == "" {
		// 内部试用默认走公共 RPC，方便开箱即用。
		// 对外/正式环境建议改为“强制配置私有 RPC”，并做访问控制与审计。
		rpcURL = chainbalance.DefaultPublicEVMRPC
		warnings = append(warnings, "rpc_url not provided; fallback to default public rpc")
	}

	symbol := strings.TrimSpace(req.Symbol)
	if symbol == "" {
		symbol = "USDT"
	}
	contract := strings.TrimSpace(req.Contract)
	if contract == "" && strings.EqualFold(symbol, "USDT") {
		// 内测默认值（Ethereum Mainnet USDT）
		contract = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
		warnings = append(warnings, "contract not provided; fallback to Ethereum mainnet USDT contract")
	}
	if contract == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("contract is required"))
		return
	}
	decimals := req.Decimals
	if decimals == 0 && strings.EqualFold(symbol, "USDT") {
		// USDT 在以太坊主网常用 decimals=6。
		decimals = 6
		warnings = append(warnings, "decimals not provided; fallback to 6 for USDT")
	}

	// 清洗地址列表：去空、去重、限流。
	addrSet := map[string]struct{}{}
	addrs := make([]string, 0, len(req.Addresses))
	for _, a := range req.Addresses {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if _, ok := addrSet[a]; ok {
			continue
		}
		addrSet[a] = struct{}{}
		addrs = append(addrs, a)
	}
	const maxAddrs = 50
	if len(addrs) > maxAddrs {
		warnings = append(warnings, fmt.Sprintf("addresses truncated: max=%d", maxAddrs))
		addrs = addrs[:maxAddrs]
	}

	p := chainbalance.NewERC20Provider(rpcURL)
	p.Symbol = symbol
	p.Contract = contract
	p.Decimals = decimals

	bal, err := p.QueryBalances(r.Context(), addrs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"chain":      "evm",
		"token_type": "erc20",
		"rpc_url":    rpcURL,
		"symbol":     symbol,
		"contract":   contract,
		"decimals":   decimals,
		"balances":   bal,
		"warnings":   warnings,
		"addr_count": len(addrs),
	})
}

func (s *Server) handleChainBTCBalances(w http.ResponseWriter, r *http.Request) {
	// 统一用 POST，避免地址列表太长导致 URL 超长。
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	type reqBody struct {
		BaseURL   string   `json:"base_url,omitempty"`
		Symbol    string   `json:"symbol,omitempty"`
		Addresses []string `json:"addresses,omitempty"`
	}
	var req reqBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
		return
	}

	baseURL := strings.TrimSpace(req.BaseURL)
	warnings := []string{}
	if baseURL == "" {
		baseURL = chainbalance.DefaultPublicBTCAPI
		warnings = append(warnings, "base_url not provided; fallback to default public btc api")
	}

	symbol := strings.TrimSpace(req.Symbol)
	if symbol == "" {
		symbol = "BTC"
	}

	// 清洗地址列表：去空、去重、限流。
	addrSet := map[string]struct{}{}
	addrs := make([]string, 0, len(req.Addresses))
	for _, a := range req.Addresses {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if _, ok := addrSet[a]; ok {
			continue
		}
		addrSet[a] = struct{}{}
		addrs = append(addrs, a)
	}
	const maxAddrs = 50
	if len(addrs) > maxAddrs {
		warnings = append(warnings, fmt.Sprintf("addresses truncated: max=%d", maxAddrs))
		addrs = addrs[:maxAddrs]
	}

	p := chainbalance.NewBTCProvider(baseURL)
	p.Symbol = symbol

	bal, err := p.QueryBalances(r.Context(), addrs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"chain":      "btc",
		"base_url":   baseURL,
		"symbol":     symbol,
		"balances":   bal,
		"warnings":   warnings,
		"addr_count": len(addrs),
	})
}

func (s *Server) handleCaseChainBalance(w http.ResponseWriter, r *http.Request, caseID string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// 说明：
	// - 这个接口是“查询 + 留痕”：把查询结果写入 artifacts（chain_balance）并固化为 token_balance 命中。
	// - 内测阶段默认不做鉴权；正式对外建议：
	//   1) 要求 operator/授权工单
	//   2) 强制私有数据源
	//   3) 对每次查询写入审计日志并限制频率
	type reqBody struct {
		Operator string `json:"operator,omitempty"`
		Note     string `json:"note,omitempty"`
		Kind     string `json:"kind,omitempty"` // evm_native|evm_erc20|btc

		// EVM / ERC20
		RPCURL   string `json:"rpc_url,omitempty"`
		Symbol   string `json:"symbol,omitempty"`
		Contract string `json:"contract,omitempty"`
		Decimals int    `json:"decimals,omitempty"`

		// BTC
		BaseURL string `json:"base_url,omitempty"`

		Addresses []string `json:"addresses,omitempty"`
	}
	var req reqBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
		return
	}

	ov, err := s.store.GetCaseOverview(r.Context(), caseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if ov == nil || strings.TrimSpace(ov.CaseID) == "" {
		writeError(w, http.StatusNotFound, fmt.Errorf("case not found: %s", caseID))
		return
	}

	operator := strings.TrimSpace(req.Operator)
	if operator == "" {
		operator = "system"
	}
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	if kind == "" {
		kind = "evm_native"
	}

	// 清洗地址列表：去空、去重、限流。
	addrSet := map[string]struct{}{}
	addrs := make([]string, 0, len(req.Addresses))
	for _, a := range req.Addresses {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if _, ok := addrSet[a]; ok {
			continue
		}
		addrSet[a] = struct{}{}
		addrs = append(addrs, a)
	}
	const maxAddrs = 50
	if len(addrs) == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("addresses is required"))
		return
	}
	warnings := []string{}
	if len(addrs) > maxAddrs {
		warnings = append(warnings, fmt.Sprintf("addresses truncated: max=%d", maxAddrs))
		addrs = addrs[:maxAddrs]
	}

	// 决定本次“留痕证据”挂到哪个 device_id：
	// - 优先复用案件已有本机(local)设备
	// - 否则创建一个“当前主机设备”作为载体（os_type 受 DB CHECK 约束）
	deviceID := ""
	if rows, err := s.store.ListCaseDevices(r.Context(), caseID); err == nil {
		for _, d := range rows {
			if strings.TrimSpace(d.ConnectionType) == "local" {
				deviceID = d.DeviceID
				break
			}
		}
	}
	if deviceID == "" {
		dev, derr := host.DetectHostDevice()
		if derr != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("detect host device: %w", derr))
			return
		}
		if err := s.store.UpsertDevice(r.Context(), caseID, dev, true, "host local device (auto)"); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("upsert host device: %w", err))
			return
		}
		deviceID = dev.ID
	}

	// 执行链上查询
	now := time.Now().Unix()
	balances := map[string]map[string]string{}
	queryMeta := map[string]any{
		"kind":       kind,
		"case_id":    caseID,
		"device_id":  deviceID,
		"queried_at": now,
	}

	switch kind {
	case "evm_native":
		rpcURL := strings.TrimSpace(req.RPCURL)
		if rpcURL == "" {
			rpcURL = chainbalance.DefaultPublicEVMRPC
			warnings = append(warnings, "rpc_url not provided; fallback to default public rpc")
		}
		symbol := strings.TrimSpace(req.Symbol)
		if symbol == "" {
			symbol = "ETH"
		}
		p := chainbalance.NewEVMProvider(rpcURL)
		p.Symbol = symbol
		out, err := p.QueryBalances(r.Context(), addrs)
		if err != nil {
			_ = s.store.AppendAudit(r.Context(), caseID, deviceID, "chain_balance", "query", "failed", operator, "webapp.chain_balance", map[string]any{
				"kind":  kind,
				"error": err.Error(),
			})
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		balances = out
		queryMeta["chain"] = "evm"
		queryMeta["rpc_url"] = rpcURL
		queryMeta["symbol"] = symbol
	case "evm_erc20":
		rpcURL := strings.TrimSpace(req.RPCURL)
		if rpcURL == "" {
			rpcURL = chainbalance.DefaultPublicEVMRPC
			warnings = append(warnings, "rpc_url not provided; fallback to default public rpc")
		}
		symbol := strings.TrimSpace(req.Symbol)
		if symbol == "" {
			symbol = "USDT"
		}
		contract := strings.TrimSpace(req.Contract)
		if contract == "" && strings.EqualFold(symbol, "USDT") {
			contract = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
			warnings = append(warnings, "contract not provided; fallback to Ethereum mainnet USDT contract")
		}
		if contract == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("contract is required"))
			return
		}
		decimals := req.Decimals
		if decimals == 0 && strings.EqualFold(symbol, "USDT") {
			decimals = 6
			warnings = append(warnings, "decimals not provided; fallback to 6 for USDT")
		}
		p := chainbalance.NewERC20Provider(rpcURL)
		p.Symbol = symbol
		p.Contract = contract
		p.Decimals = decimals
		out, err := p.QueryBalances(r.Context(), addrs)
		if err != nil {
			_ = s.store.AppendAudit(r.Context(), caseID, deviceID, "chain_balance", "query", "failed", operator, "webapp.chain_balance", map[string]any{
				"kind":  kind,
				"error": err.Error(),
			})
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		balances = out
		queryMeta["chain"] = "evm"
		queryMeta["token_type"] = "erc20"
		queryMeta["rpc_url"] = rpcURL
		queryMeta["symbol"] = symbol
		queryMeta["contract"] = contract
		queryMeta["decimals"] = decimals
	case "btc":
		baseURL := strings.TrimSpace(req.BaseURL)
		if baseURL == "" {
			baseURL = chainbalance.DefaultPublicBTCAPI
			warnings = append(warnings, "base_url not provided; fallback to default public btc api")
		}
		symbol := strings.TrimSpace(req.Symbol)
		if symbol == "" {
			symbol = "BTC"
		}
		p := chainbalance.NewBTCProvider(baseURL)
		p.Symbol = symbol
		out, err := p.QueryBalances(r.Context(), addrs)
		if err != nil {
			_ = s.store.AppendAudit(r.Context(), caseID, deviceID, "chain_balance", "query", "failed", operator, "webapp.chain_balance", map[string]any{
				"kind":  kind,
				"error": err.Error(),
			})
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		balances = out
		queryMeta["chain"] = "btc"
		queryMeta["base_url"] = baseURL
		queryMeta["symbol"] = symbol
	default:
		writeError(w, http.StatusBadRequest, fmt.Errorf("unknown kind: %s", kind))
		return
	}

	// --- 写入 chain_balance artifact（证据快照） ---
	artifactID := id.New("art")
	payload := map[string]any{
		"query":    queryMeta,
		"note":     strings.TrimSpace(req.Note),
		"warnings": warnings,
		"balances": balances,
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("marshal payload: %w", err))
		return
	}

	dir := filepath.Join(s.opts.EvidenceRoot, caseID, deviceID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("create evidence dir: %w", err))
		return
	}
	filename := fmt.Sprintf("chain_balance_%s_%d.json", kind, now)
	snapshotPath := filepath.Join(dir, filename)
	if err := os.WriteFile(snapshotPath, raw, 0o644); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("write evidence file: %w", err))
		return
	}
	sum, size, err := hash.File(snapshotPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("hash evidence file: %w", err))
		return
	}

	collectorName := "webapp_chain_query"
	collectorVer := "webapp-" + strings.TrimSpace(app.Version)
	if strings.TrimSpace(app.Version) == "" {
		collectorVer = "webapp-dev"
	}
	recordHash := hash.Text(
		artifactID,
		caseID,
		deviceID,
		string(model.ArtifactChainBalance),
		kind,
		snapshotPath,
		sum,
		fmt.Sprintf("%d", size),
		fmt.Sprintf("%d", now),
		collectorName,
		collectorVer,
		string(raw),
	)

	art := model.Artifact{
		ID:                artifactID,
		CaseID:            caseID,
		DeviceID:          deviceID,
		Type:              model.ArtifactChainBalance,
		SourceRef:         kind,
		SnapshotPath:      snapshotPath,
		SHA256:            sum,
		SizeBytes:         size,
		CollectedAt:       now,
		CollectorName:     collectorName,
		CollectorVersion:  collectorVer,
		ParserVersion:     "chainbalance-0.1.0",
		AcquisitionMethod: "api_query",
		PayloadJSON:       raw,
		RecordHash:        recordHash,
	}

	if err := s.store.SaveArtifacts(r.Context(), []model.Artifact{art}); err != nil {
		_ = s.store.AppendAudit(r.Context(), caseID, deviceID, "chain_balance", "save_artifact", "failed", operator, "webapp.chain_balance", map[string]any{
			"artifact_id": artifactID,
			"error":       err.Error(),
		})
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// --- 写入 token_balance 命中 ---
	hits := make([]model.RuleHit, 0, len(balances))
	for addr, m := range balances {
		symbol, _ := queryMeta["symbol"].(string)
		if symbol == "" {
			symbol = strings.TrimSpace(req.Symbol)
		}
		matchedValue := addr
		if symbol != "" {
			matchedValue = addr + "|" + symbol
		}
		hits = append(hits, model.RuleHit{
			ID:           id.New("hit"),
			CaseID:       caseID,
			DeviceID:     deviceID,
			Type:         model.HitTokenBalance,
			RuleID:       "chain_balance_" + kind,
			RuleName:     "链上余额查询结果",
			RuleVersion:  "chainbalance-0.1.0",
			MatchedValue: matchedValue,
			FirstSeenAt:  now,
			LastSeenAt:   now,
			Confidence:   0.95,
			Verdict:      "confirmed",
			DetailJSON: mustJSON(map[string]any{
				"kind":     kind,
				"symbol":   symbol,
				"address":  addr,
				"balances": m,
				"query":    queryMeta,
			}),
			ArtifactIDs: []string{artifactID},
		})
	}
	if err := s.store.SaveRuleHits(r.Context(), hits); err != nil {
		_ = s.store.AppendAudit(r.Context(), caseID, deviceID, "chain_balance", "save_hits", "failed", operator, "webapp.chain_balance", map[string]any{
			"artifact_id": artifactID,
			"error":       err.Error(),
		})
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	_ = s.store.AppendAudit(r.Context(), caseID, deviceID, "chain_balance", "query_and_persist", "success", operator, "webapp.chain_balance", map[string]any{
		"kind":        kind,
		"artifact_id": artifactID,
		"addr_count":  len(addrs),
		"hit_count":   len(hits),
		"warnings":    warnings,
	})

	hitIDs := make([]string, 0, len(hits))
	for _, h := range hits {
		hitIDs = append(hitIDs, h.ID)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"case_id":       caseID,
		"device_id":     deviceID,
		"kind":          kind,
		"artifact_id":   artifactID,
		"snapshot_path": snapshotPath,
		"sha256":        sum,
		"size_bytes":    size,
		"balances":      balances,
		"hit_ids":       hitIDs,
		"warnings":      warnings,
	})
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return raw
}
