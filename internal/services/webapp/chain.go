package webapp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"crypto-inspector/internal/services/chainbalance"
)

// handleChainRoutes 提供“链上余额查询”相关接口。
//
// 当前仅实现 EVM 原生币余额查询（eth_getBalance）。
// 后续可以扩展更多链与更多 token 类型。
func (s *Server) handleChainRoutes(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/chain/")
	rest = strings.Trim(rest, "/")
	if rest == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	switch parts[0] {
	case "evm":
		switch parts[1] {
		case "balances":
			s.handleChainEVMBalances(w, r)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
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
