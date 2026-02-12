package chainbalance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEVMProvider_QueryBalances(t *testing.T) {
	t.Parallel()

	// 用 httptest 模拟 JSON-RPC 节点。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req evmRPCReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
			return
		}
		if req.Method != "eth_getBalance" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "unexpected method"})
			return
		}
		if len(req.Params) < 1 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "missing params"})
			return
		}
		addr, _ := req.Params[0].(string)

		// 按地址返回不同余额：
		// - 0xA -> 1 wei
		// - 0xB -> 1 ether (1e18 wei)
		result := "0x0"
		switch addr {
		case "0xA":
			result = "0x1"
		case "0xB":
			result = "0xde0b6b3a7640000"
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  result,
		})
	}))
	defer srv.Close()

	p := NewEVMProvider(srv.URL)
	p.Symbol = "ETH"
	got, err := p.QueryBalances(context.Background(), []string{"0xA", "0xB"})
	if err != nil {
		t.Fatalf("QueryBalances: %v", err)
	}

	if got["0xA"]["WEI"] != "1" {
		t.Fatalf("0xA WEI: want 1, got %q", got["0xA"]["WEI"])
	}
	if got["0xA"]["ETH"] != "0.000000000000000001" {
		t.Fatalf("0xA ETH: want 0.000000000000000001, got %q", got["0xA"]["ETH"])
	}
	if got["0xB"]["WEI"] != "1000000000000000000" {
		t.Fatalf("0xB WEI: want 1000000000000000000, got %q", got["0xB"]["WEI"])
	}
	if got["0xB"]["ETH"] != "1" {
		t.Fatalf("0xB ETH: want 1, got %q", got["0xB"]["ETH"])
	}
}
