package chainbalance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestERC20Provider_QueryBalances_BalanceOf(t *testing.T) {
	holder := "0x000000000000000000000000000000000000dead"
	contract := "0xdAC17F958D2ee523a2206206994597C13D831ec7"
	wantData, err := encodeERC20BalanceOf(holder)
	if err != nil {
		t.Fatalf("encode calldata: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req evmRPCReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode req: %v", err)
		}
		if req.Method != "eth_call" {
			t.Fatalf("method=%s", req.Method)
		}
		if len(req.Params) < 2 {
			t.Fatalf("params len=%d", len(req.Params))
		}
		callObj, ok := req.Params[0].(map[string]any)
		if !ok {
			t.Fatalf("params[0] type=%T", req.Params[0])
		}
		if callObj["to"] != contract {
			t.Fatalf("to=%v", callObj["to"])
		}
		if callObj["data"] != wantData {
			t.Fatalf("data=%v", callObj["data"])
		}

		// 返回 12.345678 USDT（decimals=6）
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0xbc614e"}`))
	}))
	defer srv.Close()

	p := NewERC20Provider(srv.URL)
	p.Symbol = "USDT"
	p.Contract = contract
	p.Decimals = 6

	out, err := p.QueryBalances(context.Background(), []string{holder})
	if err != nil {
		t.Fatalf("QueryBalances: %v", err)
	}
	if out[holder]["USDT_RAW"] != "12345678" {
		t.Fatalf("USDT_RAW=%s", out[holder]["USDT_RAW"])
	}
	if out[holder]["USDT"] != "12.345678" {
		t.Fatalf("USDT=%s", out[holder]["USDT"])
	}
}
