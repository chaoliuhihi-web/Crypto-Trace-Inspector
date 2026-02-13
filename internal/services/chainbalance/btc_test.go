package chainbalance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBTCProvider_QueryBalances_BlockstreamAddressAPI(t *testing.T) {
	t.Parallel()

	addr := "bc1qexample0000000000000000000000000000000000"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/address/"+addr {
			t.Fatalf("path=%s", r.URL.Path)
		}

		// 最终余额 = (chain.funded - chain.spent) + (mempool.funded - mempool.spent)
		resp := blockstreamAddressResp{}
		resp.ChainStats.FundedTxoSum = 1000
		resp.ChainStats.SpentTxoSum = 200
		resp.MempoolStats.FundedTxoSum = 50
		resp.MempoolStats.SpentTxoSum = 0

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewBTCProvider(srv.URL)
	out, err := p.QueryBalances(context.Background(), []string{addr})
	if err != nil {
		t.Fatalf("QueryBalances: %v", err)
	}

	// 850 sat
	if out[addr]["SAT"] != "850" {
		t.Fatalf("SAT=%s", out[addr]["SAT"])
	}
	// 850 / 1e8 = 0.0000085
	if out[addr]["BTC"] != "0.0000085" {
		t.Fatalf("BTC=%s", out[addr]["BTC"])
	}
}
