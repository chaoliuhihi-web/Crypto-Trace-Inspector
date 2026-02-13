package matcher

import (
	"encoding/json"
	"testing"

	"crypto-inspector/internal/adapters/rules"
	"crypto-inspector/internal/domain/model"
)

func TestMatchHostArtifacts_ExtractWalletAddresses_FromBrowserHistory(t *testing.T) {
	// 这里不依赖规则库：只验证“地址抽取”逻辑是否会生成 wallet_address 命中。
	loaded := &rules.LoadedRules{}

	evm := "0x000000000000000000000000000000000000dEaD"
	btcBech32 := "bc1q" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 42 chars
	btcBase58 := "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"

	visits := []model.VisitRecord{
		{Browser: "safari", URL: "https://etherscan.io/address/" + evm, Domain: "etherscan.io", VisitedAt: 1700000001},
		{Browser: "safari", URL: "https://example.com/?addr=" + btcBech32, Domain: "example.com", VisitedAt: 1700000002},
		{Browser: "safari", URL: "https://foo.local/", Title: "send to " + btcBase58, Domain: "foo.local", VisitedAt: 1700000003},
	}
	raw, _ := json.Marshal(visits)

	artifacts := []model.Artifact{
		{
			ID:          "art_browser_history_1",
			CaseID:      "case_1",
			DeviceID:    "dev_1",
			Type:        model.ArtifactBrowserHistory,
			PayloadJSON: raw,
		},
	}

	res, err := MatchHostArtifacts(loaded, artifacts)
	if err != nil {
		t.Fatalf("MatchHostArtifacts: %v", err)
	}

	// 预期抽取出 3 个地址命中（EVM/bech32/base58）
	addrHits := 0
	for _, h := range res.Hits {
		if h.Type != model.HitWalletAddress {
			continue
		}
		addrHits++
	}
	if addrHits != 3 {
		t.Fatalf("wallet_address hits=%d, want 3", addrHits)
	}
}
