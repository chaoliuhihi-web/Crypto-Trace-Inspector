package privacy

import (
	"encoding/json"
	"strings"
	"testing"

	"crypto-inspector/internal/domain/model"
)

func TestMaskSnapshotPath(t *testing.T) {
	got := MaskSnapshotPath("/Users/alice/Library/Application Support/foo/bar.json")
	if got != "bar.json" {
		t.Fatalf("got=%q want=%q", got, "bar.json")
	}
}

func TestMaskURL(t *testing.T) {
	got := MaskURL("https://example.com/a/b?x=1")
	if got != "example.com" {
		t.Fatalf("got=%q want=%q", got, "example.com")
	}
	got = MaskURL("www.okx.com/path")
	if got != "www.okx.com" {
		t.Fatalf("got=%q want=%q", got, "www.okx.com")
	}
}

func TestMaskAddress(t *testing.T) {
	evm := "0x000000000000000000000000000000000000dEaD"
	got := MaskAddress(evm)
	if got == evm {
		t.Fatalf("address not masked")
	}
	if !strings.Contains(got, "...") {
		t.Fatalf("masked should contain ellipsis: %q", got)
	}
	if !strings.HasPrefix(strings.ToLower(got), "0x0000") {
		t.Fatalf("masked should keep prefix: %q", got)
	}
}

func TestMaskRuleHitsForReport_TokenBalance(t *testing.T) {
	evm := "0x000000000000000000000000000000000000dEaD"
	raw := mustJSON(t, map[string]any{
		"kind":    "evm_native",
		"symbol":  "ETH",
		"address": evm,
		"query": map[string]any{
			"addresses": []any{evm},
		},
	})
	hits := []model.RuleHit{{
		Type:         model.HitTokenBalance,
		MatchedValue: evm + "|ETH",
		DetailJSON:   raw,
	}}
	out := MaskRuleHitsForReport(hits)
	if len(out) != 1 {
		t.Fatalf("out len=%d", len(out))
	}
	if out[0].MatchedValue == hits[0].MatchedValue {
		t.Fatalf("MatchedValue not masked: %q", out[0].MatchedValue)
	}

	var m map[string]any
	if err := json.Unmarshal(out[0].DetailJSON, &m); err != nil {
		t.Fatalf("unmarshal detail_json: %v", err)
	}
	if addr, _ := m["address"].(string); addr == evm {
		t.Fatalf("detail_json.address not masked")
	}
}

func TestMaskRuleHitsForReport_WalletAddress(t *testing.T) {
	raw := mustJSON(t, map[string]any{
		"sample": "send to 1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
	})
	hits := []model.RuleHit{{
		Type:         model.HitWalletAddress,
		MatchedValue: "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
		DetailJSON:   raw,
	}}
	out := MaskRuleHitsForReport(hits)
	if out[0].MatchedValue == hits[0].MatchedValue {
		t.Fatalf("MatchedValue not masked")
	}
	var m map[string]any
	_ = json.Unmarshal(out[0].DetailJSON, &m)
	if m["sample"] != "<masked>" {
		t.Fatalf("sample not masked: %#v", m["sample"])
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	return raw
}
