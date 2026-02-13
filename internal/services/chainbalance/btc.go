package chainbalance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// DefaultPublicBTCAPI 是内部试用的默认公共数据源（不保证长期可用）。
// 正式对外时建议改为“配置必填”，并支持私有节点/网关。
const DefaultPublicBTCAPI = "https://blockstream.info/api"

// BTCProvider 通过 HTTP API 查询 BTC 地址余额（以 satoshi 为精确单位）。
//
// 当前实现对接 Blockstream API（/address/{addr}）。
// 返回同时包含：
// - SAT：精确整数（satoshi）
// - BTC：按 1e8 小数格式化的可读值
type BTCProvider struct {
	BaseURL string
	Symbol  string

	HTTPClient *http.Client
}

func NewBTCProvider(baseURL string) *BTCProvider {
	return &BTCProvider{BaseURL: strings.TrimSpace(baseURL)}
}

func (p *BTCProvider) QueryBalances(ctx context.Context, addresses []string) (map[string]map[string]string, error) {
	base := strings.TrimSpace(p.BaseURL)
	if base == "" {
		base = DefaultPublicBTCAPI
	}
	symbol := strings.TrimSpace(p.Symbol)
	if symbol == "" {
		symbol = "BTC"
	}

	c := p.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: 12 * time.Second}
	}

	out := make(map[string]map[string]string, len(addresses))
	for _, addr := range addresses {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		sat, err := btcGetBalanceSats(ctx, c, base, addr)
		if err != nil {
			return nil, fmt.Errorf("query %s: %w", addr, err)
		}
		out[addr] = map[string]string{
			"SAT":  sat.String(),
			symbol: formatUnits(sat, 8),
		}
	}
	return out, nil
}

type blockstreamAddressResp struct {
	ChainStats struct {
		FundedTxoSum int64 `json:"funded_txo_sum"`
		SpentTxoSum  int64 `json:"spent_txo_sum"`
	} `json:"chain_stats"`
	MempoolStats struct {
		FundedTxoSum int64 `json:"funded_txo_sum"`
		SpentTxoSum  int64 `json:"spent_txo_sum"`
	} `json:"mempool_stats"`
}

func btcGetBalanceSats(ctx context.Context, c *http.Client, baseURL, address string) (*big.Int, error) {
	u := strings.TrimRight(baseURL, "/") + "/address/" + address
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var out blockstreamAddressResp
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}

	total := out.ChainStats.FundedTxoSum - out.ChainStats.SpentTxoSum +
		out.MempoolStats.FundedTxoSum - out.MempoolStats.SpentTxoSum
	return big.NewInt(total), nil
}
