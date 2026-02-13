package chainbalance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// ERC20Provider 使用 eth_call 查询 ERC20 余额（balanceOf）。
//
// 说明：
// - 该实现仅覆盖最常见的 balanceOf(address)->uint256，不做 ABI 泛化。
// - 返回同时包含：<SYMBOL>（按 decimals 格式化）与 <SYMBOL>_RAW（原始整数）。
type ERC20Provider struct {
	RPCURL     string
	Symbol     string // 例如 USDT/USDC
	Contract   string // token 合约地址
	Decimals   int    // 例如 USDT=6，USDC=6，DAI=18
	HTTPClient *http.Client
}

func NewERC20Provider(rpcURL string) *ERC20Provider {
	return &ERC20Provider{RPCURL: strings.TrimSpace(rpcURL)}
}

func (p *ERC20Provider) QueryBalances(ctx context.Context, addresses []string) (map[string]map[string]string, error) {
	rpcURL := strings.TrimSpace(p.RPCURL)
	if rpcURL == "" {
		return nil, fmt.Errorf("rpc_url is required")
	}
	symbol := strings.TrimSpace(p.Symbol)
	if symbol == "" {
		symbol = "TOKEN"
	}
	contract := strings.TrimSpace(p.Contract)
	if contract == "" {
		return nil, fmt.Errorf("contract is required")
	}
	decimals := p.Decimals
	if decimals < 0 {
		decimals = 0
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
		n, err := evmERC20BalanceOf(ctx, c, rpcURL, contract, addr)
		if err != nil {
			return nil, fmt.Errorf("query %s: %w", addr, err)
		}
		out[addr] = map[string]string{
			symbol + "_RAW": n.String(),
			symbol:          formatUnits(n, decimals),
		}
	}
	return out, nil
}

func evmERC20BalanceOf(ctx context.Context, c *http.Client, rpcURL, contract, holder string) (*big.Int, error) {
	data, err := encodeERC20BalanceOf(holder)
	if err != nil {
		return nil, err
	}

	reqBody := evmRPCReq{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "eth_call",
		Params: []any{
			map[string]any{
				"to":   contract,
				"data": data,
			},
			"latest",
		},
	}
	raw, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

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
		return nil, fmt.Errorf("rpc http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var out evmRPCResp
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("decode rpc json: %w", err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", out.Error.Code, out.Error.Message)
	}

	hexVal := strings.TrimSpace(out.Result)
	if hexVal == "" {
		return nil, fmt.Errorf("empty result")
	}
	hexVal = strings.TrimPrefix(hexVal, "0x")
	if hexVal == "" {
		return big.NewInt(0), nil
	}
	n := new(big.Int)
	if _, ok := n.SetString(hexVal, 16); !ok {
		return nil, fmt.Errorf("invalid hex: %s", out.Result)
	}
	return n, nil
}

// encodeERC20BalanceOf 生成 balanceOf(address) 的 calldata：
// selector(4B)=0x70a08231 + holder(32B 左填充)
func encodeERC20BalanceOf(holder string) (string, error) {
	h := strings.TrimSpace(strings.ToLower(holder))
	h = strings.TrimPrefix(h, "0x")
	if len(h) != 40 {
		return "", fmt.Errorf("invalid holder address length: %d", len(h))
	}
	// 简单校验：必须是 hex
	for _, ch := range h {
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') {
			continue
		}
		return "", fmt.Errorf("invalid holder address hex: %s", holder)
	}
	return "0x70a08231" + strings.Repeat("0", 64-40) + h, nil
}

// formatUnits 把整数按 decimals 输出为可读小数字符串。
// decimals=0 则直接输出整数。
func formatUnits(n *big.Int, decimals int) string {
	if n == nil || n.Sign() == 0 {
		return "0"
	}
	if decimals <= 0 {
		return n.String()
	}

	sign := ""
	x := new(big.Int).Set(n)
	if x.Sign() < 0 {
		sign = "-"
		x.Abs(x)
	}

	denom := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	intPart := new(big.Int).Quo(x, denom)
	frac := new(big.Int).Mod(x, denom)
	if frac.Sign() == 0 {
		return sign + intPart.String()
	}

	fracStr := frac.Text(10)
	if len(fracStr) < decimals {
		fracStr = strings.Repeat("0", decimals-len(fracStr)) + fracStr
	}
	fracStr = strings.TrimRight(fracStr, "0")
	return sign + intPart.String() + "." + fracStr
}
