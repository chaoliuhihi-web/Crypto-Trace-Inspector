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

// DefaultPublicEVMRPC 是内部试用的默认公共 RPC（不保证长期可用）。
// 正式对外时建议改为“配置必填”，并支持私有节点。
const DefaultPublicEVMRPC = "https://cloudflare-eth.com"

// EVMProvider 使用 EVM JSON-RPC 查询原生币余额（eth_getBalance）。
type EVMProvider struct {
	RPCURL string
	Symbol string // 例如 ETH/BNB/MATIC

	HTTPClient *http.Client
}

func NewEVMProvider(rpcURL string) *EVMProvider {
	return &EVMProvider{RPCURL: strings.TrimSpace(rpcURL)}
}

func (p *EVMProvider) QueryBalances(ctx context.Context, addresses []string) (map[string]map[string]string, error) {
	rpcURL := strings.TrimSpace(p.RPCURL)
	if rpcURL == "" {
		return nil, fmt.Errorf("rpc_url is required")
	}
	symbol := strings.TrimSpace(p.Symbol)
	if symbol == "" {
		symbol = "ETH"
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

		wei, err := evmGetBalance(ctx, c, rpcURL, addr)
		if err != nil {
			return nil, fmt.Errorf("query %s: %w", addr, err)
		}

		out[addr] = map[string]string{
			"WEI": wei.String(),
			// 为了便于人读，这里同时给出 18 位小数的“ETH”格式；精确值请以 WEI 为准。
			symbol: formatEther18(wei),
		}
	}
	return out, nil
}

type evmRPCReq struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type evmRPCResp struct {
	JSONRPC string       `json:"jsonrpc"`
	ID      int          `json:"id"`
	Result  string       `json:"result,omitempty"`
	Error   *evmRPCError `json:"error,omitempty"`
}

type evmRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func evmGetBalance(ctx context.Context, c *http.Client, rpcURL string, address string) (*big.Int, error) {
	// 这里不做强校验（内部试用阶段），交给节点返回错误即可。
	reqBody := evmRPCReq{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "eth_getBalance",
		Params:  []any{address, "latest"},
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

	hex := strings.TrimSpace(out.Result)
	if hex == "" {
		return nil, fmt.Errorf("empty result")
	}
	hex = strings.TrimPrefix(hex, "0x")
	if hex == "" {
		return big.NewInt(0), nil
	}
	n := new(big.Int)
	if _, ok := n.SetString(hex, 16); !ok {
		return nil, fmt.Errorf("invalid hex: %s", out.Result)
	}
	return n, nil
}

func formatEther18(wei *big.Int) string {
	if wei == nil || wei.Sign() == 0 {
		return "0"
	}

	sign := ""
	w := new(big.Int).Set(wei)
	if w.Sign() < 0 {
		sign = "-"
		w.Abs(w)
	}

	denom := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	intPart := new(big.Int).Quo(w, denom)
	frac := new(big.Int).Mod(w, denom)

	if frac.Sign() == 0 {
		return sign + intPart.String()
	}

	fracStr := frac.Text(10)
	if len(fracStr) < 18 {
		fracStr = strings.Repeat("0", 18-len(fracStr)) + fracStr
	}
	fracStr = strings.TrimRight(fracStr, "0")
	return sign + intPart.String() + "." + fracStr
}
