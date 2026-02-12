package chainbalance

import "context"

// Provider 是“链上余额查询”的最小接口（与 docs/项目目录结构与模块接口.md 对齐）。
//
// 返回值约定：
// - address -> tokenSymbol -> amount(string)
// - amount 建议为可读字符串（例如 ETH）或精确整数（例如 WEI）。
//
// 当前实现优先覆盖 EVM 原生币余额（eth_getBalance），后续可扩展：
// - 多链（BTC/Tron/Solana 等）
// - Token（ERC20/721/1155）
// - 批量/并发/缓存与速率限制
// - 多数据源（RPC/Explorer/本地节点）
type Provider interface {
	QueryBalances(ctx context.Context, addresses []string) (map[string]map[string]string, error)
}
