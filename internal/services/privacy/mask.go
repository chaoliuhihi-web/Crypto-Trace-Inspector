package privacy

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"crypto-inspector/internal/domain/model"
)

var (
	reEVMAddress  = regexp.MustCompile(`(?i)0x[0-9a-f]{40}`)
	reBTCBech32   = regexp.MustCompile(`(?i)bc1[ac-hj-np-z02-9]{25,87}`)
	reBTCBase58   = regexp.MustCompile(`[13][1-9A-HJ-NP-Za-km-z]{25,34}`)
	reURLSchemeRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://`)
)

// MaskSnapshotPath 用于把绝对路径压缩为“文件名”形式，避免在对外材料中暴露用户名/目录结构。
func MaskSnapshotPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	return filepath.Base(p)
}

// MaskRuleHitsForReport 对命中结果做“展示层脱敏”（不修改数据库原始记录）。
//
// 设计目标：
// - masked 模式用于对外分享/演示时隐藏敏感信息（URL 路径、地址、用户名路径等）
// - 取证链路的“原始证据快照”仍保留在 artifacts 中，可供授权人员下载复核
func MaskRuleHitsForReport(hits []model.RuleHit) []model.RuleHit {
	if len(hits) == 0 {
		return nil
	}

	out := make([]model.RuleHit, 0, len(hits))
	for _, h := range hits {
		hh := h // copy

		// matched_value 脱敏
		switch hh.Type {
		case model.HitWalletAddress:
			hh.MatchedValue = MaskAddress(hh.MatchedValue)
			hh.DetailJSON = maskDetailJSONForWalletAddress(hh.DetailJSON)
		case model.HitTokenBalance:
			hh.MatchedValue = maskTokenBalanceMatchedValue(hh.MatchedValue)
			hh.DetailJSON = maskDetailJSONForTokenBalance(hh.DetailJSON)
		case model.HitExchangeVisited:
			hh.DetailJSON = maskDetailJSONForExchangeVisited(hh.DetailJSON)
		case model.HitWalletInstalled:
			hh.DetailJSON = maskDetailJSONForWalletInstalled(hh.DetailJSON)
		default:
			// 其他类型：保持原样
		}

		out = append(out, hh)
	}
	return out
}

func maskTokenBalanceMatchedValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return v
	}
	// 格式：addr|symbol（见 webapp/chain.go）
	parts := strings.Split(v, "|")
	if len(parts) == 0 {
		return MaskAddress(v)
	}
	addr := strings.TrimSpace(parts[0])
	if addr == "" {
		return v
	}
	parts[0] = MaskAddress(addr)
	return strings.Join(parts, "|")
}

func maskDetailJSONForExchangeVisited(raw []byte) []byte {
	if len(raw) == 0 {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	if v, ok := m["url"].(string); ok {
		m["url"] = MaskURL(v)
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

func maskDetailJSONForWalletInstalled(raw []byte) []byte {
	if len(raw) == 0 {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	for _, k := range []string{"install_path", "path", "origin_path"} {
		if v, ok := m[k].(string); ok {
			m[k] = MaskSnapshotPath(v)
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

func maskDetailJSONForWalletAddress(raw []byte) []byte {
	if len(raw) == 0 {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	// sample 可能包含完整 URL/地址片段，直接替换为占位。
	if _, ok := m["sample"]; ok {
		m["sample"] = "<masked>"
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

func maskDetailJSONForTokenBalance(raw []byte) []byte {
	if len(raw) == 0 {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	if v, ok := m["address"].(string); ok {
		m["address"] = MaskAddress(v)
	}
	// query.addresses 可能包含原始地址列表
	if q, ok := m["query"].(map[string]any); ok {
		if addrs, ok := q["addresses"].([]any); ok {
			out := make([]any, 0, len(addrs))
			for _, a := range addrs {
				if s, ok := a.(string); ok {
					out = append(out, MaskAddress(s))
				} else {
					out = append(out, a)
				}
			}
			q["addresses"] = out
			m["query"] = q
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

// MaskAddress 对常见钱包地址做“部分展示”：
// - 0x... / bc1... / 1... / 3... 等：保留头尾，隐藏中间
// - 非地址：直接返回 "<masked>"
func MaskAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	// 兼容 token_balance 这类 "addr|symbol" 的传入
	if strings.Contains(addr, "|") {
		return maskTokenBalanceMatchedValue(addr)
	}
	if !looksLikeAddress(addr) {
		return "<masked>"
	}
	if len(addr) <= 14 {
		return addr[:2] + "..." // 太短就不保留尾巴，避免泄露过多
	}
	return addr[:6] + "..." + addr[len(addr)-4:]
}

func looksLikeAddress(s string) bool {
	s = strings.TrimSpace(s)
	return reEVMAddress.MatchString(s) || reBTCBech32.MatchString(s) || reBTCBase58.MatchString(s)
}

// MaskURL 把 URL 降级为“仅保留域名”的形式，避免泄露路径/参数。
// 输入不是合法 URL 时，返回 "<masked_url>"。
func MaskURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// 对于不带 scheme 的，补一个 https:// 便于 url.Parse。
	if !reURLSchemeRE.MatchString(raw) {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "<masked_url>"
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return "<masked_url>"
	}
	return host
}
