package matcher

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"crypto-inspector/internal/adapters/rules"
	"crypto-inspector/internal/domain/model"
	"crypto-inspector/internal/platform/id"
)

// HostMatchResult 表示主机证据匹配后的命中集合。
type HostMatchResult struct {
	Hits []model.RuleHit
}

// MatchHostArtifacts 是主机匹配入口：
// - 先按证据类型反序列化
// - 再分别执行钱包命中、交易所命中
// - 最后聚合去重
func MatchHostArtifacts(loaded *rules.LoadedRules, artifacts []model.Artifact) (*HostMatchResult, error) {
	apps, extensions, visits, err := decodeArtifacts(artifacts)
	if err != nil {
		return nil, err
	}

	agg := make(map[string]*hitAccumulator)

	matchWallets(loaded, apps, extensions, artifacts, agg)
	matchExchanges(loaded, visits, artifacts, agg)
	matchWalletAddresses(visits, artifacts, agg)

	hits := make([]model.RuleHit, 0, len(agg))
	for _, a := range agg {
		a.hit.ArtifactIDs = setToSortedSlice(a.artifactSet)
		hits = append(hits, a.hit)
	}

	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Type == hits[j].Type {
			return hits[i].MatchedValue < hits[j].MatchedValue
		}
		return hits[i].Type < hits[j].Type
	})

	return &HostMatchResult{Hits: hits}, nil
}

var (
	reEVMAddress = regexp.MustCompile(`(?i)0x[0-9a-f]{40}`)
	// bech32: bc1q... / bc1p...（长度保守一些，避免误报）
	reBTCBech32 = regexp.MustCompile(`(?i)bc1[ac-hj-np-z02-9]{25,87}`)
	// base58: 1... / 3...（不含 0,O,I,l）
	reBTCBase58 = regexp.MustCompile(`[13][1-9A-HJ-NP-Za-km-z]{25,34}`)
)

// matchWalletAddresses 从浏览历史中抽取“疑似钱包地址”并固化为命中。
//
// 说明：
// - 这里不是“规则库命中”，而是基于正则的地址抽取（内测阶段用于提高线索覆盖）。
// - 抽取到地址 ≠ 证明地址归属，只表示在设备浏览痕迹中出现过该地址（需要人工复核上下文）。
func matchWalletAddresses(visits []model.VisitRecord, artifacts []model.Artifact, agg map[string]*hitAccumulator) {
	if len(visits) == 0 {
		return
	}
	artifactIDs := artifactIDsByType(artifacts, map[model.ArtifactType]struct{}{
		model.ArtifactBrowserHistory: {},
	})
	now := time.Now().Unix()

	for _, v := range visits {
		first := v.VisitedAt
		if first <= 0 {
			first = now
		}

		sources := []struct {
			Field string
			Text  string
		}{
			{Field: "url", Text: v.URL},
			{Field: "title", Text: v.Title},
		}
		for _, src := range sources {
			text := src.Text
			if strings.TrimSpace(text) == "" {
				continue
			}

			// EVM 0x... 地址
			for _, m := range reEVMAddress.FindAllString(text, -1) {
				addr := strings.ToLower(strings.TrimSpace(m))
				ruleID := "address_regex_evm"
				addOrUpdateHit(agg, hitKey(string(model.HitWalletAddress), firstDeviceID(artifacts), ruleID, addr), model.RuleHit{
					ID:           id.New("hit"),
					CaseID:       firstCaseID(artifacts),
					DeviceID:     firstDeviceID(artifacts),
					Type:         model.HitWalletAddress,
					RuleID:       ruleID,
					RuleName:     "钱包地址抽取(EVM)",
					RuleVersion:  "builtin-0.1.0",
					MatchedValue: addr,
					FirstSeenAt:  first,
					LastSeenAt:   first,
					Confidence:   0.80,
					Verdict:      "suspected",
					DetailJSON: mustJSON(map[string]any{
						"chain":       "evm",
						"match_field": src.Field,
						"browser":     v.Browser,
						"profile":     v.Profile,
						"visited_at":  v.VisitedAt,
						"sample":      truncateText(text, 240),
					}),
					ArtifactIDs: artifactIDs,
				})
			}

			// BTC bech32
			for _, m := range reBTCBech32.FindAllString(text, -1) {
				addr := strings.ToLower(strings.TrimSpace(m))
				ruleID := "address_regex_btc_bech32"
				addOrUpdateHit(agg, hitKey(string(model.HitWalletAddress), firstDeviceID(artifacts), ruleID, addr), model.RuleHit{
					ID:           id.New("hit"),
					CaseID:       firstCaseID(artifacts),
					DeviceID:     firstDeviceID(artifacts),
					Type:         model.HitWalletAddress,
					RuleID:       ruleID,
					RuleName:     "钱包地址抽取(BTC bech32)",
					RuleVersion:  "builtin-0.1.0",
					MatchedValue: addr,
					FirstSeenAt:  first,
					LastSeenAt:   first,
					Confidence:   0.85,
					Verdict:      "suspected",
					DetailJSON: mustJSON(map[string]any{
						"chain":       "btc",
						"format":      "bech32",
						"match_field": src.Field,
						"browser":     v.Browser,
						"profile":     v.Profile,
						"visited_at":  v.VisitedAt,
						"sample":      truncateText(text, 240),
					}),
					ArtifactIDs: artifactIDs,
				})
			}

			// BTC base58
			for _, pos := range reBTCBase58.FindAllStringIndex(text, -1) {
				if len(pos) != 2 {
					continue
				}
				start, end := pos[0], pos[1]
				if start < 0 || end < 0 || start >= end || end > len(text) {
					continue
				}
				// 防止把 bech32（bc1...）内部的 "1..." 误识别为 base58 地址：
				// - base58 地址前后不应再紧贴 base58 字符，否则更像是“更长字符串的一部分”。
				if start > 0 && isBTCBase58Char(text[start-1]) {
					continue
				}
				if end < len(text) && isBTCBase58Char(text[end]) {
					continue
				}

				addr := strings.TrimSpace(text[start:end])
				ruleID := "address_regex_btc_base58"
				addOrUpdateHit(agg, hitKey(string(model.HitWalletAddress), firstDeviceID(artifacts), ruleID, addr), model.RuleHit{
					ID:           id.New("hit"),
					CaseID:       firstCaseID(artifacts),
					DeviceID:     firstDeviceID(artifacts),
					Type:         model.HitWalletAddress,
					RuleID:       ruleID,
					RuleName:     "钱包地址抽取(BTC base58)",
					RuleVersion:  "builtin-0.1.0",
					MatchedValue: addr,
					FirstSeenAt:  first,
					LastSeenAt:   first,
					Confidence:   0.80,
					Verdict:      "suspected",
					DetailJSON: mustJSON(map[string]any{
						"chain":       "btc",
						"format":      "base58",
						"match_field": src.Field,
						"browser":     v.Browser,
						"profile":     v.Profile,
						"visited_at":  v.VisitedAt,
						"sample":      truncateText(text, 240),
					}),
					ArtifactIDs: artifactIDs,
				})
			}
		}
	}
}

func isBTCBase58Char(b byte) bool {
	switch {
	case b >= '1' && b <= '9':
		return true
	case b >= 'A' && b <= 'H':
		return true
	case b >= 'J' && b <= 'N':
		return true
	case b >= 'P' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'k':
		return true
	case b >= 'm' && b <= 'z':
		return true
	default:
		return false
	}
}

func truncateText(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// hitAccumulator 用于把同一规则的多次命中合并成一条记录。
type hitAccumulator struct {
	hit         model.RuleHit
	artifactSet map[string]struct{}
}

// decodeArtifacts 将统一 Artifact 还原为结构化业务记录。
func decodeArtifacts(artifacts []model.Artifact) (apps []model.AppRecord, extensions []model.ExtensionRecord, visits []model.VisitRecord, err error) {
	for _, a := range artifacts {
		switch a.Type {
		case model.ArtifactInstalledApps:
			var rows []model.AppRecord
			if err := json.Unmarshal(a.PayloadJSON, &rows); err != nil {
				return nil, nil, nil, fmt.Errorf("decode installed_apps payload: %w", err)
			}
			apps = append(apps, rows...)
		case model.ArtifactBrowserExt:
			var rows []model.ExtensionRecord
			if err := json.Unmarshal(a.PayloadJSON, &rows); err != nil {
				return nil, nil, nil, fmt.Errorf("decode browser_extension payload: %w", err)
			}
			extensions = append(extensions, rows...)
		case model.ArtifactBrowserHistory:
			var rows []model.VisitRecord
			if err := json.Unmarshal(a.PayloadJSON, &rows); err != nil {
				return nil, nil, nil, fmt.Errorf("decode browser_history payload: %w", err)
			}
			visits = append(visits, rows...)
		}
	}

	return apps, extensions, visits, nil
}

// matchWallets 匹配两类钱包线索：
// 1) 浏览器扩展 ID（高置信）
// 2) 应用名/路径关键词（中置信）
func matchWallets(loaded *rules.LoadedRules, apps []model.AppRecord, extensions []model.ExtensionRecord, artifacts []model.Artifact, agg map[string]*hitAccumulator) {
	artifactIDs := artifactIDsByType(artifacts, map[model.ArtifactType]struct{}{
		model.ArtifactInstalledApps: {},
		model.ArtifactBrowserExt:    {},
	})

	for _, wr := range loaded.Wallet.Wallets {
		if !wr.Enabled {
			continue
		}

		extSet := make(map[string]struct{})
		for _, id := range wr.BrowserExtensions.ChromeIDs {
			extSet[strings.ToLower(strings.TrimSpace(id))] = struct{}{}
		}
		for _, id := range wr.BrowserExtensions.EdgeIDs {
			extSet[strings.ToLower(strings.TrimSpace(id))] = struct{}{}
		}
		for _, id := range wr.BrowserExtensions.FirefoxIDs {
			extSet[strings.ToLower(strings.TrimSpace(id))] = struct{}{}
		}

		for _, ex := range extensions {
			eid := strings.ToLower(strings.TrimSpace(ex.ExtensionID))
			if eid == "" {
				continue
			}
			if _, ok := extSet[eid]; !ok {
				continue
			}

			addOrUpdateHit(agg, hitKey(string(model.HitWalletInstalled), wr.ID, eid), model.RuleHit{
				ID:           id.New("hit"),
				CaseID:       firstCaseID(artifacts),
				DeviceID:     firstDeviceID(artifacts),
				Type:         model.HitWalletInstalled,
				RuleID:       wr.ID,
				RuleName:     wr.Name,
				RuleVersion:  loaded.Wallet.Version,
				MatchedValue: eid,
				FirstSeenAt:  time.Now().Unix(),
				LastSeenAt:   time.Now().Unix(),
				Confidence:   walletConf(wr.Confidence.DirectMatch, loaded.Wallet.Meta.ConfidenceDefaults.DirectMatch, 0.95),
				Verdict:      "confirmed",
				DetailJSON: mustJSON(map[string]any{
					"match_field": "browser_extension_id",
					"browser":     ex.Browser,
					"profile":     ex.Profile,
				}),
				ArtifactIDs: artifactIDs,
			})
		}

		keywords := normalizedKeywords(wr)
		if len(keywords) == 0 {
			continue
		}

		for _, app := range apps {
			searchBase := strings.ToLower(strings.Join([]string{app.Name, app.InstallLocation, app.Path}, " "))
			if searchBase == "" {
				continue
			}

			matchedKeyword := ""
			for _, kw := range keywords {
				if kw == "" {
					continue
				}
				if strings.Contains(searchBase, kw) {
					matchedKeyword = kw
					break
				}
			}
			if matchedKeyword == "" {
				continue
			}

			matchedValue := strings.TrimSpace(app.Name)
			if matchedValue == "" {
				matchedValue = matchedKeyword
			}
			conf := walletConf(wr.Confidence.KeywordMatch, loaded.Wallet.Meta.ConfidenceDefaults.KeywordMatch, 0.7)
			verdict := "suspected"
			if conf >= 0.85 {
				verdict = "confirmed"
			}

			addOrUpdateHit(agg, hitKey(string(model.HitWalletInstalled), wr.ID, matchedValue), model.RuleHit{
				ID:           id.New("hit"),
				CaseID:       firstCaseID(artifacts),
				DeviceID:     firstDeviceID(artifacts),
				Type:         model.HitWalletInstalled,
				RuleID:       wr.ID,
				RuleName:     wr.Name,
				RuleVersion:  loaded.Wallet.Version,
				MatchedValue: matchedValue,
				FirstSeenAt:  time.Now().Unix(),
				LastSeenAt:   time.Now().Unix(),
				Confidence:   conf,
				Verdict:      verdict,
				DetailJSON: mustJSON(map[string]any{
					"match_field":     "app_keyword",
					"matched_keyword": matchedKeyword,
					"install_path":    app.InstallLocation,
				}),
				ArtifactIDs: artifactIDs,
			})
		}
	}
}

// matchExchanges 基于浏览历史匹配交易所域名与 URL 关键词。
func matchExchanges(loaded *rules.LoadedRules, visits []model.VisitRecord, artifacts []model.Artifact, agg map[string]*hitAccumulator) {
	if len(visits) == 0 {
		return
	}
	artifactIDs := artifactIDsByType(artifacts, map[model.ArtifactType]struct{}{
		model.ArtifactBrowserHistory: {},
	})

	for _, exr := range loaded.Exchange.Exchanges {
		if !exr.Enabled {
			continue
		}

		targets := make([]string, 0, len(exr.Domains))
		for _, d := range exr.Domains {
			n := normalizeDomain(d)
			if n != "" {
				targets = append(targets, n)
			}
		}
		contains := make([]string, 0, len(exr.URLsContains))
		for _, c := range exr.URLsContains {
			c = strings.ToLower(strings.TrimSpace(c))
			if c != "" {
				contains = append(contains, c)
			}
		}

		for _, v := range visits {
			domain := normalizeDomain(v.Domain)
			if domain == "" {
				continue
			}

			matchMode := ""
			confidence := 0.0
			for _, t := range targets {
				if domain == t {
					matchMode = "exact_domain"
					confidence = exchangeConf(exr.Confidence.ExactDomain, loaded.Exchange.Meta.ConfidenceDefaults.ExactDomain, 0.95)
					break
				}
				if strings.HasSuffix(domain, "."+t) {
					matchMode = "root_domain"
					confidence = exchangeConf(exr.Confidence.RootDomain, loaded.Exchange.Meta.ConfidenceDefaults.RootDomain, 0.90)
					break
				}
			}

			if matchMode == "" {
				urlLower := strings.ToLower(v.URL)
				for _, token := range contains {
					if strings.Contains(urlLower, token) {
						matchMode = "url_contains"
						confidence = exchangeConf(exr.Confidence.URLContains, loaded.Exchange.Meta.ConfidenceDefaults.URLContains, 0.70)
						break
					}
				}
			}

			if matchMode == "" {
				continue
			}

			verdict := "suspected"
			if confidence >= 0.85 {
				verdict = "confirmed"
			}
			first := v.VisitedAt
			if first <= 0 {
				first = time.Now().Unix()
			}

			addOrUpdateHit(agg, hitKey(string(model.HitExchangeVisited), firstDeviceID(artifacts), exr.ID, domain), model.RuleHit{
				ID:           id.New("hit"),
				CaseID:       firstCaseID(artifacts),
				DeviceID:     firstDeviceID(artifacts),
				Type:         model.HitExchangeVisited,
				RuleID:       exr.ID,
				RuleName:     exr.Name,
				RuleVersion:  loaded.Exchange.Version,
				MatchedValue: domain,
				FirstSeenAt:  first,
				LastSeenAt:   first,
				Confidence:   confidence,
				Verdict:      verdict,
				DetailJSON: mustJSON(map[string]any{
					"match_mode": matchMode,
					"browser":    v.Browser,
					"profile":    v.Profile,
					"url":        v.URL,
				}),
				ArtifactIDs: artifactIDs,
			})
		}
	}
}

// normalizedKeywords 统一钱包关键词大小写与空白，减少匹配误差。
func normalizedKeywords(w model.WalletSignature) []string {
	var out []string
	for _, s := range w.Desktop.AppKeywords {
		out = append(out, strings.ToLower(strings.TrimSpace(s)))
	}
	for _, s := range w.Desktop.FileKeywords {
		out = append(out, strings.ToLower(strings.TrimSpace(s)))
	}
	for _, s := range w.Aliases {
		out = append(out, strings.ToLower(strings.TrimSpace(s)))
	}
	return out
}

// walletConf 按 “规则值 > 全局默认 > 兜底值” 选择最终置信度。
func walletConf(primary, fallback, def float64) float64 {
	if primary > 0 {
		return primary
	}
	if fallback > 0 {
		return fallback
	}
	return def
}

// exchangeConf 按 “规则值 > 全局默认 > 兜底值” 选择最终置信度。
func exchangeConf(primary, fallback, def float64) float64 {
	if primary > 0 {
		return primary
	}
	if fallback > 0 {
		return fallback
	}
	return def
}

// addOrUpdateHit 用于聚合命中：
// - 更新最早/最晚命中时间
// - 保留更高置信度的细节
// - 合并关联证据 ID
func addOrUpdateHit(agg map[string]*hitAccumulator, key string, hit model.RuleHit) {
	if cur, ok := agg[key]; ok {
		if hit.FirstSeenAt > 0 && (cur.hit.FirstSeenAt == 0 || hit.FirstSeenAt < cur.hit.FirstSeenAt) {
			cur.hit.FirstSeenAt = hit.FirstSeenAt
		}
		if hit.LastSeenAt > cur.hit.LastSeenAt {
			cur.hit.LastSeenAt = hit.LastSeenAt
		}
		if hit.Confidence > cur.hit.Confidence {
			cur.hit.Confidence = hit.Confidence
			cur.hit.Verdict = hit.Verdict
			cur.hit.DetailJSON = hit.DetailJSON
		}
		for _, a := range hit.ArtifactIDs {
			cur.artifactSet[a] = struct{}{}
		}
		return
	}

	set := make(map[string]struct{}, len(hit.ArtifactIDs))
	for _, a := range hit.ArtifactIDs {
		set[a] = struct{}{}
	}
	agg[key] = &hitAccumulator{hit: hit, artifactSet: set}
}

// setToSortedSlice 将集合输出为稳定有序切片，方便比对与测试。
func setToSortedSlice(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// hitKey 生成命中聚合键，避免大小写差异导致重复。
func hitKey(parts ...string) string {
	for i := range parts {
		parts[i] = strings.ToLower(strings.TrimSpace(parts[i]))
	}
	return strings.Join(parts, "|")
}

// normalizeDomain 用于域名匹配前预处理。
func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "www.")
	return d
}

// firstCaseID 从证据列表中提取 caseID（默认所有 artifact 属于同一案件）。
func firstCaseID(artifacts []model.Artifact) string {
	for _, a := range artifacts {
		if a.CaseID != "" {
			return a.CaseID
		}
	}
	return ""
}

// firstDeviceID 从证据列表中提取 deviceID。
func firstDeviceID(artifacts []model.Artifact) string {
	for _, a := range artifacts {
		if a.DeviceID != "" {
			return a.DeviceID
		}
	}
	return ""
}

// artifactIDsByType 过滤出指定证据类型对应的 artifact ID。
func artifactIDsByType(artifacts []model.Artifact, types map[model.ArtifactType]struct{}) []string {
	var out []string
	for _, a := range artifacts {
		if _, ok := types[a.Type]; ok {
			out = append(out, a.ID)
		}
	}
	return out
}

// mustJSON 保证 detail_json 至少为合法 JSON。
func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return raw
}
