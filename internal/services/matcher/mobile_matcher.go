package matcher

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"crypto-inspector/internal/adapters/rules"
	"crypto-inspector/internal/domain/model"
	"crypto-inspector/internal/platform/id"
)

// MatchMobileArtifacts 基于移动端证据执行规则匹配：
// - mobile_packages：钱包安装/APP 线索
// - browser_history（如果存在）：交易所访问、地址抽取
func MatchMobileArtifacts(loaded *rules.LoadedRules, artifacts []model.Artifact) (*HostMatchResult, error) {
	pkgsByDev, pkgArtifactIDsByDev, err := decodeMobilePackagesByDevice(artifacts)
	if err != nil {
		return nil, err
	}

	agg := make(map[string]*hitAccumulator)
	now := time.Now().Unix()
	caseID := firstCaseID(artifacts)

	for _, wr := range loaded.Wallet.Wallets {
		if !wr.Enabled {
			continue
		}

		androidSet := toSet(wr.Mobile.AndroidPackages)
		iosSet := toSet(wr.Mobile.IOSBundleIDs)
		if len(androidSet) == 0 && len(iosSet) == 0 {
			continue
		}

		// 注意：移动端可能同时连接多台设备，因此 key 必须包含 device_id，
		// 关联证据也必须按 device 粒度绑定（避免“跨设备串证据”）。
		for deviceID, rows := range pkgsByDev {
			artifactIDs := pkgArtifactIDsByDev[deviceID]
			for _, pkg := range rows {
				p := strings.ToLower(strings.TrimSpace(pkg.Package))
				if p == "" {
					continue
				}

				matchField := ""
				switch pkg.OS {
				case model.OSAndroid:
					if _, ok := androidSet[p]; ok {
						matchField = "android_package"
					}
				case model.OSIOS:
					if _, ok := iosSet[p]; ok {
						matchField = "ios_bundle_id"
					}
				}
				if matchField == "" {
					continue
				}

				conf := walletConf(wr.Confidence.DirectMatch, loaded.Wallet.Meta.ConfidenceDefaults.DirectMatch, 0.95)
				verdict := "suspected"
				if conf >= 0.85 {
					verdict = "confirmed"
				}

				addOrUpdateHit(agg, hitKey(string(model.HitWalletInstalled), deviceID, wr.ID, p, string(pkg.OS)), model.RuleHit{
					ID:           id.New("hit"),
					CaseID:       caseID,
					DeviceID:     deviceID,
					Type:         model.HitWalletInstalled,
					RuleID:       wr.ID,
					RuleName:     wr.Name,
					RuleVersion:  loaded.Wallet.Version,
					MatchedValue: p,
					FirstSeenAt:  now,
					LastSeenAt:   now,
					Confidence:   conf,
					Verdict:      verdict,
					DetailJSON: mustJSON(map[string]any{
						"match_field": matchField,
						"os":          pkg.OS,
						"identifier":  pkg.Identifier,
					}),
					ArtifactIDs: artifactIDs,
				})
			}
		}
	}

	// 移动端浏览历史（如果采集器提供）：用于交易所访问 + 地址抽取。
	visitsByDev, historyArtifactIDsByDev, err := decodeBrowserHistoryByDevice(artifacts)
	if err != nil {
		return nil, err
	}
	for deviceID, visits := range visitsByDev {
		if len(visits) == 0 {
			continue
		}
		// 只传入当前设备的 browser_history artifacts（保证 firstDeviceID/关联证据正确）。
		var devArts []model.Artifact
		for _, a := range artifacts {
			if a.DeviceID != deviceID {
				continue
			}
			if a.Type != model.ArtifactBrowserHistory {
				continue
			}
			devArts = append(devArts, a)
		}
		// 兜底：如果 artifacts 未携带该 device 的 browser_history（理论上不该发生），
		// 仍然用 artifactIDs 作为关联证据集合。
		if len(devArts) == 0 && len(historyArtifactIDsByDev[deviceID]) > 0 {
			for _, aid := range historyArtifactIDsByDev[deviceID] {
				devArts = append(devArts, model.Artifact{
					ID:       aid,
					CaseID:   caseID,
					DeviceID: deviceID,
					Type:     model.ArtifactBrowserHistory,
				})
			}
		}

		matchExchanges(loaded, visits, devArts, agg)
		matchWalletAddresses(visits, devArts, agg)
	}

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

func decodeMobilePackagesByDevice(artifacts []model.Artifact) (map[string][]model.MobilePackageRecord, map[string][]string, error) {
	pkgsByDev := map[string][]model.MobilePackageRecord{}
	artIDsByDev := map[string][]string{}
	for _, a := range artifacts {
		if a.Type != model.ArtifactMobilePackages {
			continue
		}
		var rows []model.MobilePackageRecord
		if err := json.Unmarshal(a.PayloadJSON, &rows); err != nil {
			return nil, nil, fmt.Errorf("decode mobile_packages payload: %w", err)
		}
		pkgsByDev[a.DeviceID] = append(pkgsByDev[a.DeviceID], rows...)
		artIDsByDev[a.DeviceID] = append(artIDsByDev[a.DeviceID], a.ID)
	}
	return pkgsByDev, artIDsByDev, nil
}

func decodeBrowserHistoryByDevice(artifacts []model.Artifact) (map[string][]model.VisitRecord, map[string][]string, error) {
	visitsByDev := map[string][]model.VisitRecord{}
	artIDsByDev := map[string][]string{}
	for _, a := range artifacts {
		if a.Type != model.ArtifactBrowserHistory {
			continue
		}
		var rows []model.VisitRecord
		if err := json.Unmarshal(a.PayloadJSON, &rows); err != nil {
			return nil, nil, fmt.Errorf("decode browser_history payload: %w", err)
		}
		visitsByDev[a.DeviceID] = append(visitsByDev[a.DeviceID], rows...)
		artIDsByDev[a.DeviceID] = append(artIDsByDev[a.DeviceID], a.ID)
	}
	return visitsByDev, artIDsByDev, nil
}

func toSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		set[item] = struct{}{}
	}
	return set
}
