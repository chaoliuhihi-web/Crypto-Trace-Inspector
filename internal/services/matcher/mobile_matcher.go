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

// MatchMobileArtifacts 基于移动端安装包证据执行钱包规则匹配。
func MatchMobileArtifacts(loaded *rules.LoadedRules, artifacts []model.Artifact) (*HostMatchResult, error) {
	packages, err := decodeMobilePackages(artifacts)
	if err != nil {
		return nil, err
	}

	agg := make(map[string]*hitAccumulator)
	artifactIDs := artifactIDsByType(artifacts, map[model.ArtifactType]struct{}{
		model.ArtifactMobilePackages: {},
	})
	now := time.Now().Unix()

	for _, wr := range loaded.Wallet.Wallets {
		if !wr.Enabled {
			continue
		}

		androidSet := toSet(wr.Mobile.AndroidPackages)
		iosSet := toSet(wr.Mobile.IOSBundleIDs)
		if len(androidSet) == 0 && len(iosSet) == 0 {
			continue
		}

		for _, pkg := range packages {
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

			addOrUpdateHit(agg, hitKey(string(model.HitWalletInstalled), wr.ID, p, string(pkg.OS)), model.RuleHit{
				ID:           id.New("hit"),
				CaseID:       firstCaseID(artifacts),
				DeviceID:     pkg.DeviceID,
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

func decodeMobilePackages(artifacts []model.Artifact) ([]model.MobilePackageRecord, error) {
	var out []model.MobilePackageRecord
	for _, a := range artifacts {
		if a.Type != model.ArtifactMobilePackages {
			continue
		}
		var rows []model.MobilePackageRecord
		if err := json.Unmarshal(a.PayloadJSON, &rows); err != nil {
			return nil, fmt.Errorf("decode mobile_packages payload: %w", err)
		}
		out = append(out, rows...)
	}
	return out, nil
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
