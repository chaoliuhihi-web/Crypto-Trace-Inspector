package rules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"crypto-inspector/internal/domain/model"

	"gopkg.in/yaml.v3"
)

// Loader 负责从磁盘读取并校验规则文件。
type Loader struct {
	WalletFile   string
	ExchangeFile string
}

// LoadedRules 是加载后的规则集合和其文件哈希，用于留痕与版本确认。
type LoadedRules struct {
	Wallet         model.WalletRuleBundle
	WalletSHA256   string
	Exchange       model.ExchangeRuleBundle
	ExchangeSHA256 string
}

func NewLoader(walletFile, exchangeFile string) *Loader {
	return &Loader{WalletFile: walletFile, ExchangeFile: exchangeFile}
}

// Load 按顺序加载钱包规则与交易所规则，并执行基础结构校验。
func (l *Loader) Load(ctx context.Context) (*LoadedRules, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	walletRaw, err := os.ReadFile(l.WalletFile)
	if err != nil {
		return nil, fmt.Errorf("read wallet rules: %w", err)
	}

	var wallet model.WalletRuleBundle
	if err := yaml.Unmarshal(walletRaw, &wallet); err != nil {
		return nil, fmt.Errorf("parse wallet rules: %w", err)
	}
	if err := validateWalletRules(wallet); err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	exchangeRaw, err := os.ReadFile(l.ExchangeFile)
	if err != nil {
		return nil, fmt.Errorf("read exchange rules: %w", err)
	}

	var exchange model.ExchangeRuleBundle
	if err := yaml.Unmarshal(exchangeRaw, &exchange); err != nil {
		return nil, fmt.Errorf("parse exchange rules: %w", err)
	}
	if err := validateExchangeRules(exchange); err != nil {
		return nil, err
	}

	walletSum := sha256.Sum256(walletRaw)
	exchangeSum := sha256.Sum256(exchangeRaw)

	return &LoadedRules{
		Wallet:         wallet,
		WalletSHA256:   hex.EncodeToString(walletSum[:]),
		Exchange:       exchange,
		ExchangeSHA256: hex.EncodeToString(exchangeSum[:]),
	}, nil
}

// validateWalletRules 检查钱包规则的完整性与唯一性。
func validateWalletRules(bundle model.WalletRuleBundle) error {
	if strings.TrimSpace(bundle.Version) == "" {
		return errors.New("wallet rules: version is required")
	}
	if strings.TrimSpace(bundle.BundleType) == "" {
		return errors.New("wallet rules: bundle_type is required")
	}
	if len(bundle.Wallets) == 0 {
		return errors.New("wallet rules: wallets is empty")
	}

	seen := make(map[string]struct{}, len(bundle.Wallets))
	for _, w := range bundle.Wallets {
		id := strings.TrimSpace(w.ID)
		if id == "" {
			return errors.New("wallet rules: wallet id is required")
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("wallet rules: duplicate wallet id: %s", id)
		}
		seen[id] = struct{}{}

		if strings.TrimSpace(w.Name) == "" {
			return fmt.Errorf("wallet rules: wallet name is required: %s", id)
		}

		if !hasAnyWalletMatcher(w) {
			return fmt.Errorf("wallet rules: no matcher found for wallet: %s", id)
		}
	}

	return nil
}

// hasAnyWalletMatcher 确保每条钱包规则至少有一种可触发匹配的条件。
func hasAnyWalletMatcher(w model.WalletSignature) bool {
	return len(w.Desktop.AppKeywords) > 0 ||
		len(w.Desktop.FileKeywords) > 0 ||
		len(w.Desktop.InstallPathsWindows) > 0 ||
		len(w.Desktop.InstallPathsMacOS) > 0 ||
		len(w.BrowserExtensions.ChromeIDs) > 0 ||
		len(w.BrowserExtensions.EdgeIDs) > 0 ||
		len(w.BrowserExtensions.FirefoxIDs) > 0 ||
		len(w.Mobile.AndroidPackages) > 0 ||
		len(w.Mobile.IOSBundleIDs) > 0
}

// validateExchangeRules 检查交易所规则的完整性与唯一性。
func validateExchangeRules(bundle model.ExchangeRuleBundle) error {
	if strings.TrimSpace(bundle.Version) == "" {
		return errors.New("exchange rules: version is required")
	}
	if strings.TrimSpace(bundle.BundleType) == "" {
		return errors.New("exchange rules: bundle_type is required")
	}
	if len(bundle.Exchanges) == 0 {
		return errors.New("exchange rules: exchanges is empty")
	}

	seen := make(map[string]struct{}, len(bundle.Exchanges))
	for _, ex := range bundle.Exchanges {
		id := strings.TrimSpace(ex.ID)
		if id == "" {
			return errors.New("exchange rules: exchange id is required")
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("exchange rules: duplicate exchange id: %s", id)
		}
		seen[id] = struct{}{}

		if strings.TrimSpace(ex.Name) == "" {
			return fmt.Errorf("exchange rules: exchange name is required: %s", id)
		}
		if len(ex.Domains) == 0 && len(ex.URLsContains) == 0 {
			return fmt.Errorf("exchange rules: no matcher found for exchange: %s", id)
		}
	}

	return nil
}
