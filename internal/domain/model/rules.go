package model

// WalletRuleBundle 是钱包规则文件的顶层结构。
type WalletRuleBundle struct {
	Version     string            `yaml:"version"`
	BundleType  string            `yaml:"bundle_type"`
	Maintainer  string            `yaml:"maintainer"`
	Description string            `yaml:"description"`
	Meta        WalletBundleMeta  `yaml:"meta"`
	Wallets     []WalletSignature `yaml:"wallets"`
}

// WalletBundleMeta 保存钱包规则文件的全局元信息。
type WalletBundleMeta struct {
	ConfidenceDefaults WalletConfidence `yaml:"confidence_defaults"`
	Notes              []string         `yaml:"notes"`
}

// WalletSignature 定义一条钱包识别规则。
type WalletSignature struct {
	ID                string             `yaml:"id"`
	Enabled           bool               `yaml:"enabled"`
	Name              string             `yaml:"name"`
	Aliases           []string           `yaml:"aliases"`
	Categories        []string           `yaml:"categories"`
	Desktop           WalletDesktopHints `yaml:"desktop"`
	BrowserExtensions BrowserExtensions  `yaml:"browser_extensions"`
	Mobile            WalletMobileHints  `yaml:"mobile"`
	Confidence        WalletConfidence   `yaml:"confidence"`
}

// WalletDesktopHints 是桌面端钱包识别线索。
type WalletDesktopHints struct {
	AppKeywords         []string `yaml:"app_keywords"`
	FileKeywords        []string `yaml:"file_keywords"`
	InstallPathsWindows []string `yaml:"install_paths_windows"`
	InstallPathsMacOS   []string `yaml:"install_paths_macos"`
}

// BrowserExtensions 是浏览器扩展 ID 线索。
type BrowserExtensions struct {
	ChromeIDs  []string `yaml:"chrome_ids"`
	EdgeIDs    []string `yaml:"edge_ids"`
	FirefoxIDs []string `yaml:"firefox_ids"`
}

// WalletMobileHints 是移动端钱包识别线索。
type WalletMobileHints struct {
	AndroidPackages []string `yaml:"android_packages"`
	IOSBundleIDs    []string `yaml:"ios_bundle_ids"`
}

// WalletConfidence 定义钱包命中的置信度配置。
type WalletConfidence struct {
	DirectMatch  float64 `yaml:"direct_match"`
	KeywordMatch float64 `yaml:"keyword_match"`
	WeakHint     float64 `yaml:"weak_hint"`
}

// ExchangeRuleBundle 是交易所域名规则的顶层结构。
type ExchangeRuleBundle struct {
	Version     string           `yaml:"version"`
	BundleType  string           `yaml:"bundle_type"`
	Maintainer  string           `yaml:"maintainer"`
	Description string           `yaml:"description"`
	Meta        ExchangeMeta     `yaml:"meta"`
	Exchanges   []ExchangeDomain `yaml:"exchanges"`
}

// ExchangeMeta 保存交易所规则的全局元信息。
type ExchangeMeta struct {
	MatchModes         []string           `yaml:"match_modes"`
	ConfidenceDefaults ExchangeConfidence `yaml:"confidence_defaults"`
}

// ExchangeDomain 定义一条交易所识别规则。
type ExchangeDomain struct {
	ID           string             `yaml:"id"`
	Enabled      bool               `yaml:"enabled"`
	Name         string             `yaml:"name"`
	Aliases      []string           `yaml:"aliases"`
	Domains      []string           `yaml:"domains"`
	URLsContains []string           `yaml:"urls_contains"`
	Confidence   ExchangeConfidence `yaml:"confidence"`
}

// ExchangeConfidence 定义交易所命中的置信度配置。
type ExchangeConfidence struct {
	ExactDomain float64 `yaml:"exact_domain"`
	RootDomain  float64 `yaml:"root_domain"`
	URLContains float64 `yaml:"url_contains"`
}
