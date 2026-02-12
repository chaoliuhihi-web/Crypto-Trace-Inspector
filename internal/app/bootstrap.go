package app

// Config 存放应用级默认路径配置。
type Config struct {
	DBPath           string
	WalletRulePath   string
	ExchangeRulePath string
}

// DefaultConfig 返回本地开发环境的默认配置。
func DefaultConfig() Config {
	return Config{
		DBPath:           "data/inspector.db",
		WalletRulePath:   "rules/wallet_signatures.template.yaml",
		ExchangeRulePath: "rules/exchange_domains.template.yaml",
	}
}
