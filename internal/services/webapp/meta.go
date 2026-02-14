package webapp

import (
	"net/http"
	"time"

	"crypto-inspector/internal/adapters/rules"
	"crypto-inspector/internal/app"
	"crypto-inspector/internal/domain/model"
)

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	schemaVersion, _ := s.store.GetSchemaMetaValue(r.Context(), "schema_version")
	schemaName, _ := s.store.GetSchemaMetaValue(r.Context(), "schema_name")

	walletPath, exchangePath := s.activeRulePaths(r.Context())
	loader := rules.NewLoader(walletPath, exchangePath)
	loaded, err := loader.Load(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"time": time.Now().Unix(),
		"app": map[string]any{
			"version":    app.Version,
			"commit":     app.Commit,
			"build_time": app.BuildTime,
		},
		"db": map[string]any{
			"schema_version": schemaVersion,
			"schema_name":    schemaName,
			"path":           s.opts.DBPath,
		},
		"rules": map[string]any{
			"wallet": map[string]any{
				"path":    walletPath,
				"version": loaded.Wallet.Version,
				"total":   len(loaded.Wallet.Wallets),
				"enabled": countEnabledWallets(loaded.Wallet.Wallets),
				"sha256":  loaded.WalletSHA256,
			},
			"exchange": map[string]any{
				"path":    exchangePath,
				"version": loaded.Exchange.Version,
				"total":   len(loaded.Exchange.Exchanges),
				"enabled": countEnabledExchanges(loaded.Exchange.Exchanges),
				"sha256":  loaded.ExchangeSHA256,
			},
		},
	})
}

func countEnabledWallets(wallets []model.WalletSignature) int {
	total := 0
	for _, w := range wallets {
		if w.Enabled {
			total++
		}
	}
	return total
}

func countEnabledExchanges(exchanges []model.ExchangeDomain) int {
	total := 0
	for _, ex := range exchanges {
		if ex.Enabled {
			total++
		}
	}
	return total
}
