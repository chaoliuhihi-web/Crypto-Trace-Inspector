package app

// 版本信息。打包时可通过 -ldflags 注入：
// -X crypto-inspector/internal/app.Version=...
// -X crypto-inspector/internal/app.Commit=...
// -X crypto-inspector/internal/app.BuildTime=...
var (
	Version   = "dev"
	Commit    = ""
	BuildTime = ""
)

