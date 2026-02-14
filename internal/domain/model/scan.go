package model

// OSType 表示被扫描设备的操作系统类型。
type OSType string

const (
	// OSWindows 表示 Windows 主机。
	OSWindows OSType = "windows"
	// OSMacOS 表示 macOS 主机。
	OSMacOS OSType = "macos"
	// OSAndroid 表示 Android 设备。
	OSAndroid OSType = "android"
	// OSIOS 表示 iOS 设备。
	OSIOS OSType = "ios"
)

// Device 表示一次案件中的设备对象（当前为主机）。
type Device struct {
	ID         string // 系统内设备 ID（非硬件序列号）
	Name       string // 设备名，例如主机名
	OS         OSType // 操作系统类型
	Identifier string // 稳定标识（由主机信息计算）
}

// ArtifactType 表示证据类型。
type ArtifactType string

const (
	// ArtifactInstalledApps 安装软件清单证据。
	ArtifactInstalledApps ArtifactType = "installed_apps"
	// ArtifactBrowserExt 浏览器扩展清单证据。
	ArtifactBrowserExt ArtifactType = "browser_extension"
	// ArtifactBrowserHistory 浏览历史证据。
	ArtifactBrowserHistory ArtifactType = "browser_history"
	// ArtifactBrowserHistoryDB 浏览历史原始 SQLite DB 快照（zip，包含 db + -wal/-shm）。
	// 该证据用于提升取证强度：不仅保留“解析后的记录”，也保留“解析所依赖的原始库副本”。
	ArtifactBrowserHistoryDB ArtifactType = "browser_history_db"
	// ArtifactMobilePackages 移动端安装包/应用清单证据。
	ArtifactMobilePackages ArtifactType = "mobile_packages"
	// ArtifactMobileBackup 移动端备份元数据证据（骨架阶段）。
	ArtifactMobileBackup ArtifactType = "mobile_backup"
	// ArtifactChainBalance 链上余额查询结果快照（用于把“链上查询结果”固化进证据链）。
	ArtifactChainBalance ArtifactType = "chain_balance"
)

// Artifact 表示一条落库证据（对应 artifacts 表）。
type Artifact struct {
	ID                string       // 证据 ID
	CaseID            string       // 关联案件
	DeviceID          string       // 关联设备
	Type              ArtifactType // 证据类型
	SourceRef         string       // 来源描述，例如 macos_browser_history
	SnapshotPath      string       // 证据快照文件路径
	SHA256            string       // 快照文件哈希
	SizeBytes         int64        // 快照文件大小
	CollectedAt       int64        // 采集时间（Unix 秒）
	CollectorName     string       // 采集器名称
	CollectorVersion  string       // 采集器版本
	ParserVersion     string       // 解析逻辑版本
	AcquisitionMethod string       // 采集方式
	PayloadJSON       []byte       // 结构化证据内容（JSON）
	IsEncrypted       bool         // 是否加密内容
	EncryptionNote    string       // 加密说明
	RecordHash        string       // 元数据链路哈希
}

// HitType 表示规则命中类型。
type HitType string

const (
	// HitWalletInstalled 命中钱包安装或钱包扩展。
	HitWalletInstalled HitType = "wallet_installed"
	// HitExchangeVisited 命中交易所访问记录。
	HitExchangeVisited HitType = "exchange_visited"
	// HitWalletAddress 从证据中抽取到的钱包地址（例如 0x... / bc1...）。
	HitWalletAddress HitType = "wallet_address"
	// HitTokenBalance 链上余额查询结果（例如 ETH/USDT/BTC 的数量）。
	HitTokenBalance HitType = "token_balance"
)

// RuleHit 表示一次规则命中结果（对应 rule_hits 表）。
type RuleHit struct {
	ID           string   // 命中 ID
	CaseID       string   // 关联案件
	DeviceID     string   // 关联设备
	Type         HitType  // 命中类型
	RuleID       string   // 命中的规则 ID
	RuleName     string   // 命中的规则名称
	RuleBundleID string   // 规则包 ID（rule_bundles.bundle_id）；非规则命中可为空
	RuleVersion  string   // 规则版本
	MatchedValue string   // 触发命中的值（域名/扩展ID/应用名）
	FirstSeenAt  int64    // 最早命中时间
	LastSeenAt   int64    // 最晚命中时间
	Confidence   float64  // 置信度 [0,1]
	Verdict      string   // confirmed/suspected/unsupported
	DetailJSON   []byte   // 命中细节 JSON
	ArtifactIDs  []string // 关联证据 ID 列表
}

// AppRecord 是安装软件采集后的统一结构。
type AppRecord struct {
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	Publisher       string `json:"publisher,omitempty"`
	InstallLocation string `json:"install_location,omitempty"`
	Path            string `json:"path,omitempty"`

	// Windows 常见字段（来自注册表卸载项）
	InstallDate     string `json:"install_date,omitempty"`     // 典型格式：YYYYMMDD（原始值）
	UninstallString string `json:"uninstall_string,omitempty"` // 卸载命令（原始值）
	DisplayIcon     string `json:"display_icon,omitempty"`     // 图标路径（原始值）

	// macOS 常见字段（来自 .app/Contents/Info.plist）
	BundleID string `json:"bundle_id,omitempty"` // CFBundleIdentifier
}

// ExtensionRecord 是浏览器扩展采集后的统一结构。
type ExtensionRecord struct {
	Browser     string `json:"browser"`
	Profile     string `json:"profile,omitempty"`
	ExtensionID string `json:"extension_id"`
	Name        string `json:"name,omitempty"`
	Version     string `json:"version,omitempty"`
	Path        string `json:"path,omitempty"` // 扩展目录或扩展包路径（best effort）
}

// VisitRecord 是浏览历史采集后的统一结构。
type VisitRecord struct {
	Browser   string `json:"browser"`
	Profile   string `json:"profile,omitempty"`
	URL       string `json:"url"`
	Domain    string `json:"domain"`
	Title     string `json:"title,omitempty"`
	VisitedAt int64  `json:"visited_at"`
}

// MobilePackageRecord 是移动端安装包采集后的统一结构。
type MobilePackageRecord struct {
	OS         OSType `json:"os"`
	DeviceID   string `json:"device_id"`
	Identifier string `json:"identifier"`
	Package    string `json:"package"`
	Raw        string `json:"raw,omitempty"`
}

// MobileBackupRecord 是移动端备份信息的统一结构（用于 iOS 备份骨架）。
type MobileBackupRecord struct {
	OS          OSType `json:"os"`
	DeviceID    string `json:"device_id"`
	Identifier  string `json:"identifier"`
	Authorized  bool   `json:"authorized"`
	BackupRoot  string `json:"backup_root,omitempty"`
	BackupHint  string `json:"backup_hint,omitempty"`
	CommandHint string `json:"command_hint,omitempty"`
	Error       string `json:"error,omitempty"`
	CollectedAt int64  `json:"collected_at"`
}
