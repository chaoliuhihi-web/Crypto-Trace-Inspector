package host

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"crypto-inspector/internal/domain/model"
	"crypto-inspector/internal/platform/hash"
	"crypto-inspector/internal/platform/id"

	"howett.net/plist"
	_ "modernc.org/sqlite"
)

const (
	collectorVersion = "0.1.0"
	parserVersion    = "0.1.0"
)

// Scanner 负责主机端证据采集与快照落盘。
type Scanner struct {
	EvidenceRoot string
}

func NewScanner(evidenceRoot string) *Scanner {
	return &Scanner{EvidenceRoot: evidenceRoot}
}

// DetectHostDevice 根据当前运行环境识别主机设备信息。
func DetectHostDevice() (model.Device, error) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown-host"
	}
	osName := runtime.GOOS

	var osType model.OSType
	switch osName {
	case "windows":
		osType = model.OSWindows
	case "darwin":
		osType = model.OSMacOS
	default:
		return model.Device{}, fmt.Errorf("unsupported host os: %s", osName)
	}

	identifier := hash.Text(hostname, osName)
	return model.Device{
		ID:         id.New("dev"),
		Name:       hostname,
		OS:         osType,
		Identifier: identifier,
	}, nil
}

// Scan 根据 OS 分发到不同采集器实现。
func (s *Scanner) Scan(ctx context.Context, caseID string, device model.Device) ([]model.Artifact, error) {
	switch device.OS {
	case model.OSWindows:
		return s.scanWindows(ctx, caseID, device)
	case model.OSMacOS:
		return s.scanMacOS(ctx, caseID, device)
	default:
		return nil, fmt.Errorf("unsupported host os: %s", device.OS)
	}
}

// scanWindows 采集 Windows 主机三类核心证据：
// 1) 安装软件 2) 浏览器扩展 3) 浏览历史
func (s *Scanner) scanWindows(ctx context.Context, caseID string, device model.Device) ([]model.Artifact, error) {
	var out []model.Artifact

	apps, appErr := collectWindowsInstalledApps(ctx)
	artifact, err := s.makeArtifact(caseID, device.ID, model.ArtifactInstalledApps, "windows_registry_apps", "windows_registry", apps)
	if err != nil {
		return nil, err
	}
	out = append(out, artifact)

	ext, extErr := collectWindowsExtensions()
	artifact, err = s.makeArtifact(caseID, device.ID, model.ArtifactBrowserExt, "windows_browser_extensions", "directory_scan", ext)
	if err != nil {
		return nil, err
	}
	out = append(out, artifact)

	visits, historyErr := collectWindowsHistory(ctx)
	artifact, err = s.makeArtifact(caseID, device.ID, model.ArtifactBrowserHistory, "windows_browser_history", "sqlite_extract", visits)
	if err != nil {
		return nil, err
	}
	out = append(out, artifact)

	// P1：增强证据强度，把用于解析的原始 SQLite 库副本也落盘为 artifact（best effort）。
	out = append(out, s.snapshotHistoryDBArtifacts(caseID, device.ID, collectWindowsHistoryDBSpecs())...)

	if appErr != nil || extErr != nil || historyErr != nil {
		var parts []string
		if appErr != nil {
			parts = append(parts, "apps: "+appErr.Error())
		}
		if extErr != nil {
			parts = append(parts, "extensions: "+extErr.Error())
		}
		if historyErr != nil {
			parts = append(parts, "history: "+historyErr.Error())
		}
		return out, errors.New(strings.Join(parts, "; "))
	}

	return out, nil
}

// scanMacOS 采集 macOS 主机三类核心证据：
// 1) 应用 bundle 2) 浏览器扩展 3) 浏览历史
func (s *Scanner) scanMacOS(ctx context.Context, caseID string, device model.Device) ([]model.Artifact, error) {
	var out []model.Artifact

	apps, appErr := collectMacInstalledApps()
	artifact, err := s.makeArtifact(caseID, device.ID, model.ArtifactInstalledApps, "macos_bundle_apps", "bundle_scan", apps)
	if err != nil {
		return nil, err
	}
	out = append(out, artifact)

	ext, extErr := collectMacExtensions()
	artifact, err = s.makeArtifact(caseID, device.ID, model.ArtifactBrowserExt, "macos_browser_extensions", "directory_scan", ext)
	if err != nil {
		return nil, err
	}
	out = append(out, artifact)

	visits, historyErr := collectMacHistory(ctx)
	artifact, err = s.makeArtifact(caseID, device.ID, model.ArtifactBrowserHistory, "macos_browser_history", "sqlite_extract", visits)
	if err != nil {
		return nil, err
	}
	out = append(out, artifact)

	// P1：增强证据强度，把用于解析的原始 SQLite 库副本也落盘为 artifact（best effort）。
	out = append(out, s.snapshotHistoryDBArtifacts(caseID, device.ID, collectMacHistoryDBSpecs())...)

	if appErr != nil || extErr != nil || historyErr != nil {
		var parts []string
		if appErr != nil {
			parts = append(parts, "apps: "+appErr.Error())
		}
		if extErr != nil {
			parts = append(parts, "extensions: "+extErr.Error())
		}
		if historyErr != nil {
			parts = append(parts, "history: "+historyErr.Error())
		}
		return out, errors.New(strings.Join(parts, "; "))
	}

	return out, nil
}

// makeArtifact 将采集结果标准化成 Artifact：
// - payload 序列化为 JSON
// - 写入 evidence 目录
// - 计算文件哈希与 record_hash
func (s *Scanner) makeArtifact(caseID, deviceID string, t model.ArtifactType, sourceRef, method string, payload any) (model.Artifact, error) {
	now := time.Now().Unix()
	artifactID := id.New("art")

	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return model.Artifact{}, fmt.Errorf("marshal payload %s: %w", t, err)
	}

	dir := filepath.Join(s.EvidenceRoot, caseID, deviceID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return model.Artifact{}, fmt.Errorf("create evidence dir: %w", err)
	}

	name := fmt.Sprintf("%s_%s_%d.json", string(t), sourceRef, now)
	snapshotPath := filepath.Join(dir, sanitizeFilename(name))
	if err := os.WriteFile(snapshotPath, raw, 0o644); err != nil {
		return model.Artifact{}, fmt.Errorf("write evidence file: %w", err)
	}

	sum, size, err := hash.File(snapshotPath)
	if err != nil {
		return model.Artifact{}, fmt.Errorf("hash evidence file: %w", err)
	}

	recordHash := hash.Text(
		artifactID,
		caseID,
		deviceID,
		string(t),
		sourceRef,
		snapshotPath,
		sum,
		fmt.Sprintf("%d", size),
		fmt.Sprintf("%d", now),
		"host_scanner",
		collectorVersion,
		string(raw),
	)

	return model.Artifact{
		ID:                artifactID,
		CaseID:            caseID,
		DeviceID:          deviceID,
		Type:              t,
		SourceRef:         sourceRef,
		SnapshotPath:      snapshotPath,
		SHA256:            sum,
		SizeBytes:         size,
		CollectedAt:       now,
		CollectorName:     "host_scanner",
		CollectorVersion:  collectorVersion,
		ParserVersion:     parserVersion,
		AcquisitionMethod: method,
		PayloadJSON:       raw,
		RecordHash:        recordHash,
	}, nil
}

// makeZipArtifact 创建“单个 zip 文件作为 snapshot_path”的证据。
// 典型用途：保留原始 SQLite DB（含 wal/shm）副本，提升取证强度。
func (s *Scanner) makeZipArtifact(caseID, deviceID string, t model.ArtifactType, sourceRef, method string, files map[string]string, payload any) (model.Artifact, error) {
	now := time.Now().Unix()
	artifactID := id.New("art")

	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return model.Artifact{}, fmt.Errorf("marshal payload %s: %w", t, err)
	}

	dir := filepath.Join(s.EvidenceRoot, caseID, deviceID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return model.Artifact{}, fmt.Errorf("create evidence dir: %w", err)
	}

	name := fmt.Sprintf("%s_%s_%d.zip", string(t), sourceRef, now)
	snapshotPath := filepath.Join(dir, sanitizeFilename(name))
	if err := writeZip(snapshotPath, files); err != nil {
		return model.Artifact{}, fmt.Errorf("write zip evidence file: %w", err)
	}

	sum, size, err := hash.File(snapshotPath)
	if err != nil {
		return model.Artifact{}, fmt.Errorf("hash evidence file: %w", err)
	}

	recordHash := hash.Text(
		artifactID,
		caseID,
		deviceID,
		string(t),
		sourceRef,
		snapshotPath,
		sum,
		fmt.Sprintf("%d", size),
		fmt.Sprintf("%d", now),
		"host_scanner",
		collectorVersion,
		string(raw),
	)

	return model.Artifact{
		ID:                artifactID,
		CaseID:            caseID,
		DeviceID:          deviceID,
		Type:              t,
		SourceRef:         sourceRef,
		SnapshotPath:      snapshotPath,
		SHA256:            sum,
		SizeBytes:         size,
		CollectedAt:       now,
		CollectorName:     "host_scanner",
		CollectorVersion:  collectorVersion,
		ParserVersion:     parserVersion,
		AcquisitionMethod: method,
		PayloadJSON:       raw,
		RecordHash:        recordHash,
	}, nil
}

type historyDBSpec struct {
	Browser string
	Profile string
	Path    string
}

func (s *Scanner) snapshotHistoryDBArtifacts(caseID, deviceID string, specs []historyDBSpec) []model.Artifact {
	if len(specs) == 0 {
		return nil
	}

	out := make([]model.Artifact, 0, len(specs))
	for _, sp := range specs {
		src := strings.TrimSpace(sp.Path)
		if src == "" {
			continue
		}
		if _, err := os.Stat(src); err != nil {
			continue
		}

		// 先复制（含 wal/shm）到临时目录，避免“浏览器锁文件 + wal 旁路数据”导致证据不完整。
		tmpCopy, cleanup, err := copySQLiteForRead(src)
		if err != nil {
			continue
		}

		files := map[string]string{
			filepath.Base(src): tmpCopy,
		}
		for _, suffix := range []string{"-wal", "-shm"} {
			if _, err := os.Stat(tmpCopy + suffix); err == nil {
				files[filepath.Base(src)+suffix] = tmpCopy + suffix
			}
		}

		payload := map[string]any{
			"kind":        "sqlite_snapshot_zip",
			"browser":     sp.Browser,
			"profile":     sp.Profile,
			"origin_path": src,
			"files":       sortedKeys(files),
		}
		sourceRef := fmt.Sprintf("%s_%s", sp.Browser, sp.Profile)
		art, err := s.makeZipArtifact(caseID, deviceID, model.ArtifactBrowserHistoryDB, sourceRef, "sqlite_snapshot_zip", files, payload)
		cleanup()
		if err != nil {
			continue
		}
		out = append(out, art)
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

func collectWindowsHistoryDBSpecs() []historyDBSpec {
	local := os.Getenv("LOCALAPPDATA")
	appdata := os.Getenv("APPDATA")
	if local == "" && appdata == "" {
		return nil
	}

	var out []historyDBSpec
	if local != "" {
		out = append(out, chromiumHistoryDBSpecs(filepath.Join(local, "Google", "Chrome", "User Data"), "chrome")...)
		out = append(out, chromiumHistoryDBSpecs(filepath.Join(local, "Microsoft", "Edge", "User Data"), "edge")...)
	}
	if appdata != "" {
		out = append(out, firefoxPlacesDBSpecs(filepath.Join(appdata, "Mozilla", "Firefox", "Profiles"))...)
	}
	return out
}

func collectMacHistoryDBSpecs() []historyDBSpec {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}

	var out []historyDBSpec
	out = append(out, chromiumHistoryDBSpecs(filepath.Join(home, "Library", "Application Support", "Google", "Chrome"), "chrome")...)
	out = append(out, chromiumHistoryDBSpecs(filepath.Join(home, "Library", "Application Support", "Microsoft Edge"), "edge")...)
	out = append(out, firefoxPlacesDBSpecs(filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles"))...)
	out = append(out, safariHistoryDBSpecs(filepath.Join(home, "Library", "Safari", "History.db"))...)
	return out
}

func chromiumHistoryDBSpecs(profileRoot, browser string) []historyDBSpec {
	pattern := filepath.Join(profileRoot, "*", "History")
	files, _ := filepath.Glob(pattern)
	if len(files) == 0 {
		return nil
	}

	out := make([]historyDBSpec, 0, len(files))
	for _, f := range files {
		profile := filepath.Base(filepath.Dir(f))
		out = append(out, historyDBSpec{
			Browser: browser,
			Profile: profile,
			Path:    f,
		})
	}
	return out
}

func firefoxPlacesDBSpecs(profileRoot string) []historyDBSpec {
	pattern := filepath.Join(profileRoot, "*", "places.sqlite")
	files, _ := filepath.Glob(pattern)
	if len(files) == 0 {
		return nil
	}

	out := make([]historyDBSpec, 0, len(files))
	for _, f := range files {
		profile := filepath.Base(filepath.Dir(f))
		out = append(out, historyDBSpec{
			Browser: "firefox",
			Profile: profile,
			Path:    f,
		})
	}
	return out
}

func safariHistoryDBSpecs(path string) []historyDBSpec {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	return []historyDBSpec{{
		Browser: "safari",
		Profile: "default",
		Path:    path,
	}}
}

func writeZip(dst string, files map[string]string) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	keys := sortedKeys(files)
	for _, name := range keys {
		src := files[name]
		if strings.TrimSpace(src) == "" {
			continue
		}
		in, err := os.Open(src)
		if err != nil {
			return err
		}

		w, err := zw.Create(name)
		if err != nil {
			in.Close()
			return err
		}
		if _, err := io.Copy(w, in); err != nil {
			in.Close()
			return err
		}
		in.Close()
	}

	// 确保落盘
	if err := zw.Close(); err != nil {
		return err
	}
	return f.Sync()
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sanitizeFilename 把路径/空格等字符替换为安全文件名字符。
func sanitizeFilename(in string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_")
	return r.Replace(in)
}

// collectWindowsInstalledApps 从注册表读取安装程序信息。
func collectWindowsInstalledApps(ctx context.Context) ([]model.AppRecord, error) {
	// Use PowerShell registry query for installed applications.
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", `
$ErrorActionPreference = 'SilentlyContinue'
$paths = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
Get-ItemProperty $paths |
  Where-Object { $_.DisplayName } |
  Select-Object DisplayName,DisplayVersion,Publisher,InstallLocation,InstallDate,UninstallString,DisplayIcon |
  ConvertTo-Json -Depth 3
`)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("powershell query failed: %w", err)
	}

	type row struct {
		DisplayName     string `json:"DisplayName"`
		DisplayVersion  string `json:"DisplayVersion"`
		Publisher       string `json:"Publisher"`
		InstallLocation string `json:"InstallLocation"`
		InstallDate     string `json:"InstallDate"`
		UninstallString string `json:"UninstallString"`
		DisplayIcon     string `json:"DisplayIcon"`
	}

	var many []row
	if err := json.Unmarshal(out, &many); err != nil {
		var one row
		if err2 := json.Unmarshal(out, &one); err2 != nil {
			return nil, fmt.Errorf("parse powershell json: %w", err)
		}
		many = []row{one}
	}

	apps := make([]model.AppRecord, 0, len(many))
	for _, item := range many {
		apps = append(apps, model.AppRecord{
			Name:            strings.TrimSpace(item.DisplayName),
			Version:         strings.TrimSpace(item.DisplayVersion),
			Publisher:       strings.TrimSpace(item.Publisher),
			InstallLocation: strings.TrimSpace(item.InstallLocation),
			InstallDate:     strings.TrimSpace(item.InstallDate),
			UninstallString: strings.TrimSpace(item.UninstallString),
			DisplayIcon:     strings.TrimSpace(item.DisplayIcon),
		})
	}
	return dedupeApps(apps), nil
}

// collectMacInstalledApps 扫描常见应用目录（/Applications 与 ~/Applications）。
func collectMacInstalledApps() ([]model.AppRecord, error) {
	roots := []string{"/Applications"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		roots = append(roots, filepath.Join(home, "Applications"))
	}

	seen := make(map[string]struct{})
	var apps []model.AppRecord
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".app") {
				continue
			}
			appPath := filepath.Join(root, entry.Name())
			info := readMacAppInfo(appPath)
			name := strings.TrimSpace(info.Name)
			if name == "" {
				name = strings.TrimSuffix(entry.Name(), ".app")
			}

			// 优先使用 bundle_id 去重（更稳定）；否则退化到应用名。
			key := strings.ToLower(strings.TrimSpace(info.BundleID))
			if key == "" {
				key = strings.ToLower(name)
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			apps = append(apps, model.AppRecord{
				Name:     name,
				Version:  strings.TrimSpace(info.Version),
				BundleID: strings.TrimSpace(info.BundleID),
				Path:     appPath,
			})
		}
	}

	sort.Slice(apps, func(i, j int) bool {
		return strings.ToLower(apps[i].Name) < strings.ToLower(apps[j].Name)
	})
	return apps, nil
}

type macAppInfo struct {
	Name     string
	BundleID string
	Version  string
}

// readMacAppInfo 从 .app 的 Info.plist 中读取 bundle id 与版本信息（best effort）。
func readMacAppInfo(appPath string) macAppInfo {
	infoPlist := filepath.Join(appPath, "Contents", "Info.plist")
	raw, err := os.ReadFile(infoPlist)
	if err != nil || len(raw) == 0 {
		return macAppInfo{}
	}

	// Info.plist 可能是 XML 也可能是二进制 plist；howett.net/plist 两者都支持。
	var p struct {
		CFBundleDisplayName        string `plist:"CFBundleDisplayName"`
		CFBundleName               string `plist:"CFBundleName"`
		CFBundleIdentifier         string `plist:"CFBundleIdentifier"`
		CFBundleShortVersionString string `plist:"CFBundleShortVersionString"`
		CFBundleVersion            string `plist:"CFBundleVersion"`
	}
	if _, err := plist.Unmarshal(raw, &p); err != nil {
		return macAppInfo{}
	}

	name := strings.TrimSpace(p.CFBundleDisplayName)
	if name == "" {
		name = strings.TrimSpace(p.CFBundleName)
	}
	ver := strings.TrimSpace(p.CFBundleShortVersionString)
	if ver == "" {
		ver = strings.TrimSpace(p.CFBundleVersion)
	}

	return macAppInfo{
		Name:     name,
		BundleID: strings.TrimSpace(p.CFBundleIdentifier),
		Version:  ver,
	}
}

// collectWindowsExtensions 扫描 Chrome/Edge/Firefox 扩展目录。
func collectWindowsExtensions() ([]model.ExtensionRecord, error) {
	local := os.Getenv("LOCALAPPDATA")
	appdata := os.Getenv("APPDATA")
	if local == "" && appdata == "" {
		return nil, errors.New("LOCALAPPDATA and APPDATA are empty")
	}

	var out []model.ExtensionRecord
	if local != "" {
		out = append(out, scanChromiumExtensions(filepath.Join(local, "Google", "Chrome", "User Data"), "chrome")...)
		out = append(out, scanChromiumExtensions(filepath.Join(local, "Microsoft", "Edge", "User Data"), "edge")...)
	}
	if appdata != "" {
		out = append(out, scanFirefoxExtensions(filepath.Join(appdata, "Mozilla", "Firefox", "Profiles"))...)
	}
	return dedupeExtensions(out), nil
}

// collectMacExtensions 扫描 macOS 下 Chrome/Edge/Firefox 扩展目录。
func collectMacExtensions() ([]model.ExtensionRecord, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	var out []model.ExtensionRecord
	out = append(out, scanChromiumExtensions(filepath.Join(home, "Library", "Application Support", "Google", "Chrome"), "chrome")...)
	out = append(out, scanChromiumExtensions(filepath.Join(home, "Library", "Application Support", "Microsoft Edge"), "edge")...)
	out = append(out, scanFirefoxExtensions(filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles"))...)
	return dedupeExtensions(out), nil
}

// scanChromiumExtensions 扫描 Chromium 系浏览器扩展目录结构：
// {profile}/Extensions/{extensionID}
func scanChromiumExtensions(root, browser string) []model.ExtensionRecord {
	pattern := filepath.Join(root, "*", "Extensions", "*")
	matches, _ := filepath.Glob(pattern)

	out := make([]model.ExtensionRecord, 0, len(matches))
	for _, m := range matches {
		parts := strings.Split(filepath.Clean(m), string(filepath.Separator))
		if len(parts) < 4 {
			continue
		}
		extID := parts[len(parts)-1]
		profile := ""
		for i := len(parts) - 1; i >= 0; i-- {
			if strings.EqualFold(parts[i], "Extensions") && i > 0 {
				profile = parts[i-1]
				break
			}
		}

		name, version := readChromiumExtensionManifest(m)
		out = append(out, model.ExtensionRecord{
			Browser:     browser,
			Profile:     profile,
			ExtensionID: strings.TrimSpace(extID),
			Name:        name,
			Version:     version,
			Path:        m,
		})
	}
	return out
}

// scanFirefoxExtensions 扫描 Firefox 扩展目录并提取 profile 信息。
func scanFirefoxExtensions(profileRoot string) []model.ExtensionRecord {
	// Firefox 的真实扩展信息（id/name/version/active）优先来自 extensions.json。
	// 该文件位于 profile 根目录，结构稳定且无需解压 xpi。
	profiles, _ := filepath.Glob(filepath.Join(profileRoot, "*"))
	var out []model.ExtensionRecord

	for _, p := range profiles {
		fi, err := os.Stat(p)
		if err != nil || !fi.IsDir() {
			continue
		}
		profile := filepath.Base(p)
		extJSON := filepath.Join(p, "extensions.json")
		raw, err := os.ReadFile(extJSON)
		if err == nil && len(bytes.TrimSpace(raw)) > 0 {
			type addonLocale struct {
				Name string `json:"name"`
			}
			type addon struct {
				ID            string      `json:"id"`
				Version       string      `json:"version"`
				Type          string      `json:"type"`
				Active        bool        `json:"active"`
				DefaultLocale addonLocale `json:"defaultLocale"`
				Path          string      `json:"path"`
			}
			var payload struct {
				Addons []addon `json:"addons"`
			}
			if err := json.Unmarshal(raw, &payload); err == nil && len(payload.Addons) > 0 {
				for _, a := range payload.Addons {
					id := strings.TrimSpace(a.ID)
					if id == "" {
						continue
					}
					// 只保留“扩展”类型，减少噪音（theme/locale 等可按需再加）。
					if strings.TrimSpace(a.Type) != "" && strings.ToLower(strings.TrimSpace(a.Type)) != "extension" {
						continue
					}
					out = append(out, model.ExtensionRecord{
						Browser:     "firefox",
						Profile:     profile,
						ExtensionID: id,
						Name:        strings.TrimSpace(a.DefaultLocale.Name),
						Version:     strings.TrimSpace(a.Version),
						Path:        strings.TrimSpace(a.Path),
					})
				}
				// 当前 profile 已成功解析，不再做目录 fallback。
				continue
			}
		}

		// fallback：旧版本/异常情况下尝试扫描 extensions 目录（只能拿到文件名，信息较弱）。
		pattern := filepath.Join(p, "extensions", "*")
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			name := strings.TrimSpace(filepath.Base(m))
			if name == "" {
				continue
			}
			out = append(out, model.ExtensionRecord{
				Browser:     "firefox",
				Profile:     profile,
				ExtensionID: strings.TrimSuffix(name, filepath.Ext(name)),
				Name:        name,
				Path:        m,
			})
		}
	}

	return out
}

// readChromiumExtensionManifest 从扩展目录读取 manifest.json（best effort）并返回 name/version。
//
// 目录结构（典型）：
//
//	.../Extensions/<extensionID>/<version>/manifest.json
func readChromiumExtensionManifest(extDir string) (name, version string) {
	verDir := pickLatestChromiumExtVersionDir(extDir)
	if verDir == "" {
		return "", ""
	}
	manifestPath := filepath.Join(verDir, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return "", ""
	}

	var m struct {
		Name          string `json:"name"`
		ShortName     string `json:"short_name"`
		Version       string `json:"version"`
		DefaultLocale string `json:"default_locale"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", ""
	}

	name = strings.TrimSpace(m.Name)
	if name == "" {
		name = strings.TrimSpace(m.ShortName)
	}
	version = strings.TrimSpace(m.Version)

	// __MSG_xxx__ 本地化占位符解析（best effort）
	if strings.HasPrefix(name, "__MSG_") && strings.HasSuffix(name, "__") {
		key := strings.TrimSuffix(strings.TrimPrefix(name, "__MSG_"), "__")
		if resolved := lookupChromiumLocaleMessage(verDir, m.DefaultLocale, key); resolved != "" {
			name = resolved
		}
	}

	return name, version
}

func pickLatestChromiumExtVersionDir(extDir string) string {
	entries, err := os.ReadDir(extDir)
	if err != nil {
		return ""
	}

	type candidate struct {
		name    string
		path    string
		parts   []int
		modTime time.Time
	}
	var cands []candidate
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n := strings.TrimSpace(e.Name())
		if n == "" || strings.HasPrefix(n, ".") {
			continue
		}
		fi, _ := e.Info()
		cands = append(cands, candidate{
			name:  n,
			path:  filepath.Join(extDir, n),
			parts: parseVersionParts(n),
			modTime: func() time.Time {
				if fi != nil {
					return fi.ModTime()
				}
				return time.Time{}
			}(),
		})
	}
	if len(cands) == 0 {
		return ""
	}
	sort.Slice(cands, func(i, j int) bool {
		// 优先按版本号各段比较（语义化-ish）；无法解析时退化到修改时间/字符串比较。
		pi, pj := cands[i].parts, cands[j].parts
		if len(pi) > 0 && len(pj) > 0 {
			max := len(pi)
			if len(pj) > max {
				max = len(pj)
			}
			for k := 0; k < max; k++ {
				ai, aj := 0, 0
				if k < len(pi) {
					ai = pi[k]
				}
				if k < len(pj) {
					aj = pj[k]
				}
				if ai != aj {
					return ai > aj
				}
			}
		}
		if !cands[i].modTime.Equal(cands[j].modTime) && !cands[i].modTime.IsZero() && !cands[j].modTime.IsZero() {
			return cands[i].modTime.After(cands[j].modTime)
		}
		return cands[i].name > cands[j].name
	})
	return cands[0].path
}

func parseVersionParts(v string) []int {
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		iv, err := strconv.Atoi(p)
		if err != nil {
			// 有非数字段时直接放弃解析（避免误判）
			return nil
		}
		out = append(out, iv)
	}
	return out
}

// lookupChromiumLocaleMessage 从 _locales/*/messages.json 中解析 __MSG_xxx__。
func lookupChromiumLocaleMessage(extVersionDir, defaultLocale, key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	keyLower := strings.ToLower(key)

	localesRoot := filepath.Join(extVersionDir, "_locales")
	if _, err := os.Stat(localesRoot); err != nil {
		return ""
	}

	tryLocales := []string{}
	if strings.TrimSpace(defaultLocale) != "" {
		tryLocales = append(tryLocales, strings.TrimSpace(defaultLocale))
	}
	tryLocales = append(tryLocales, "en", "en_US", "zh_CN", "zh-CN", "zh")

	// 最后兜底：枚举目录任取一个（保证“尽量有名字”）
	entries, _ := os.ReadDir(localesRoot)
	for _, e := range entries {
		if e.IsDir() {
			tryLocales = append(tryLocales, e.Name())
		}
	}

	seen := map[string]struct{}{}
	for _, loc := range tryLocales {
		loc = strings.TrimSpace(loc)
		if loc == "" {
			continue
		}
		if _, ok := seen[loc]; ok {
			continue
		}
		seen[loc] = struct{}{}

		msgPath := filepath.Join(localesRoot, loc, "messages.json")
		raw, err := os.ReadFile(msgPath)
		if err != nil {
			continue
		}
		var m map[string]struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			continue
		}
		if v, ok := m[key]; ok {
			return strings.TrimSpace(v.Message)
		}
		if keyLower != "" {
			if v, ok := m[keyLower]; ok {
				return strings.TrimSpace(v.Message)
			}
		}
	}

	return ""
}

// collectWindowsHistory 采集 Windows 下 Chrome/Edge/Firefox 历史。
func collectWindowsHistory(ctx context.Context) ([]model.VisitRecord, error) {
	local := os.Getenv("LOCALAPPDATA")
	appdata := os.Getenv("APPDATA")
	if local == "" && appdata == "" {
		return nil, errors.New("LOCALAPPDATA and APPDATA are empty")
	}

	var out []model.VisitRecord
	if local != "" {
		out = append(out, collectChromiumHistory(ctx, filepath.Join(local, "Google", "Chrome", "User Data"), "chrome")...)
		out = append(out, collectChromiumHistory(ctx, filepath.Join(local, "Microsoft", "Edge", "User Data"), "edge")...)
	}
	if appdata != "" {
		out = append(out, collectFirefoxHistory(ctx, filepath.Join(appdata, "Mozilla", "Firefox", "Profiles"))...)
	}
	if len(out) == 0 {
		return nil, errors.New("no history records collected")
	}
	return out, nil
}

// collectMacHistory 采集 macOS 下 Chrome/Edge/Firefox/Safari 历史。
func collectMacHistory(ctx context.Context) ([]model.VisitRecord, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	var out []model.VisitRecord
	out = append(out, collectChromiumHistory(ctx, filepath.Join(home, "Library", "Application Support", "Google", "Chrome"), "chrome")...)
	out = append(out, collectChromiumHistory(ctx, filepath.Join(home, "Library", "Application Support", "Microsoft Edge"), "edge")...)
	out = append(out, collectFirefoxHistory(ctx, filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles"))...)
	out = append(out, collectSafariHistory(ctx, filepath.Join(home, "Library", "Safari", "History.db"))...)
	if len(out) == 0 {
		return nil, errors.New("no history records collected")
	}
	return out, nil
}

// collectChromiumHistory 查询 Chromium History 库，提取 URL 与访问时间。
func collectChromiumHistory(ctx context.Context, profileRoot, browser string) []model.VisitRecord {
	pattern := filepath.Join(profileRoot, "*", "History")
	files, _ := filepath.Glob(pattern)
	var out []model.VisitRecord

	for _, f := range files {
		profile := filepath.Base(filepath.Dir(f))
		query := `
SELECT urls.url, COALESCE(urls.title, ''), visits.visit_time
FROM urls
JOIN visits ON urls.id = visits.url
ORDER BY visits.visit_time DESC
LIMIT 1500;
`
		rows, err := querySQLite(ctx, f, query)
		if err != nil {
			continue
		}
		for _, r := range rows {
			if len(r) < 3 {
				continue
			}
			u := strings.TrimSpace(r[0])
			domain := extractDomain(u)
			if domain == "" {
				continue
			}
			out = append(out, model.VisitRecord{
				Browser:   browser,
				Profile:   profile,
				URL:       u,
				Domain:    domain,
				Title:     r[1],
				VisitedAt: chrometimeToEpoch(r[2]),
			})
		}
	}
	return dedupeVisits(out)
}

// collectFirefoxHistory 查询 places.sqlite 中访问记录。
func collectFirefoxHistory(ctx context.Context, profileRoot string) []model.VisitRecord {
	pattern := filepath.Join(profileRoot, "*", "places.sqlite")
	files, _ := filepath.Glob(pattern)
	var out []model.VisitRecord

	for _, f := range files {
		profile := filepath.Base(filepath.Dir(f))
		query := `
SELECT url, COALESCE(title, ''), COALESCE(last_visit_date, 0)
FROM moz_places
WHERE url IS NOT NULL
ORDER BY last_visit_date DESC
LIMIT 1500;
`
		rows, err := querySQLite(ctx, f, query)
		if err != nil {
			continue
		}
		for _, r := range rows {
			if len(r) < 3 {
				continue
			}
			u := strings.TrimSpace(r[0])
			domain := extractDomain(u)
			if domain == "" {
				continue
			}
			out = append(out, model.VisitRecord{
				Browser:   "firefox",
				Profile:   profile,
				URL:       u,
				Domain:    domain,
				Title:     r[1],
				VisitedAt: microToEpoch(r[2]),
			})
		}
	}
	return dedupeVisits(out)
}

// collectSafariHistory 查询 Safari 的 History.db。
func collectSafariHistory(ctx context.Context, historyDB string) []model.VisitRecord {
	if _, err := os.Stat(historyDB); err != nil {
		return nil
	}
	query := `
SELECT hi.url, COALESCE(hi.title, ''), hv.visit_time
FROM history_items hi
JOIN history_visits hv ON hi.id = hv.history_item
ORDER BY hv.visit_time DESC
LIMIT 1500;
`
	rows, err := querySQLite(ctx, historyDB, query)
	if err != nil {
		return nil
	}

	var out []model.VisitRecord
	for _, r := range rows {
		if len(r) < 3 {
			continue
		}
		u := strings.TrimSpace(r[0])
		domain := extractDomain(u)
		if domain == "" {
			continue
		}
		out = append(out, model.VisitRecord{
			Browser:   "safari",
			Profile:   "default",
			URL:       u,
			Domain:    domain,
			Title:     r[1],
			VisitedAt: safariToEpoch(r[2]),
		})
	}
	return dedupeVisits(out)
}

// querySQLite 使用 Go 的 sqlite 驱动读取 sqlite：
// 先复制数据库（含 -wal/-shm）再查询，避免浏览器锁文件导致读取失败，
// 同时尽量保留 WAL 中的最新记录（常见于 Chrome/Edge/Safari）。
func querySQLite(ctx context.Context, dbPath, sqlQuery string) ([][]string, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return nil, err
	}

	tmpCopy, cleanup, err := copySQLiteForRead(dbPath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	db, err := sql.Open("sqlite", tmpCopy)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, _ = db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`)

	rows, err := db.QueryContext(ctx, sqlQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	out := make([][]string, 0, 256)
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		for i := range vals {
			vals[i] = nil
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make([]string, 0, len(cols))
		for _, v := range vals {
			switch x := v.(type) {
			case nil:
				row = append(row, "")
			case []byte:
				row = append(row, string(x))
			case string:
				row = append(row, x)
			default:
				row = append(row, fmt.Sprint(x))
			}
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func copySQLiteForRead(src string) (dst string, cleanup func(), err error) {
	tmpDir, err := os.MkdirTemp("", "crypto_inspector_sqlite_")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(tmpDir) }

	dst = filepath.Join(tmpDir, filepath.Base(src))
	if err := copyFile(src, dst); err != nil {
		cleanup()
		return "", nil, err
	}

	// sqlite WAL/SHM sidecars
	for _, suffix := range []string{"-wal", "-shm"} {
		srcSide := src + suffix
		if _, err := os.Stat(srcSide); err == nil {
			_ = copyFile(srcSide, dst+suffix)
		}
	}

	return dst, cleanup, nil
}

// copyFile 用于创建数据库副本文件。
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

// extractDomain 从 URL 中提取标准化域名。
func extractDomain(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	host = strings.TrimPrefix(host, "www.")
	return host
}

// chrometimeToEpoch 将 Chromium 时间（1601 起点微秒）转换为 Unix 秒。
func chrometimeToEpoch(v string) int64 {
	// Chromium visit_time = microseconds since 1601-01-01.
	iv, err := parseInt64(v)
	if err != nil || iv <= 0 {
		return time.Now().Unix()
	}
	const epochDiffMicros int64 = 11644473600 * 1_000_000
	unixMicros := iv - epochDiffMicros
	if unixMicros <= 0 {
		return time.Now().Unix()
	}
	return unixMicros / 1_000_000
}

// microToEpoch 将 Unix 起点微秒转换为 Unix 秒（Firefox）。
func microToEpoch(v string) int64 {
	iv, err := parseInt64(v)
	if err != nil || iv <= 0 {
		return time.Now().Unix()
	}
	// Firefox last_visit_date = microseconds since Unix epoch.
	return iv / 1_000_000
}

// safariToEpoch 将 Safari 时间（2001 起点秒）转换为 Unix 秒。
func safariToEpoch(v string) int64 {
	fv, err := parseFloat64(v)
	if err != nil {
		return time.Now().Unix()
	}
	// Safari visit_time = seconds since 2001-01-01.
	const appleRef = 978307200
	return int64(fv) + appleRef
}

// parseInt64 用于解析 sqlite 文本字段中的整数值。
func parseInt64(v string) (int64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, errors.New("empty")
	}
	var out int64
	_, err := fmt.Sscan(v, &out)
	return out, err
}

// parseFloat64 用于解析 sqlite 文本字段中的浮点值。
func parseFloat64(v string) (float64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, errors.New("empty")
	}
	var out float64
	_, err := fmt.Sscan(v, &out)
	return out, err
}

// dedupeApps 对应用记录做去重。
func dedupeApps(in []model.AppRecord) []model.AppRecord {
	seen := map[string]struct{}{}
	out := make([]model.AppRecord, 0, len(in))
	for _, a := range in {
		key := strings.ToLower(strings.TrimSpace(a.Name + "|" + a.InstallLocation + "|" + a.Path))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, a)
	}
	return out
}

// dedupeExtensions 对扩展记录做去重。
func dedupeExtensions(in []model.ExtensionRecord) []model.ExtensionRecord {
	seen := map[string]struct{}{}
	out := make([]model.ExtensionRecord, 0, len(in))
	for _, e := range in {
		key := strings.ToLower(strings.TrimSpace(e.Browser + "|" + e.Profile + "|" + e.ExtensionID))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, e)
	}
	return out
}

// dedupeVisits 对访问记录做去重。
func dedupeVisits(in []model.VisitRecord) []model.VisitRecord {
	seen := map[string]struct{}{}
	out := make([]model.VisitRecord, 0, len(in))
	for _, v := range in {
		key := strings.ToLower(strings.TrimSpace(v.Browser + "|" + v.Profile + "|" + v.URL + "|" + fmt.Sprintf("%d", v.VisitedAt)))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, v)
	}
	return out
}
