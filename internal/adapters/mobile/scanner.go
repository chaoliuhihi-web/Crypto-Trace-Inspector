package mobile

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"crypto-inspector/internal/domain/model"
	"crypto-inspector/internal/platform/hash"
	"crypto-inspector/internal/platform/id"
)

const (
	collectorVersion = "0.1.0"
	parserVersion    = "0.1.0"
)

// ConnectedDevice 描述一次扫描中识别到的移动设备。
type ConnectedDevice struct {
	Device         model.Device
	ConnectionType string
	Authorized     bool
	AuthNote       string
}

// ScanResult 是移动端采集输出。
type ScanResult struct {
	Devices   []ConnectedDevice
	Artifacts []model.Artifact
	Warnings  []string
}

// Scanner 负责移动端设备识别、证据采集与证据落盘。
type Scanner struct {
	EvidenceRoot        string
	IOSBackupDir        string
	EnableIOSFullBackup bool
	// EnableAndroid/EnableIOS 用于控制采集范围（UI 勾选项对齐）。
	EnableAndroid bool
	EnableIOS     bool
}

func NewScanner(evidenceRoot, iosBackupDir string, enableIOSFullBackup bool, enableAndroid bool, enableIOS bool) *Scanner {
	if iosBackupDir == "" {
		tmp := filepath.Join(evidenceRoot, "ios_backups")
		tmp = filepath.Clean(tmp)
		iosBackupDir = tmp
	}
	// 兼容策略：如果两个都为 false，则默认都开启（防止旧调用方因零值导致“全跳过”）。
	if !enableAndroid && !enableIOS {
		enableAndroid = true
		enableIOS = true
	}
	return &Scanner{
		EvidenceRoot:        evidenceRoot,
		IOSBackupDir:        iosBackupDir,
		EnableIOSFullBackup: enableIOSFullBackup,
		EnableAndroid:       enableAndroid,
		EnableIOS:           enableIOS,
	}
}

func (s *Scanner) Scan(ctx context.Context, caseID string) (*ScanResult, error) {
	out := &ScanResult{}

	if s.EnableAndroid {
		androidDevices, androidArtifacts, androidWarnings, err := s.scanAndroid(ctx, caseID)
		if err != nil {
			return nil, err
		}
		out.Devices = append(out.Devices, androidDevices...)
		out.Artifacts = append(out.Artifacts, androidArtifacts...)
		out.Warnings = append(out.Warnings, androidWarnings...)
	} else {
		out.Warnings = append(out.Warnings, "android scan disabled by request")
	}

	if s.EnableIOS {
		iosDevices, iosArtifacts, iosWarnings, err := s.scanIOS(ctx, caseID)
		if err != nil {
			return nil, err
		}
		out.Devices = append(out.Devices, iosDevices...)
		out.Artifacts = append(out.Artifacts, iosArtifacts...)
		out.Warnings = append(out.Warnings, iosWarnings...)
	} else {
		out.Warnings = append(out.Warnings, "ios scan disabled by request")
	}

	return out, nil
}

func (s *Scanner) scanAndroid(ctx context.Context, caseID string) ([]ConnectedDevice, []model.Artifact, []string, error) {
	if _, err := exec.LookPath("adb"); err != nil {
		return nil, nil, []string{"adb not found, skip android scan"}, nil
	}

	raw, err := runCmd(ctx, "adb", "devices")
	if err != nil {
		return nil, nil, []string{"adb devices failed: " + err.Error()}, nil
	}

	devices := parseADBDevices(raw)
	var connected []ConnectedDevice
	var artifacts []model.Artifact
	var warnings []string

	for _, d := range devices {
		dev := model.Device{
			ID:         id.New("dev"),
			Name:       d.Serial,
			OS:         model.OSAndroid,
			Identifier: d.Serial,
		}
		connected = append(connected, ConnectedDevice{
			Device:         dev,
			ConnectionType: "usb",
			Authorized:     d.State == "device",
			AuthNote:       d.State,
		})

		if d.State != "device" {
			warnings = append(warnings, fmt.Sprintf("android device %s not authorized/state=%s", d.Serial, d.State))
			continue
		}

		pkgsRaw, err := runCmd(ctx, "adb", "-s", d.Serial, "shell", "pm", "list", "packages")
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("collect android packages failed (%s): %v", d.Serial, err))
			continue
		}

		packages := parseAndroidPackages(pkgsRaw)
		records := make([]model.MobilePackageRecord, 0, len(packages))
		for _, pkg := range packages {
			records = append(records, model.MobilePackageRecord{
				OS:         model.OSAndroid,
				DeviceID:   dev.ID,
				Identifier: dev.Identifier,
				Package:    pkg,
			})
		}

		art, err := s.makeArtifact(caseID, dev.ID, model.ArtifactMobilePackages, "android_pm_packages", "adb_shell_pm", records)
		if err != nil {
			return nil, nil, nil, err
		}
		artifacts = append(artifacts, art)
	}

	return connected, artifacts, warnings, nil
}

func (s *Scanner) scanIOS(ctx context.Context, caseID string) ([]ConnectedDevice, []model.Artifact, []string, error) {
	if _, err := exec.LookPath("idevice_id"); err != nil {
		return nil, nil, []string{"idevice_id not found, skip ios scan"}, nil
	}

	raw, err := runCmd(ctx, "idevice_id", "-l")
	if err != nil {
		return nil, nil, []string{"idevice_id -l failed: " + err.Error()}, nil
	}

	udids := parseUDIDs(raw)
	var connected []ConnectedDevice
	var artifacts []model.Artifact
	var warnings []string

	for _, udid := range udids {
		name := udid
		if n, err := queryIOSDeviceName(ctx, udid); err == nil && strings.TrimSpace(n) != "" {
			name = strings.TrimSpace(n)
		}

		authorized, authNote := validateIOSPair(ctx, udid)
		dev := model.Device{
			ID:         id.New("dev"),
			Name:       name,
			OS:         model.OSIOS,
			Identifier: udid,
		}
		connected = append(connected, ConnectedDevice{
			Device:         dev,
			ConnectionType: "usb",
			Authorized:     authorized,
			AuthNote:       authNote,
		})

		if !authorized {
			warnings = append(warnings, fmt.Sprintf("ios device %s not authorized: %s", udid, authNote))
		}

		// iOS 备份接入骨架：记录备份路径与建议命令，供后续真正备份流程接入。
		backupRoot := filepath.Join(s.IOSBackupDir, udid)
		backupHint := "skeleton only, no full backup performed"
		backupErrText := ""
		if authorized && s.EnableIOSFullBackup {
			if err := os.MkdirAll(backupRoot, 0o755); err != nil {
				backupErrText = err.Error()
				warnings = append(warnings, fmt.Sprintf("create ios backup root failed (%s): %v", udid, err))
			} else if err := tryIOSFullBackup(ctx, udid, backupRoot); err != nil {
				backupErrText = err.Error()
				warnings = append(warnings, fmt.Sprintf("ios full backup failed (%s): %v", udid, err))
				backupHint = "full backup failed, fallback to metadata only"
			} else {
				backupHint = "full backup completed"
			}
		}

		backupRecords := []model.MobileBackupRecord{{
			OS:          model.OSIOS,
			DeviceID:    dev.ID,
			Identifier:  udid,
			Authorized:  authorized,
			BackupRoot:  backupRoot,
			BackupHint:  backupHint,
			CommandHint: fmt.Sprintf("idevicebackup2 -u %s backup %s", udid, backupRoot),
			Error:       backupErrText,
			CollectedAt: time.Now().Unix(),
		}}
		backupArtifact, err := s.makeArtifact(caseID, dev.ID, model.ArtifactMobileBackup, "ios_backup_stub", "ios_backup_stub", backupRecords)
		if err != nil {
			return nil, nil, nil, err
		}
		artifacts = append(artifacts, backupArtifact)

		if !authorized {
			continue
		}

		packages, err := collectIOSPackages(ctx, udid)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("collect ios packages failed (%s): %v", udid, err))
			continue
		}
		records := make([]model.MobilePackageRecord, 0, len(packages))
		for _, pkg := range packages {
			records = append(records, model.MobilePackageRecord{
				OS:         model.OSIOS,
				DeviceID:   dev.ID,
				Identifier: dev.Identifier,
				Package:    pkg,
			})
		}
		packagesArtifact, err := s.makeArtifact(caseID, dev.ID, model.ArtifactMobilePackages, "ios_installed_apps", "ideviceinstaller_list", records)
		if err != nil {
			return nil, nil, nil, err
		}
		artifacts = append(artifacts, packagesArtifact)
	}

	return connected, artifacts, warnings, nil
}

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
		"mobile_scanner",
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
		CollectorName:     "mobile_scanner",
		CollectorVersion:  collectorVersion,
		ParserVersion:     parserVersion,
		AcquisitionMethod: method,
		PayloadJSON:       raw,
		RecordHash:        recordHash,
	}, nil
}

func sanitizeFilename(in string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_")
	return r.Replace(in)
}

type adbDevice struct {
	Serial string
	State  string
}

func parseADBDevices(raw string) []adbDevice {
	s := bufio.NewScanner(strings.NewReader(raw))
	out := []adbDevice{}
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "List of devices attached") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		out = append(out, adbDevice{Serial: parts[0], State: strings.ToLower(parts[1])})
	}
	return out
}

func parseAndroidPackages(raw string) []string {
	s := bufio.NewScanner(strings.NewReader(raw))
	set := map[string]struct{}{}
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		line = strings.TrimPrefix(line, "package:")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		set[line] = struct{}{}
	}
	pkgs := make([]string, 0, len(set))
	for k := range set {
		pkgs = append(pkgs, k)
	}
	sort.Strings(pkgs)
	return pkgs
}

func parseUDIDs(raw string) []string {
	s := bufio.NewScanner(strings.NewReader(raw))
	set := map[string]struct{}{}
	for s.Scan() {
		udid := strings.TrimSpace(s.Text())
		if udid == "" {
			continue
		}
		set[udid] = struct{}{}
	}
	udids := make([]string, 0, len(set))
	for k := range set {
		udids = append(udids, k)
	}
	sort.Strings(udids)
	return udids
}

func validateIOSPair(ctx context.Context, udid string) (bool, string) {
	if _, err := exec.LookPath("idevicepair"); err != nil {
		return false, "idevicepair not found"
	}
	cmd := exec.CommandContext(ctx, "idevicepair", "-u", udid, "validate")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return false, msg
	}
	return true, "validated"
}

func queryIOSDeviceName(ctx context.Context, udid string) (string, error) {
	if _, err := exec.LookPath("ideviceinfo"); err != nil {
		return "", err
	}
	out, err := runCmd(ctx, "ideviceinfo", "-u", udid, "-k", "DeviceName")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func collectIOSPackages(ctx context.Context, udid string) ([]string, error) {
	if _, err := exec.LookPath("ideviceinstaller"); err != nil {
		return nil, errors.New("ideviceinstaller not found")
	}

	raw, err := runCmd(ctx, "ideviceinstaller", "-u", udid, "-l")
	if err != nil {
		return nil, err
	}

	s := bufio.NewScanner(strings.NewReader(raw))
	set := map[string]struct{}{}
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		// 常见输出形态：com.example.app - AppName
		pkg := line
		if idx := strings.Index(line, " - "); idx > 0 {
			pkg = line[:idx]
		}
		pkg = strings.TrimSpace(pkg)
		if pkg == "" {
			continue
		}
		set[pkg] = struct{}{}
	}
	if len(set) == 0 {
		return nil, errors.New("no packages parsed from ideviceinstaller output")
	}

	pkgs := make([]string, 0, len(set))
	for k := range set {
		pkgs = append(pkgs, k)
	}
	sort.Strings(pkgs)
	return pkgs, nil
}

func tryIOSFullBackup(ctx context.Context, udid, backupRoot string) error {
	if _, err := exec.LookPath("idevicebackup2"); err != nil {
		return errors.New("idevicebackup2 not found")
	}
	backupCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(backupCtx, "idevicebackup2", "-u", udid, "backup", backupRoot)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("idevicebackup2 failed: %s", msg)
	}
	return nil
}

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
	}
	return string(out), nil
}
