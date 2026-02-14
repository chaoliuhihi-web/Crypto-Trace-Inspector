param(
  [Parameter(Mandatory = $true)]
  [string]$InstallerPath,

  [string]$InstallDir = "$env:TEMP\\CryptoTraceInspector-Install",
  [string]$Listen = "127.0.0.1:8788",
  [int]$TimeoutSeconds = 90
)

# Windows 安装器冒烟测试（CI 用）：
# - 静默安装到临时目录
# - 启动 inspector-desktop（--ui none）并等待 /api/health 就绪
# - 静默卸载并验证文件已移除
#
# 目的：尽早发现“安装包缺文件 / 参数不兼容 / 启动即崩 / 端口监听失败”等问题。
# 注意：这是最小回归，并不替代真实环境（不同权限/杀软/策略）的完整验证。

$ErrorActionPreference = "Stop"

Write-Host "== Windows installer smoke test =="
Write-Host "InstallerPath=$InstallerPath"
Write-Host "InstallDir=$InstallDir"
Write-Host "Listen=$Listen"

if (-not (Test-Path $InstallerPath)) {
  throw "installer not found: $InstallerPath"
}

if (Test-Path $InstallDir) {
  Remove-Item -Recurse -Force $InstallDir
}

Write-Host "[1/4] install (silent)"
$installArgs = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /DIR=`"$InstallDir`""
$p = Start-Process -FilePath $InstallerPath -ArgumentList $installArgs -Wait -PassThru
if ($p.ExitCode -ne 0) {
  throw "installer exit code: $($p.ExitCode)"
}

$desktopExe = Join-Path $InstallDir "inspector-desktop.exe"
$cliExe = Join-Path $InstallDir "inspector.exe"
if (-not (Test-Path $desktopExe)) { throw "missing installed desktop exe: $desktopExe" }
if (-not (Test-Path $cliExe)) { throw "missing installed cli exe: $cliExe" }

Write-Host "[2/4] start desktop (headless) and wait for /api/health"
$dataRoot = Join-Path $env:LOCALAPPDATA "Crypto-Trace-Inspector\\ci-test"
$db = Join-Path $dataRoot "inspector.db"
$evidence = Join-Path $dataRoot "evidence"
$ios = Join-Path $evidence "ios_backups"

New-Item -ItemType Directory -Force -Path $ios | Out-Null

$serverArgs = @(
  "--ui", "none",
  "--no-open",
  "--listen", $Listen,
  "--db", $db,
  "--evidence-dir", $evidence,
  "--ios-backup-dir", $ios
)

$server = Start-Process -FilePath $desktopExe -ArgumentList $serverArgs -PassThru
try {
  $healthUrl = "http://$Listen/api/health"
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  $ok = $false
  while ((Get-Date) -lt $deadline) {
    try {
      $resp = Invoke-WebRequest -UseBasicParsing -Uri $healthUrl -TimeoutSec 5
      if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300) {
        $ok = $true
        break
      }
    } catch {
      Start-Sleep -Milliseconds 500
    }
  }
  if (-not $ok) {
    throw "health check timeout: $healthUrl"
  }
  Write-Host "Health OK: $healthUrl"
} finally {
  if ($server -and -not $server.HasExited) {
    Stop-Process -Id $server.Id -Force
    Start-Sleep -Milliseconds 300
  }
}

Write-Host "[3/4] uninstall (silent)"
$unins = Join-Path $InstallDir "unins000.exe"
if (Test-Path $unins) {
  $uninstallArgs = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-"
  $u = Start-Process -FilePath $unins -ArgumentList $uninstallArgs -Wait -PassThru
  if ($u.ExitCode -ne 0) {
    throw "uninstaller exit code: $($u.ExitCode)"
  }
} else {
  Write-Host "WARN: uninstaller not found: $unins"
}

Write-Host "[4/4] verify uninstall"
if (Test-Path $desktopExe) {
  throw "uninstall failed: still exists: $desktopExe"
}

Write-Host "OK"
