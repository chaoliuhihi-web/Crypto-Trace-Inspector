; Windows 原生安装包（Inno Setup）脚本
;
; 使用方式（在 Windows 上执行）：
; 1) 先构建 Windows bundle：
;      bash scripts/package_bundle.sh
;    这会生成 dist\crypto-inspector-windows-amd64\ 目录（包含 exe + rules + 启动脚本）
; 2) 安装 Inno Setup 6（推荐）：
;      choco install innosetup -y
; 3) 编译安装器：
;      "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\windows\crypto-trace-inspector.iss
;
; 说明：
; - 安装目录（程序本体）默认在 Program Files
; - 运行数据（DB/证据/日志）默认在 %LOCALAPPDATA%\Crypto-Trace-Inspector\
; - 快捷方式会以参数形式把 --db/--evidence-dir/--wallet/--exchange 等路径固定住，
;   避免“工作目录变化导致找不到规则/写不了 data”的问题。

#define MyAppName "Crypto Trace Inspector"
#define MyAppPublisher "Crypto Inspector"
#define MyAppURL "https://github.com/chaoliuhihi-web/Crypto-Trace-Inspector"
#define MyAppVersion "0.1.0-dev"

#define BundleDir "..\\..\\dist\\crypto-inspector-windows-amd64"

[Setup]
AppId={{D2CB60D2-4E26-4F86-9E57-18C6F2B7D6B1}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\CryptoTraceInspector
DisableProgramGroupPage=yes
Compression=lzma
SolidCompression=yes
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
WizardStyle=modern
OutputDir=..\..\dist\installers\windows
OutputBaseFilename=CryptoTraceInspector-Setup-{#MyAppVersion}-windows-amd64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked

[Dirs]
Name: "{localappdata}\Crypto-Trace-Inspector\data\evidence\ios_backups"
Name: "{localappdata}\Crypto-Trace-Inspector\logs"

[Files]
Source: "{#BundleDir}\\inspector-desktop.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BundleDir}\\inspector.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BundleDir}\\rules\\*"; DestDir: "{app}\\rules"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\inspector-desktop.exe"; Parameters: {code:GetDesktopParams}
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\inspector-desktop.exe"; Parameters: {code:GetDesktopParams}; Tasks: desktopicon

[Run]
Filename: "{app}\inspector-desktop.exe"; Parameters: {code:GetDesktopParams}; Flags: nowait postinstall skipifsilent

[Code]
function GetDesktopParams(Param: string): string;
begin
  Result :=
    '--listen 127.0.0.1:8787 ' +
    '--db "' + ExpandConstant('{localappdata}\Crypto-Trace-Inspector\data\inspector.db') + '" ' +
    '--evidence-dir "' + ExpandConstant('{localappdata}\Crypto-Trace-Inspector\data\evidence') + '" ' +
    '--ios-backup-dir "' + ExpandConstant('{localappdata}\Crypto-Trace-Inspector\data\evidence\ios_backups') + '" ' +
    '--wallet "' + ExpandConstant('{app}\rules\wallet_signatures.template.yaml') + '" ' +
    '--exchange "' + ExpandConstant('{app}\rules\exchange_domains.template.yaml') + '"';
end;

