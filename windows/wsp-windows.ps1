# ============================================================================
# Windows 版启动入口
#
#   .\wsp-windows.ps1 check                 环境与能力自检（建议先跑这个）
#   .\wsp-windows.ps1 start --once          单次巡检（验证配置是否生效）
#   .\wsp-windows.ps1 start --foreground    前台持续监控（第一次先这样跑）
#   .\wsp-windows.ps1 filescan --update-baseline   发布代码后更新文件基线
#   .\wsp-windows.ps1 report                查看告警统计
#
# 说明：
#   * 已安装时使用 ProgramData 配置，否则使用项目根目录的 windows.json；
#   * Security 事件日志需要管理员权限，普通运行会自动跳过该模块并提示；
#   * 安装为开机自启服务请用：  .\install-service.ps1
# ============================================================================
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $ScriptDir
$DefaultConfig = Join-Path $Root "windows.json"

function Write-Info($msg) { Write-Host "[wsp] $msg" -ForegroundColor Cyan }
function Write-Warn2($msg) { Write-Host "[wsp] $msg" -ForegroundColor Yellow }

# --- 找 Python ---------------------------------------------------------------
. (Join-Path $ScriptDir "python-common.ps1")
$python = Get-WspPythonPath
if (-not $python) {
    Write-Host "[错误] 未找到可用的 Python 3.9+。请检查 PATH，或设置 WSP_PYTHON 为解释器完整路径。" -ForegroundColor Red
    Write-Host "       下载： https://www.python.org/downloads/windows/" -ForegroundColor Red
    exit 1
}

# 用 python -V 取版本：避免把多行 Python 代码传给 -c 时被缩进/引号问题影响
$version = ""
try {
    $raw = (& $python -V 2>&1 | Select-Object -First 1)
    if ("$raw" -match "(\d+\.\d+)") { $version = $matches[1] }
} catch { $version = "" }

if (-not $version) {
    # 退路：一行式代码（单引号包裹，避免 PowerShell 提前解析引号）
    $probe = 'import sys;sys.stdout.write("%d.%d"%sys.version_info[:2])'
    try { $version = (& $python -c $probe 2>$null | Select-Object -First 1) } catch { $version = "" }
}
if (-not $version) {
    Write-Host "[错误] 无法识别 Python 版本，请确认 Python 安装完整。" -ForegroundColor Red
    exit 1
}
$version = "$version".Trim()
$isOk = $false
try { $isOk = ([version]$version -ge [version]"3.9") } catch { $isOk = $false }
if (-not $isOk) {
    Write-Host "[错误] Python 版本过低（$version），需要 3.9 及以上。" -ForegroundColor Red
    exit 1
}
Write-Host ("[wsp] Python {0}  -->  {1}" -f $version, $python) -ForegroundColor DarkGray

# --- 配置准备 ---------------------------------------------------------------
# 已安装的配置优先；首次试运行直接用随项目附带的配置。
$configPath = $DefaultConfig
if ($env:ProgramData) {
    $installedConfig = Join-Path $env:ProgramData "webshell-watch\config.json"
    if (Test-Path -LiteralPath $installedConfig -PathType Leaf) { $configPath = $installedConfig }
}
if (-not (Test-Path $configPath)) {
    Write-Host "[错误] 找不到配置文件：$configPath" -ForegroundColor Red
    exit 1
}

# --- 检查管理员（Security 事件日志需要） -------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warn2 "当前不是管理员：Windows 安全事件日志监控会被跳过（其他模块正常）。"
    Write-Warn2 "需要事件日志请以管理员身份重新打开 PowerShell 再运行。"
}

# --- 交给共用实现 -----------------------------------------------------------
$env:WW_CONFIG = $configPath
$env:PYTHONIOENCODING = "utf-8"
$entry = Join-Path $Root "wsp.py"
if (-not (Test-Path $entry)) {
    Write-Host "[错误] 找不到 $entry，请确认目录结构完整。" -ForegroundColor Red
    exit 1
}

& $python $entry @Args
exit $LASTEXITCODE
