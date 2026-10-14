# ============================================================================
# Windows 服务安装脚本
#
#   .\install-service.ps1              安装为开机自启服务（需要管理员）
#   .\install-service.ps1 -Uninstall   卸载服务
#   .\install-service.ps1 -Status      查看服务状态
#
# 实现方式：
#   不使用第三方工具（如 nssm），而是注册一个「计划任务」以 SYSTEM 身份
#   在开机时启动，效果等同服务，且无需额外依赖：
#     · 开机自启（触发器：系统启动）
#     · 崩溃自动重启（任务失败后重试）
#     · 以最高权限运行（能读 Security 事件日志）
#
#   若你更希望使用真正的 Windows 服务，可安装 NSSM 后把
#   「python.exe <根目录>\wsp.py --config <配置> start」注册为服务。
# ============================================================================
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$Status,
    [string]$TaskName = "webshell-watch",
    [string]$ConfigPath = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $ScriptDir

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "[错误] 需要管理员权限。请右键 PowerShell → 以管理员身份运行。" -ForegroundColor Red
        exit 1
    }
}

. (Join-Path $ScriptDir "python-common.ps1")

Assert-Admin

# --- 状态查询 ---------------------------------------------------------------
if ($Status) {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Host "计划任务 $TaskName 不存在（尚未安装）" -ForegroundColor Yellow
    } else {
        $info = Get-ScheduledTaskInfo -TaskName $TaskName
        Write-Host "计划任务 : $TaskName"
        Write-Host "状态     : $($task.State)"
        Write-Host "上次运行 : $($info.LastRunTime)"
        Write-Host "上次结果 : $($info.LastTaskResult)"
        Write-Host "下次运行 : $($info.NextRunTime)"
    }
    # 进程情况
    $procs = Get-CimInstance Win32_Process -Filter "Name like '%python%'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*wsp.py*" }
    if ($procs) {
        foreach ($p in $procs) { Write-Host "运行中   : PID $($p.ProcessId)" }
    } else {
        Write-Host "运行中   : 未发现监控进程" -ForegroundColor Yellow
    }
    exit 0
}

# --- 卸载 -------------------------------------------------------------------
if ($Uninstall) {
    Write-Host "==> 停止并删除计划任务 $TaskName"
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    # 结束残留进程
    Get-CimInstance Win32_Process -Filter "Name like '%python%'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*wsp.py*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "webshell-watch*" -ErrorAction SilentlyContinue
    Write-Host "已卸载。配置与日志保留在 C:\ProgramData\webshell-watch 下，如需清理请手动删除。" -ForegroundColor Green
    exit 0
}

# --- 安装 -------------------------------------------------------------------
$python = Get-WspPythonPath
if (-not $python) {
    Write-Host "[错误] 未找到 Python，请先安装 Python 3.9+。" -ForegroundColor Red
    exit 1
}

$entry = Join-Path $Root "wsp.py"
if (-not (Test-Path $entry)) {
    Write-Host "[错误] 找不到 $entry" -ForegroundColor Red
    exit 1
}

# 配置：放到 ProgramData，便于服务账号读写
$programData = Join-Path $env:ProgramData "webshell-watch"
New-Item -ItemType Directory -Force -Path $programData | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $programData "logs") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $programData "state") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $programData "rules") | Out-Null

if (-not $ConfigPath) { $ConfigPath = Join-Path $programData "config.json" }
if (-not (Test-Path $ConfigPath)) {
    Copy-Item (Join-Path $Root "windows.json") $ConfigPath -Force
    Write-Host "==> 已生成配置 $ConfigPath"
} else {
    Write-Host "==> 使用已存在的配置 $ConfigPath"
}

# 自定义规则
$srcRules = Join-Path $Root "rules"
if (Test-Path $srcRules) {
    Copy-Item (Join-Path $srcRules "*.json") (Join-Path $programData "rules") -Force -ErrorAction SilentlyContinue
}

Write-Host "==> 先做一次自检"
& $python $entry --config $ConfigPath check

Write-Host "==> 注册计划任务（开机自启 + 崩溃重启 + 最高权限）"
$action = New-ScheduledTaskAction -Execute $python `
    -Argument "`"$entry`" --config `"$ConfigPath`" start" `
    -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 5) `
    -ExecutionTimeLimit (New-TimeSpan -Days 365) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 6

$info = Get-ScheduledTaskInfo -TaskName $TaskName
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Green
Write-Host "安装完成。" -ForegroundColor Green
Write-Host "----------------------------------------------------------------------------"
Write-Host "服务状态 : $((Get-ScheduledTask -TaskName $TaskName).State)"
Write-Host "上次结果 : $($info.LastTaskResult)  （0 表示正常）"
Write-Host "配置     : $ConfigPath"
Write-Host "告警日志 : $programData\logs\alerts-<日期>.jsonl"
Write-Host "运行日志 : $programData\logs\watch-<日期>.log"
Write-Host ""
Write-Host "常用命令："
Write-Host "  .\install-service.ps1 -Status                    查看状态"
Write-Host "  Get-Content `"$programData\logs\alerts-$(Get-Date -Format yyyyMMdd).jsonl`" -Wait   实时看告警"
Write-Host "  .\wsp-windows.ps1 report                         告警统计"
Write-Host "  .\wsp-windows.ps1 filescan --update-baseline     发布代码后更新基线"
Write-Host "  .\install-service.ps1 -Uninstall                 卸载"
Write-Host "============================================================================" -ForegroundColor Green
