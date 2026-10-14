@echo off
rem ===========================================================================
rem  Windows 版双击入口（等价于 .\wsp-windows.ps1 check）
rem
rem  第一次使用建议：
rem    1) 双击本文件，确认自检结果（Python、IIS 日志、事件日志权限）
rem    2) 按自检提示修改 windows.json 里的 Web 根目录与日志路径
rem    3) 以管理员身份运行 install-service.ps1 安装开机自启
rem ===========================================================================
chcp 65001 >nul
setlocal
cd /d "%~dp0"

where powershell >nul 2>nul
if errorlevel 1 (
    echo [错误] 未找到 powershell，本脚本需要 Windows PowerShell。
    pause
    exit /b 1
)

echo ============================================================
echo   WebShell 防守监控（Windows 版）
echo ============================================================
echo.
echo 即将执行环境自检（不会修改任何系统配置）。
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0wsp-windows.ps1" check
echo.
echo ------------------------------------------------------------
echo  自检结束。接下来可以：
echo    .\wsp-windows.ps1 start --foreground    前台试运行，看是否抓到告警
echo    以管理员身份运行 install-service.ps1     安装为开机自启
echo ------------------------------------------------------------
pause
