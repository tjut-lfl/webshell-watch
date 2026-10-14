# powershell -NoProfile -ExecutionPolicy Bypass -File tests\test_windows_entry.ps1 -PythonPath C:\path\python.exe
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PythonPath)
$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$parseCount = 0
foreach ($file in (Get-ChildItem -LiteralPath (Join-Path $projectRoot "windows") -Filter *.ps1)) {
    $tokens = $null
    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
    $parseCount++
}
Write-Output "PASS: PowerShell syntax ($parseCount files)"
. (Join-Path $projectRoot "windows\python-common.ps1")
$originalOverride = $env:WSP_PYTHON
try {
    $env:WSP_PYTHON = $PythonPath
    $resolved = Get-WspPythonPath
    if (-not $resolved -or -not (Test-Path -LiteralPath $resolved)) { throw "Valid Python was not resolved" }
    Write-Output "PASS: Resolve usable Python"
    $env:WSP_PYTHON = Join-Path $projectRoot "missing-python.exe"
    if (Get-WspPythonPath) { throw "Invalid Python was accepted" }
    Write-Output "PASS: Reject unavailable Python"
    $env:WSP_PYTHON = $PythonPath
    $entry = Join-Path $projectRoot "windows\wsp-windows.ps1"
    $result = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entry --version 2>&1
    if ($LASTEXITCODE -ne 0 -or ($result -join "`n") -notmatch 'wsp 1\.0\.0') {
        throw "Windows PowerShell entry failed: $result"
    }
    Write-Output "PASS: Windows PowerShell launcher --version"
} finally {
    $env:WSP_PYTHON = $originalOverride
}
