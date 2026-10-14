# 过滤 WindowsApps 占位程序，并返回实际解释器，供入口和计划任务共用。
function Get-WspPythonPath {
    $candidates = @()
    if ($env:WSP_PYTHON) {
        $candidates += $env:WSP_PYTHON
    } else {
        foreach ($name in @("python", "python3", "py")) {
            $commands = Get-Command $name -CommandType Application -All -ErrorAction SilentlyContinue
            foreach ($command in $commands) { $candidates += $command.Source }
        }
    }
    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        try {
            $probe = & $candidate -c 'import sys; assert sys.version_info >= (3, 9); print(sys.executable)' 2>$null
            if ($LASTEXITCODE -eq 0 -and $probe) {
                $path = ("$probe").Trim()
                if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }
            }
        } catch { continue }
    }
    return $null
}
