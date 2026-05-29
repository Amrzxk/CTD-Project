<#
.SYNOPSIS
    Forcefully stops every H-IDS process started by start_all.ps1.
.DESCRIPTION
    The original start_all.ps1 cleanup only Stop-Process-es the tracked
    Start-Process PIDs. That misses several real-world cases:

      * Start-Process "python" → py.exe launcher → child python.exe.
        The wrapper exits but the actual uvicorn keeps holding :8000.
      * Orphan processes from a crashed/closed previous run.
      * Silent Stop-Process failures (-ErrorAction SilentlyContinue +
        try/catch{} swallows everything).

    This script catches them all by killing on two axes:
      1. Whoever is bound to :8000 (uvicorn) or :5173 (vite).
      2. Any python.exe whose command line contains one of the H-IDS
         module names — kills children regardless of parent PID.

    Idempotent: safe to call any number of times.
.EXAMPLE
    .\stop_all.ps1
#>

function Stop-PortHolder($port) {
    $owners = (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue).OwningProcess
    if ($owners) {
        $owners | Sort-Object -Unique | ForEach-Object {
            Write-Host "  Killing PID $_ (port $port)" -ForegroundColor Gray
            Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue
        }
    }
}

function Stop-PythonModule($modulePattern) {
    Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*$modulePattern*" } |
        ForEach-Object {
            Write-Host "  Killing PID $($_.ProcessId) ($modulePattern)" -ForegroundColor Gray
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        }
}

Write-Host "Stopping H-IDS stack..." -ForegroundColor Yellow
Stop-PortHolder 8000          # uvicorn API
Stop-PortHolder 5173          # vite dashboard
Stop-PythonModule "app.core.flow_meter_worker"
Stop-PythonModule "app.core.snort_tailer_worker"
Stop-PythonModule "app.main:app"      # uvicorn invocation
Stop-PythonModule "alert_simulator"
Start-Sleep 1
Write-Host "Stop complete." -ForegroundColor Green
