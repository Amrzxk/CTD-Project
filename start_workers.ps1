# -------------------------------------------------------
#  start_workers.ps1 — Hybrid IDS process orchestrator
#
#  PowerShell equivalent for Windows development.
#
#  Usage:
#    .\start_workers.ps1
#
#  Prerequisites:
#    - Redis must be running (e.g. Docker Desktop)
#    - Python venv activated with requirements.txt
#    - Snort 3 running and writing alert_json
# -------------------------------------------------------

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "[orchestrator] Starting Hybrid IDS workers …" -ForegroundColor Cyan
Write-Host ""

# --- 1. Flow Meter Worker ---
Write-Host "[orchestrator] Starting flow_meter_worker …" -ForegroundColor Green
$flowMeter = Start-Process -FilePath "python" `
    -ArgumentList "-m", "app.core.flow_meter_worker" `
    -PassThru -NoNewWindow
Write-Host "[orchestrator]   PID=$($flowMeter.Id)"

# --- 2. Snort Tailer Worker ---
Write-Host "[orchestrator] Starting snort_tailer_worker …" -ForegroundColor Green
$snortTailer = Start-Process -FilePath "python" `
    -ArgumentList "-m", "app.core.snort_tailer_worker" `
    -PassThru -NoNewWindow
Write-Host "[orchestrator]   PID=$($snortTailer.Id)"

# --- 3. Uvicorn API Server ---
$uvicornHost = if ($env:UVICORN_HOST) { $env:UVICORN_HOST } else { "127.0.0.1" }
$uvicornPort = if ($env:UVICORN_PORT) { $env:UVICORN_PORT } else { "8000" }

Write-Host "[orchestrator] Starting uvicorn on ${uvicornHost}:${uvicornPort} …" -ForegroundColor Green
# Note: --reload removed. It wipes the in-memory predictions_store on every
# file edit (including unrelated docs / config changes), which surfaces to
# the analyst as "Analytics page is empty even though I just uploaded".
# Set $env:UVICORN_RELOAD=1 if you really need auto-reload while editing.
$uvicornArgs = @("app.main:app", "--host", $uvicornHost, "--port", $uvicornPort, "--timeout-keep-alive", "900")
if ($env:UVICORN_RELOAD -eq "1") {
    $uvicornArgs += "--reload"
    Write-Host "[orchestrator]   --reload enabled (UVICORN_RELOAD=1) — store will wipe on file edits" -ForegroundColor Yellow
}
$uvicorn = Start-Process -FilePath "uvicorn" `
    -ArgumentList $uvicornArgs `
    -PassThru -NoNewWindow
Write-Host "[orchestrator]   PID=$($uvicorn.Id)"

Write-Host ""
Write-Host "[orchestrator] All workers started." -ForegroundColor Cyan
Write-Host "[orchestrator] Press Ctrl+C or close this window to stop." -ForegroundColor Yellow
Write-Host ""

# --- Wait for any process to exit ---
try {
    while ($true) {
        if ($flowMeter.HasExited -or $snortTailer.HasExited -or $uvicorn.HasExited) {
            Write-Host "[orchestrator] A worker exited. Shutting down …" -ForegroundColor Red
            break
        }
        Start-Sleep -Seconds 2
    }
}
finally {
    # --- Cleanup ---
    Write-Host "[orchestrator] Stopping all workers …" -ForegroundColor Yellow
    @($flowMeter, $snortTailer, $uvicorn) | ForEach-Object {
        if (-not $_.HasExited) {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "[orchestrator] All workers stopped." -ForegroundColor Cyan
}
