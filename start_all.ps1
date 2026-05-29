<#
.SYNOPSIS
    One-click launcher for the Hybrid IDS stack.
.DESCRIPTION
    Opens each component in its own terminal window:
      1. Redis (Docker) — verifies running
      2. Flow Meter Worker
      3. Snort Tailer Worker (reads SNORT_ALERT_LOG -> Redis pub/sub)
      4. Uvicorn API
      5. Dashboard (Vite)
      6. Alert Simulator (skipped when -NoSimulator OR -WithSnortLive)

    With -WithSnortLive, the simulator is replaced by a real Snort 3
    process running inside WSL that replays a PCAP into the shared
    alert log so the tailer can pick up genuine signatures.

    Close any window or press Ctrl+C here to stop all.
.EXAMPLE
    .\start_all.ps1
    .\start_all.ps1 -NoSimulator
    .\start_all.ps1 -WithSnortLive -SnortPcap Testing/pcap/test_attack_sample.pcap
#>
param(
    [switch]$NoSimulator,
    [int]$AlertCount = 0,
    [float]$AlertInterval = 1.5,
    [switch]$WithSnortLive,
    [string]$SnortPcap = "Testing/pcap/test_wednesday_multi_attack_2gb.pcap"
)

$Root = $PSScriptRoot
if (-not $Root) { $Root = Split-Path -Parent $MyInvocation.MyCommand.Path }

Write-Host ""
Write-Host "  ============================================" -ForegroundColor Cyan
Write-Host "    Hybrid IDS - Full Stack Launcher" -ForegroundColor Cyan
Write-Host "  ============================================" -ForegroundColor Cyan
Write-Host ""

# --- 0. Pre-flight: kill any orphan processes from a previous run ---
# Without this, an orphan uvicorn keeps holding :8000 and the new one we
# spawn fails to bind silently — the dashboard then keeps talking to the
# old uvicorn with stale predictions_store. Idempotent.
$stopScript = Join-Path $Root "stop_all.ps1"
if (Test-Path $stopScript) {
    Write-Host "[0/6] Pre-flight clean (kills orphans from previous runs)..." -ForegroundColor Yellow
    & $stopScript
} else {
    Write-Host "[0/6] stop_all.ps1 not found; skipping pre-flight clean" -ForegroundColor DarkYellow
}
Write-Host ""

# --- 1. Redis ---
Write-Host "[1/5] Checking Redis..." -ForegroundColor Yellow
$redisOk = docker exec redis redis-cli PING 2>$null
if ($redisOk -ne "PONG") {
    Write-Host "  Starting Redis..." -ForegroundColor Gray
    docker start redis 2>$null
    if ($LASTEXITCODE -ne 0) { docker run -d --name redis -p 6379:6379 redis:latest 2>$null }
    Start-Sleep 2
}
Write-Host "  Redis OK" -ForegroundColor Green

# --- 2. Flow Meter ---
Write-Host "[2/6] Starting Flow Meter Worker..." -ForegroundColor Yellow
$flowMeter = Start-Process -FilePath "python" `
    -ArgumentList "-u -m app.core.flow_meter_worker" `
    -WorkingDirectory $Root `
    -PassThru -WindowStyle Normal
Write-Host "  Flow Meter PID: $($flowMeter.Id)" -ForegroundColor Green

# Wait for flows to populate Redis
Write-Host "  Waiting 6s for initial flow processing..." -ForegroundColor Gray
Start-Sleep 6

# --- 3. Snort Tailer ---
Write-Host "[3/6] Starting Snort Tailer Worker..." -ForegroundColor Yellow
$tailer = Start-Process -FilePath "python" `
    -ArgumentList "-u -m app.core.snort_tailer_worker" `
    -WorkingDirectory $Root `
    -PassThru -WindowStyle Normal
Write-Host "  Tailer PID: $($tailer.Id) (reads SNORT_ALERT_LOG)" -ForegroundColor Green
Start-Sleep 1

# --- 4. Uvicorn ---
Write-Host "[4/6] Starting Uvicorn API..." -ForegroundColor Yellow
$uvicorn = Start-Process -FilePath "python" `
    -ArgumentList "-u -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --timeout-keep-alive 900" `
    -WorkingDirectory $Root `
    -PassThru -WindowStyle Normal
Write-Host "  Uvicorn PID: $($uvicorn.Id) -> http://127.0.0.1:8000" -ForegroundColor Green

# Health probe — Start-Process opens uvicorn in a detached window, so a bind
# failure (port already taken by an orphan we couldn't kill) wouldn't surface
# here otherwise. Poll /health for up to 10s and warn loudly if it never
# answers — saves a confusing "All services running!" + dead dashboard.
$healthOk = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 500
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8000/health" -UseBasicParsing -TimeoutSec 1 -ErrorAction Stop
        if ($resp.StatusCode -eq 200) { $healthOk = $true; break }
    } catch { }
}
if ($healthOk) {
    Write-Host "  Uvicorn healthy" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Uvicorn did not answer /health within 10s." -ForegroundColor Red
    Write-Host "  An orphan process may still hold :8000. Run .\stop_all.ps1 and retry." -ForegroundColor Red
}

# --- 5. Dashboard ---
Write-Host "[5/6] Starting Dashboard..." -ForegroundColor Yellow
$dashboard = Start-Process -FilePath "cmd" `
    -ArgumentList "/c npm run dev" `
    -WorkingDirectory (Join-Path $Root "dashboard") `
    -PassThru -WindowStyle Normal
Write-Host "  Dashboard PID: $($dashboard.Id) -> http://localhost:5173" -ForegroundColor Green
Start-Sleep 5

# --- 6. Simulator OR live Snort replay ---
$sim = $null
$snortLive = $null
if ($WithSnortLive) {
    Write-Host "[6/6] Starting live Snort 3 (WSL) replaying $SnortPcap..." -ForegroundColor Yellow
    $wslPcap = "/mnt/f/GradProject/$($SnortPcap -replace '\\','/')"
    $snortCmd = @"
snort --daq-dir /usr/local/lib/daq -c /mnt/f/GradProject/Testing/snort/snort.lua -r $wslPcap -A alert_json -l /mnt/f/GradProject/.tmp/snort/logs
"@
    $snortLive = Start-Process -FilePath "wsl.exe" `
        -ArgumentList @("-d", "Ubuntu-24.04", "--", "bash", "-c", $snortCmd) `
        -PassThru -WindowStyle Normal
    Write-Host "  Snort PID: $($snortLive.Id) (writes /mnt/f/GradProject/.tmp/snort/logs/alert_json.txt)" -ForegroundColor Green
} elseif (-not $NoSimulator) {
    Write-Host "[6/6] Starting Alert Simulator..." -ForegroundColor Yellow
    $simArgs = if ($AlertCount -gt 0) { "-u -m app.tools.alert_simulator --count $AlertCount --interval $AlertInterval" } else { "-u -m app.tools.alert_simulator --continuous --interval $AlertInterval" }
    $sim = Start-Process -FilePath "python" `
        -ArgumentList $simArgs `
        -WorkingDirectory $Root `
        -PassThru -WindowStyle Normal
    Write-Host "  Simulator PID: $($sim.Id)" -ForegroundColor Green
} else {
    Write-Host "[6/6] Simulator + Snort skipped" -ForegroundColor Gray
}

# --- Done ---
Write-Host ""
Write-Host "  ============================================" -ForegroundColor Green
Write-Host "    All services running!" -ForegroundColor Green
Write-Host "  ============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Dashboard:  http://localhost:5173/dashboard" -ForegroundColor Cyan
Write-Host "  API:        http://127.0.0.1:8000/health" -ForegroundColor Cyan
Write-Host ""
Write-Host "  1. Open the Dashboard URL above" -ForegroundColor White
Write-Host "  2. Click 'Connect to Stream'" -ForegroundColor White
Write-Host "  3. Events will appear automatically!" -ForegroundColor White
Write-Host ""
Write-Host "  Press ENTER to stop all services..." -ForegroundColor Yellow
Read-Host

# --- Cleanup ---
# Delegate to stop_all.ps1 so the trusted port-based + command-line-based
# kill logic runs everywhere. The tracked-PID Stop-Process approach used
# previously silently missed orphans (py.exe wrapper children, processes
# that survived a swallowed Stop-Process error, etc.).
if (Test-Path $stopScript) {
    & $stopScript
} else {
    Write-Host "Stopping all services (fallback — stop_all.ps1 missing)..." -ForegroundColor Yellow
    $pids = @($flowMeter, $tailer, $uvicorn, $dashboard, $sim, $snortLive) | Where-Object { $_ -ne $null -and -not $_.HasExited }
    foreach ($p in $pids) {
        try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
    Write-Host "All services stopped." -ForegroundColor Green
}
