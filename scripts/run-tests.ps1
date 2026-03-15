# Run dnstt tests and update the "Test results" section in README.
# Usage: .\scripts\run-tests.ps1 [-Short]
#   -Short   Skip slow integration tests (latency, overhead, reconnect, concurrent).

param([switch]$Short)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
if (-not (Test-Path (Join-Path $ProjectRoot "go.mod"))) {
    $ProjectRoot = $PWD.Path
}
Set-Location $ProjectRoot

# Use temp dir for metrics during test run (no report folder left behind)
$MetricsDir = [System.IO.Path]::GetTempFileName()
Remove-Item $MetricsDir -Force
New-Item -ItemType Directory -Path $MetricsDir | Out-Null
try {
    $env:DNSTT_METRICS_DIR = $MetricsDir

    # Build test args
    $testArgs = @(
        "test", "-tags", "integration", "-v", "-timeout", "120s",
        "./dnsttEx-server/", "./dnsttEx-client/", "./integration/",
        "./dns/", "./noise/", "./turbotunnel/"
    )
    if ($Short) { $testArgs += "-short" }

    Write-Host "Running tests..." -ForegroundColor Cyan
    $startTime = Get-Date
    $testOutput = & go $testArgs 2>&1
    $testExitCode = $LASTEXITCODE
    $duration = (Get-Date) - $startTime
    $testOutput | Out-Host

    # Parse summary
    $testOutputStr = if ($testOutput -is [string]) { $testOutput } else { $testOutput -join [Environment]::NewLine }
    $pass = ([regex]::Matches($testOutputStr, "--- PASS:")).Count
    $fail = ([regex]::Matches($testOutputStr, "--- FAIL:")).Count
    $skip = ([regex]::Matches($testOutputStr, "--- SKIP:")).Count

    # Helpers: format numbers in readable units
    function Format-BytesPerSec($b) {
        if ($b -ge 1e6) { return "{0:N1} MB/s" -f ($b / 1e6) }
        if ($b -ge 1024) { return "{0:N1} KB/s" -f ($b / 1024) }
        return "$([math]::Round($b, 0)) B/s"
    }
    function Format-Bytes($b) {
        if ($b -ge 1048576) { return "{0:N1} MB" -f ($b / 1048576) }
        if ($b -ge 1024) { return "{0:N0} KB" -f ($b / 1024) }
        return "$b B"
    }
    function Format-Ms($ms) {
        if ($ms -ge 1000) { return "{0:N1} s" -f ($ms / 1000) }
        return "$([math]::Round($ms, 0)) ms"
    }

    # Build the section content
    $lines = @()
    $lines += "**Last run:** $(Get-Date -Format 'yyyy-MM-dd HH:mm') · $pass passed, $fail failed, $skip skipped · $([math]::Round($duration.TotalSeconds, 1))s"
    $lines += ""

    $readJson = {
        param($path)
        if (-not (Test-Path $path)) { return $null }
        try { return Get-Content -Raw -Path $path | ConvertFrom-Json } catch { return $null }
    }

    # Concurrent throughput
    $c = & $readJson (Join-Path $MetricsDir "concurrent.json")
    if ($c) {
        $lines += "- **Throughput** (multiple streams at once): " + (Format-BytesPerSec $c.aggregate_bytes_per_s) + " over $($c.num_connections) connections (" + (Format-Bytes $c.total_bytes) + " in " + (Format-Ms $c.duration_ms) + ")"
        $lines += ""
    }

    # Latency
    $l = & $readJson (Join-Path $MetricsDir "latency_percentiles.json")
    if ($l) {
        $lines += "- **Latency** (round-trip time): median " + (Format-Ms $l.p50_ms) + ", 95th %ile " + (Format-Ms $l.p95_ms) + ", 99th %ile " + (Format-Ms $l.p99_ms) + " (n=$($l.samples))"
        $lines += ""
    }

    # Overhead
    $o = & $readJson (Join-Path $MetricsDir "overhead.json")
    if ($o) {
        $lines += "- **Wire overhead** (DNS encoding): " + "{0:N1}" -f $o.overhead_ratio + "× — " + (Format-Bytes $o.payload_bytes_total) + " payload becomes " + (Format-Bytes $o.wire_bytes_total) + " on the wire"
        $lines += ""
    }

    # Reconnect
    $r = & $readJson (Join-Path $MetricsDir "reconnect.json")
    if ($r) {
        $lines += "- **Reconnect** (after server restart): " + (Format-Ms $r.reconnect_ms)
        $lines += ""
    }

    if (-not $c -and -not $l -and -not $o -and -not $r) {
        $lines += "*No metrics (run without `-Short` to run full integration tests).*"
        $lines += ""
    }

    $sectionContent = $lines -join [Environment]::NewLine

    # Update README: replace content between the markers
    $readmePath = Join-Path $ProjectRoot "README"
    $readme = Get-Content -Raw -Path $readmePath -Encoding UTF8
    $startMarker = "<!-- test-results-start -->"
    $endMarker = "<!-- test-results-end -->"
    $pattern = [regex]::Escape($startMarker) + ".*?" + [regex]::Escape($endMarker)
    $replacement = $startMarker + [Environment]::NewLine + $sectionContent + [Environment]::NewLine + $endMarker
    $newReadme = [regex]::Replace($readme, $pattern, $replacement, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if ($newReadme -eq $readme) {
        Write-Warning "README markers not found; section not updated."
    } else {
        $newReadme | Set-Content -Path $readmePath -Encoding UTF8 -NoNewline:$false
        Write-Host ""
        Write-Host "README test results section updated." -ForegroundColor Green
    }

    if ($testExitCode -ne 0) {
        Write-Host "Tests had failures (exit code $testExitCode)." -ForegroundColor Red
        exit $testExitCode
    }
    Write-Host "All tests passed." -ForegroundColor Green
} finally {
    Remove-Item -Recurse -Force $MetricsDir -ErrorAction SilentlyContinue
}
