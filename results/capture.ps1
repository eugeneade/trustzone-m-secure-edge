<#
.SYNOPSIS
  Capture one benchmark run (M3-M5) from the board and summarise it.

.DESCRIPTION
  Listens on the ST-LINK virtual COM port until the firmware prints "# end",
  then writes (timestamped, under results/):
    raw/bench_<ts>.log   full UART transcript
    bench_<ts>.csv       benchmark rows, cycles, with the "# key=value" header
    bench_<ts>.md        Markdown summary: all rows in cycles and microseconds,
                         derived Secure-world overheads, M4 step breakdown and
                         M5 interrupt latency

  Start this first, then reset or flash the board (make flash).
  With -FromCsv, skips the board and regenerates the .md next to a saved CSV.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File results/capture.ps1 -Port COM5
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File results/capture.ps1 -FromCsv results/bench_20261031_170748.csv
#>
param(
  [string]$Port = 'COM5',
  [int]$Baud = 115200,
  [int]$TimeoutSec = 120,
  [string]$FromCsv
)

$ErrorActionPreference = 'Stop'
$outDir = $PSScriptRoot

if ($FromCsv) {
  $ts = [IO.Path]::GetFileNameWithoutExtension($FromCsv) -replace '^(bench|m3)_', ''
  $block = Get-Content $FromCsv | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
  $mdPath = [IO.Path]::ChangeExtension((Resolve-Path $FromCsv).Path, '.md')
} else {
  $rawDir = Join-Path $outDir 'raw'
  New-Item -ItemType Directory -Force $rawDir | Out-Null
  $ts = Get-Date -Format 'yyyyMMdd_HHmmss'

  $sp = New-Object System.IO.Ports.SerialPort $Port, $Baud, 'None', 8, 'One'
  # Drain the ST-LINK bridge quickly: a large driver buffer and short polls.
  # With 100 ms polls and the default 4 KB buffer, whole sections were lost.
  $sp.ReadBufferSize = 1MB
  $sp.Open()
  Write-Host "Listening on $Port at $Baud baud. Reset or flash the board now..."
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $sb = New-Object System.Text.StringBuilder
  $done = $false
  try {
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec -and -not $done) {
      $chunk = $sp.ReadExisting()
      if ($chunk.Length -gt 0) {
        [void]$sb.Append($chunk)
        # Only the tail can newly contain the end marker.
        $tailLen = [Math]::Min($sb.Length, $chunk.Length + 8)
        $done = $sb.ToString($sb.Length - $tailLen, $tailLen) -match '# end'
      }
      Start-Sleep -Milliseconds 20
    }
  } finally {
    $sp.Close()
  }
  $text = $sb.ToString()

  $text | Out-File -Encoding utf8 (Join-Path $rawDir "bench_$ts.log")
  if ($text -notmatch '# end') {
    throw "Timed out after $TimeoutSec s without '# end'; transcript saved to raw/bench_$ts.log"
  }

  # Keep everything from the CSV preamble ("# sysclk_hz=") through "# end".
  $lines = ($text -split "`r?`n") | ForEach-Object { $_.Trim() }
  $start = [Array]::FindIndex($lines, [Predicate[string]]{ param($l) $l -like '# sysclk_hz=*' })
  $end   = [Array]::FindIndex($lines, [Predicate[string]]{ param($l) $l -eq '# end' })
  $block = $lines[$start..$end]
  $block | Out-File -Encoding utf8 (Join-Path $outDir "bench_$ts.csv")
  $mdPath = Join-Path $outDir "bench_$ts.md"
}

$meta = @{}
foreach ($l in $block | Where-Object { $_ -like '# *=*' }) {
  foreach ($kv in ($l.Substring(2) -split ' ')) {
    $k, $v = $kv -split '=', 2
    $meta[$k] = $v
  }
}
$mhz = [double]$meta['sysclk_hz'] / 1e6
$rows = $block | Where-Object { $_ -notlike '#*' } | ConvertFrom-Csv

function Us([double]$c) { ($c / $mhz).ToString('F3', [Globalization.CultureInfo]::InvariantCulture) }
function Row($op, $bytes) { $rows | Where-Object { $_.op -eq $op -and $_.bytes -eq "$bytes" } }

$md = @()
$md += "Benchmark run ${ts}: SYSCLK $mhz MHz, ICACHE=$($meta['icache']), $($meta['runs']) runs per op after $($meta['warmup']) warm-up runs."
$md += ''
$md += '| Operation | Bytes | Median cycles | Mean cycles | Mean us | Min | Max | Std dev | Runs |'
$md += '|-----------|------:|--------------:|------------:|--------:|----:|----:|--------:|-----:|'
foreach ($r in $rows) {
  $md += "| $($r.op) | $($r.bytes) | $($r.median) | $($r.mean) | $(Us $r.mean) | $($r.min) | $($r.max) | $($r.stddev) | $($r.runs) |"
}

$md += ''
$md += 'Derived Secure-world overhead (difference of medians):'
$md += ''
$md += '| Quantity | Cycles | us | Relative |'
$md += '|----------|-------:|---:|---------:|'
$ns = Row 'ns_call_empty' 0
$nsc = Row 'nsc_call_empty' 0
$d = [double]$nsc.median - [double]$ns.median
$md += "| NS -> S -> NS transition (empty call) | $d | $(Us $d) | |"
foreach ($b in ($rows | Where-Object { $_.op -eq 'hmac_ns' } | ForEach-Object { $_.bytes })) {
  $a = [double](Row 'hmac_ns' $b).median
  $s = [double](Row 'hmac_nsc' $b).median
  $d = $s - $a
  $md += "| HMAC-SHA256 $b B: Secure minus NS | $d | $(Us $d) | {0:P2} |" -f ($d / $a)
}

# M4: break "Secure minus NS" into steps (needs the probe_* / step_* rows).
function Med($op, $bytes) { [double](Row $op $bytes).median }
$switch = (Med 'nsc_call_empty' 0) - (Med 'ns_call_empty' 0)
foreach ($b in ($rows | Where-Object { $_.op -eq 'step_checks' } | ForEach-Object { $_.bytes })) {
  $total = (Med 'hmac_nsc' $b) - (Med 'hmac_ns' $b)
  $parts = [ordered]@{
    'World switch (empty Secure call minus empty NS call)' = $switch
    'Argument passing (probe_args minus empty Secure call)' = (Med 'probe_args' $b) - (Med 'nsc_call_empty' 0)
    'Pointer checks (in Secure)' = Med 'step_checks' $b
    'Tag copy-out (in Secure)' = Med 'step_copy' $b
    'Tag zeroize (in Secure)' = Med 'step_zeroize' $b
    'HMAC core, Secure minus NS' = (Med 'hmac_core_s' $b) - (Med 'hmac_core_ns' $b)
  }
  $sum = ($parts.Values | Measure-Object -Sum).Sum
  $md += ''
  $md += "Breakdown of the Secure-service overhead at $b B (medians):"
  $md += ''
  $md += '| Step | Cycles | us | Share of total |'
  $md += '|------|-------:|---:|---------------:|'
  foreach ($k in $parts.Keys) {
    $md += "| $k | $($parts[$k]) | $(Us $parts[$k]) | {0:P1} |" -f ($parts[$k] / $total)
  }
  $md += "| **Sum of steps** | $sum | $(Us $sum) | {0:P1} |" -f ($sum / $total)
  $md += "| **Measured total (hmac_nsc minus hmac_ns)** | $total | $(Us $total) | |"
  $md += "| Unexplained residual | $($total - $sum) | $(Us ($total - $sum)) | |"
  $md += "| _For comparison: mbedtls_platform_zeroize, same buffer_ | $(Med 'step_zeroize_mbedtls' $b) | $(Us (Med 'step_zeroize_mbedtls' $b)) | |"
}

# M5: interrupt latency (needs the irq_* rows).
$irqRows = $rows | Where-Object { $_.op -like 'irq_*' }
if ($irqRows) {
  $base = Row 'irq_idle_ns' 0
  $md += ''
  $md += "M5: Non-Secure interrupt latency, cycles from timer event to handler (TIM2 period check: $($meta['irq_period_cycles']) observed, $($meta['irq_period_expected']) expected):"
  $md += ''
  $md += '| Foreground code | Median | Max | Max us | Max minus idle max |'
  $md += '|-----------------|-------:|----:|-------:|-------------------:|'
  foreach ($r in $irqRows) {
    $md += "| $($r.op) ($($r.bytes) B) | $($r.median) | $($r.max) | $(Us $r.max) | $([double]$r.max - [double]$base.max) |"
  }
}

# M6: hardware HASH vs software (needs the hmac_hw_nsc / hmac_core_hw_s rows).
$hwSizes = $rows | Where-Object { $_.op -eq 'hmac_hw_nsc' } | ForEach-Object { $_.bytes }
if ($hwSizes) {
  $md += ''
  $md += 'M6: HMAC-SHA256, software vs HASH peripheral (median cycles):'
  $md += ''
  $md += '| Bytes | SW in NS | SW Secure service | HW Secure service | HW core (in Secure) | HW service minus HW core | Speedup, SW service / HW service |'
  $md += '|------:|---------:|------------------:|------------------:|--------------------:|-------------------------:|---------------------------------:|'
  foreach ($b in $hwSizes) {
    $swNs = Med 'hmac_ns' $b
    $swS = Med 'hmac_nsc' $b
    $hwS = Med 'hmac_hw_nsc' $b
    $hwCore = Med 'hmac_core_hw_s' $b
    $md += "| $b | $swNs | $swS | $hwS | $hwCore | $($hwS - $hwCore) | {0:N1}x |" -f ($swS / $hwS)
  }
  if ($meta.ContainsKey('hw_contention_irqs')) {
    $md += ''
    $md += "HASH peripheral contention: $($meta['hw_contention_irqs']) interrupts each requested a 16-byte hardware MAC while the foreground ran 1 KB hardware MACs. " +
           "Busy (refused): $($meta['hw_contention_busy']), computed correctly: $($meta['hw_contention_ok']), wrong or failed: $($meta['hw_contention_handler_errors']). " +
           "Foreground: $($meta['hw_contention_fg_runs']) MACs, $($meta['hw_contention_fg_errors']) wrong or failed."
  }
}

$md | Out-File -Encoding utf8 $mdPath
$md -join "`n"
if ($FromCsv) {
  Write-Host "`nSaved $mdPath"
} else {
  Write-Host "`nSaved results/bench_$ts.csv, results/bench_$ts.md, results/raw/bench_$ts.log"
}
