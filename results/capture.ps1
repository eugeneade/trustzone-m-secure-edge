<#
.SYNOPSIS
  Capture one benchmark run (M3 + M4) from the board and summarise it.

.DESCRIPTION
  Listens on the ST-LINK virtual COM port until the firmware prints "# end",
  then writes (timestamped, under results/):
    raw/bench_<ts>.log   full UART transcript
    bench_<ts>.csv       benchmark rows, cycles, with the "# key=value" header
    bench_<ts>.md        Markdown table in cycles and microseconds, plus the
                      derived Secure-world overheads

  Start this first, then reset or flash the board (make flash).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File results/capture.ps1 -Port COM5
#>
param(
  [string]$Port = 'COM5',
  [int]$Baud = 115200,
  [int]$TimeoutSec = 120
)

$ErrorActionPreference = 'Stop'
$outDir = $PSScriptRoot
$rawDir = Join-Path $outDir 'raw'
New-Item -ItemType Directory -Force $rawDir | Out-Null
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'

$sp = New-Object System.IO.Ports.SerialPort $Port, $Baud, 'None', 8, 'One'
$sp.Open()
Write-Host "Listening on $Port at $Baud baud. Reset or flash the board now..."
$sw = [Diagnostics.Stopwatch]::StartNew()
$text = ''
try {
  while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec -and $text -notmatch '# end') {
    $text += $sp.ReadExisting()
    Start-Sleep -Milliseconds 100
  }
} finally {
  $sp.Close()
}

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

$md | Out-File -Encoding utf8 (Join-Path $outDir "bench_$ts.md")
$md -join "`n"
Write-Host "`nSaved results/bench_$ts.csv, results/bench_$ts.md, results/raw/bench_$ts.log"
