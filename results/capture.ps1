<#
.SYNOPSIS
  Capture one M3 benchmark run from the board and summarise it.

.DESCRIPTION
  Listens on the ST-LINK virtual COM port until the firmware prints "# end",
  then writes (timestamped, under results/):
    raw/m3_<ts>.log   full UART transcript
    m3_<ts>.csv       benchmark rows, cycles, with the "# key=value" header
    m3_<ts>.md        Markdown table in cycles and microseconds, plus the
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

$text | Out-File -Encoding utf8 (Join-Path $rawDir "m3_$ts.log")
if ($text -notmatch '# end') {
  throw "Timed out after $TimeoutSec s without '# end'; transcript saved to raw/m3_$ts.log"
}

# Keep everything from the CSV preamble ("# sysclk_hz=") through "# end".
$lines = ($text -split "`r?`n") | ForEach-Object { $_.Trim() }
$start = [Array]::FindIndex($lines, [Predicate[string]]{ param($l) $l -like '# sysclk_hz=*' })
$end   = [Array]::FindIndex($lines, [Predicate[string]]{ param($l) $l -eq '# end' })
$block = $lines[$start..$end]
$block | Out-File -Encoding utf8 (Join-Path $outDir "m3_$ts.csv")

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
$md += "M3 run ${ts}: SYSCLK $mhz MHz, ICACHE=$($meta['icache']), $($meta['runs']) runs per op after $($meta['warmup']) warm-up runs."
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

$md | Out-File -Encoding utf8 (Join-Path $outDir "m3_$ts.md")
$md -join "`n"
Write-Host "`nSaved results/m3_$ts.csv, results/m3_$ts.md, results/raw/m3_$ts.log"
