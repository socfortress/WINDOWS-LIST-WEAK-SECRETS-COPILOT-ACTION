[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\List-Weak-Secrets.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log',
  [switch]$NoProgress
)

$ErrorActionPreference = 'Stop'
$HostName  = $env:COMPUTERNAME
$LogMaxKB  = 100
$LogKeep   = 5
$MaxSizeMB = 50
$runStart  = Get-Date

$logDir = Split-Path -Path $LogPath -Parent
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType File -Force | Out-Null }

function Rotate-Log {
  param([string]$Path,[int]$MaxKB,[int]$Keep)
  if (Test-Path $Path -PathType Leaf) {
    $sizeKB = [math]::Ceiling((Get-Item $Path).Length / 1KB)
    if ($sizeKB -ge $MaxKB) {
      for ($i = $Keep - 1; $i -ge 1; $i--) {
        $src = "$Path.$i"; $dst = "$Path." + ($i + 1)
        if (Test-Path $src) { Move-Item $src $dst -Force }
      }
      Move-Item $Path "$Path.1" -Force
    }
  }
}

function Write-Log {
  param([string]$Level,[string]$Message)
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  Add-Content -Path $LogPath -Value "[$ts][$Level] $Message" -Encoding utf8
  switch ($Level) {
    'ERROR' { Write-Host "[$ts][$Level] $Message" -ForegroundColor Red }
    'WARN'  { Write-Host "[$ts][$Level] $Message" -ForegroundColor Yellow }
    default { Write-Host "[$ts][$Level] $Message" }
  }
}

function NowISO { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString('N')))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  $payload = ($JsonLines -join [Environment]::NewLine) + [Environment]::NewLine
  Set-Content -Path $tmp -Value $payload -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force }
  catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

function Get-FileHashSHA256 {
  param([string]$FilePath)
  try { (Get-FileHash -Algorithm SHA256 -Path $FilePath -ErrorAction Stop).Hash } catch { $null }
}

Rotate-Log -Path $LogPath -MaxKB $LogMaxKB -Keep $LogKeep
Write-Log INFO "=== SCRIPT START : Scan for Weak Secrets on C:\ (MaxSizeMB=$MaxSizeMB) ==="

$searchPatterns  = @('*.env','*.ini','*.txt','*.json')
$keywordPatterns = @('password\s*=', 'apikey\s*=', 'secret\s*=', 'token\s*=')

$ts    = NowISO
$lines = New-Object System.Collections.ArrayList
$scannedFiles = 0
$flagged = New-Object System.Collections.Generic.List[object]
$dirSet  = New-Object System.Collections.Generic.HashSet[string]
$sw = [System.Diagnostics.Stopwatch]::StartNew()

try {
  [void]$lines.Add( (@{
    timestamp        = $ts
    host             = $HostName
    action           = 'scan_weak_secrets'
    copilot_action   = $true
    item             = 'verify_source'
    description      = 'Scan configuration and limits'
    root             = 'C:\'
    patterns         = $searchPatterns
    keywords         = $keywordPatterns
    max_size_mb      = $MaxSizeMB
  } | ConvertTo-Json -Compress -Depth 6) )

  Get-ChildItem -Path 'C:\' -Recurse -Include $searchPatterns -File -Force -ErrorAction SilentlyContinue |
  ForEach-Object {
    $f = $_
    if ($f.Length -ge ($MaxSizeMB * 1MB)) { return }
    $null = $dirSet.Add($f.DirectoryName)
    $scannedFiles++

    if (-not $NoProgress -and ($scannedFiles % 200 -eq 0)) {
      Write-Progress -Activity "Scanning C:\" -Status ("files={0} flagged={1}" -f $scannedFiles, $flagged.Count) -PercentComplete 0
      Write-Host -NoNewline "."
    }

    $content = ''
    try { $content = Get-Content -Path $f.FullName -Raw -Encoding UTF8 -ErrorAction Stop } catch { $content = '' }

    foreach ($pattern in $keywordPatterns) {
      if ($content -match $pattern) {
        $sha = Get-FileHashSHA256 -FilePath $f.FullName
        $rec = [PSCustomObject]@{
          file_path = $f.FullName
          size_kb   = [math]::Round($f.Length / 1KB, 2)
          match     = $pattern
          sha256    = $sha
        }
        $flagged.Add($rec) | Out-Null

        [void]$lines.Add( (@{
          timestamp      = $ts
          host           = $HostName
          action         = 'scan_weak_secrets'
          copilot_action = $true
          item           = 'weak_secret'
          description    = "Keyword match: $pattern"
          file_path      = $rec.file_path
          size_kb        = $rec.size_kb
          match          = $rec.match
          sha256         = $rec.sha256
        } | ConvertTo-Json -Compress -Depth 5) )

        break
      }
    }
  }

  if (-not $NoProgress) { Write-Progress -Activity "Scanning C:\" -Completed }

  $sw.Stop()

  $summary = @{
    timestamp        = $ts
    host             = $HostName
    action           = 'scan_weak_secrets'
    copilot_action   = $true
    item             = 'summary'
    description      = 'Run summary and counts'
    root_dir         = 'C:\'
    max_size_mb      = $MaxSizeMB
    scanned_directories = $dirSet.Count
    scanned_files    = $scannedFiles
    flagged_files    = $flagged.Count
    duration_s       = [math]::Round($sw.Elapsed.TotalSeconds, 1)
  }
  $lines = ,(@($summary | ConvertTo-Json -Compress -Depth 5)) + $lines

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log INFO ("NDJSON written to {0} ({1} lines)" -f $ARLog, $lines.Count)

  Write-Host ""
  Write-Host ("Scan finished in {0:n1}s. Files={1} Flagged={2}" -f $sw.Elapsed.TotalSeconds, $scannedFiles, $flagged.Count) -ForegroundColor Cyan
  if ($flagged.Count -gt 0) {
    $flagged | Select-Object file_path, size_kb, match | Format-Table -AutoSize
  } else {
    Write-Host "No weak-secrets matches found." -ForegroundColor Green
  }
}
catch {
  Write-Log ERROR ("Failure: {0}" -f $_.Exception.Message)
  $err = @(
    (@{
      timestamp      = NowISO
      host           = $HostName
      action         = 'scan_weak_secrets'
      copilot_action = $true
      item           = 'error'
      description    = 'Unhandled error'
      error          = $_.Exception.Message
    } | ConvertTo-Json -Compress -Depth 4)
  )
  Write-NDJSONLines -JsonLines $err -Path $ARLog
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log INFO "=== SCRIPT END : duration ${dur}s ==="
}
