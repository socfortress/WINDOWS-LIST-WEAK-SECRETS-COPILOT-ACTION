[CmdletBinding()]
param (
    [string]$LogPath = "$env:TEMP\List-WeakSecrets.log",
    [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log',
    [string]$RootDir = 'C:\',
    [switch]$ExcludeSystem,
    [int]$MaxSizeMB = 50
)

$ErrorActionPreference = 'Stop'
$HostName  = $env:COMPUTERNAME
$LogMaxKB  = 100
$LogKeep   = 5

function Rotate-Log {
    param ([string]$Path, [int]$MaxKB, [int]$Keep)
    if (Test-Path $Path) {
        $SizeKB = (Get-Item $Path).Length / 1KB
        if ($SizeKB -ge $MaxKB) {
            for ($i = $Keep; $i -ge 1; $i--) {
                $Old = "$Path.$i"
                $New = "$Path.$($i + 1)"
                if (Test-Path $Old) { Rename-Item $Old $New -Force }
            }
            Rename-Item $Path "$Path.1" -Force
        }
    }
}

function Write-Log {
    param ([string]$Level, [string]$Message)
    $Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    Add-Content -Path $LogPath -Value "[$Timestamp][$Level] $Message"
}

function Get-FileHashSHA256 {
    param ([string]$FilePath)
    try {
        $hash = Get-FileHash -Algorithm SHA256 -Path $FilePath -ErrorAction Stop
        return $hash.Hash
    } catch {
        return $null
    }
}

Rotate-Log -Path $LogPath -MaxKB $LogMaxKB -Keep $LogKeep

Write-Log INFO "=== SCRIPT START : List Weak Secrets (Configurable) ==="
Write-Log INFO "Scanning $RootDir (ExcludeSystem=$ExcludeSystem, MaxSizeMB=$MaxSizeMB)"

try {
    $searchPatterns = @("*.env","*.ini","*.txt","*.json")
    $keywordPatterns = @('password\s*=','apikey\s*=','secret\s*=','token\s*=')

    $allItems = Get-ChildItem -Path $RootDir -Recurse -Include $searchPatterns -ErrorAction SilentlyContinue
    $dirs = $allItems | Where-Object { $_.PSIsContainer }
    $files = $allItems | Where-Object { -not $_.PSIsContainer }

    if ($ExcludeSystem) {
        $files = $files | Where-Object {
            $_.FullName -notmatch '^C:\\Windows' -and
            $_.FullName -notmatch '^C:\\Program Files' -and
            $_.FullName -notmatch '^C:\\Program Files \(x86\)' -and
            $_.FullName -notmatch '^C:\\ProgramData'
        }
    }

    $files = $files | Where-Object { $_.Length -lt ($MaxSizeMB * 1MB) }

    $flagged = @()
    foreach ($file in $files) {
        $content = ""
        try {
            $content = Get-Content -Path $file.FullName -ErrorAction SilentlyContinue -Raw -Encoding UTF8
        } catch {}
        foreach ($pattern in $keywordPatterns) {
            if ($content -match $pattern) {
                $sha256 = Get-FileHashSHA256 -FilePath $file.FullName
                $flagged += [PSCustomObject]@{
                    FilePath = $file.FullName
                    SizeKB   = [math]::Round($file.Length / 1KB, 2)
                    Match    = $pattern
                    SHA256   = $sha256
                }
                break
            }
        }
    }
    $report = [PSCustomObject]@{
        timestamp = (Get-Date).ToString('o')
        hostname  = $HostName
        type      = 'weak_secrets_flagged'
        scanned_directories = $dirs.Count
        scanned_files       = $files.Count
        flagged             = $flagged
        copilot_action = $true
    }
    $json = $report | ConvertTo-Json -Depth 5 -Compress
    $tempFile = "$env:TEMP\arlog.tmp"
    Set-Content -Path $tempFile -Value $json -Encoding ascii -Force

    try {
        Move-Item -Path $tempFile -Destination $ARLog -Force
        Write-Log INFO "Log file replaced at $ARLog"
    } catch {
        Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
        Write-Log WARN "Log locked, wrote results to $ARLog.new"
    }

    Write-Host "Scanned $($dirs.Count) directories and $($files.Count) files." -ForegroundColor Cyan
    if ($flagged.Count -gt 0) {
        Write-Host "Found $($flagged.Count) files containing possible secrets." -ForegroundColor Yellow
        $flagged | Format-Table FilePath, SizeKB, Match, SHA256 -AutoSize
    } else {
        Write-Host "No plain-text secrets detected." -ForegroundColor Green
    }
    Write-Host "`nResults written to $ARLog (or .new if locked)" -ForegroundColor Gray
    Write-Log INFO "Scan complete. Flagged $($flagged.Count) files. JSON written."
}
catch {
    Write-Log ERROR "Failed to complete secret inventory: $_"

    $errorObj = [PSCustomObject]@{
        timestamp = (Get-Date).ToString('o')
        hostname  = $HostName
        type      = 'weak_secrets_flagged'
        status    = 'error'
        error     = $_.Exception.Message
        copilot_action = $true
    }
    $json = $errorObj | ConvertTo-Json -Compress
    $fallback = "$ARLog.new"
    Set-Content -Path $fallback -Value $json -Encoding ascii -Force
    Write-Log WARN "Error logged to $fallback"
}

Write-Log INFO "=== SCRIPT END : List Weak Secrets ==="

