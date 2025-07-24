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

function Log-FlaggedJSON {
    param ($Data, [int]$DirCount, [int]$FileCount)
    $Entry = @{
        timestamp = (Get-Date).ToString('o')
        hostname  = $HostName
        type      = 'weak_secrets_flagged'
        scanned_directories = $DirCount
        scanned_files = $FileCount
        flagged = $Data
    } | ConvertTo-Json -Depth 5 -Compress
    Add-Content -Path $ARLog -Value $Entry
}

Rotate-Log -Path $LogPath -MaxKB $LogMaxKB -Keep $LogKeep

try {
    if (Test-Path $ARLog) {
        Remove-Item -Path $ARLog -Force -ErrorAction Stop
    }
    New-Item -Path $ARLog -ItemType File -Force | Out-Null
    Write-Log INFO "Active response log cleared for fresh run."
} catch {
    Write-Log WARN "Failed to clear ${ARLog}: $($_.Exception.Message)"
}

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
    Log-FlaggedJSON -Data $flagged -DirCount $dirs.Count -FileCount $files.Count
    Write-Host "Scanned $($dirs.Count) directories and $($files.Count) files." -ForegroundColor Cyan
    if ($flagged.Count -gt 0) {
        Write-Host "Found $($flagged.Count) files containing possible secrets." -ForegroundColor Yellow
        $flagged | Format-Table FilePath, SizeKB, Match, SHA256 -AutoSize
    } else {
        Write-Host "No plain-text secrets detected." -ForegroundColor Green
    }
    Write-Host "`nFlagged results (with SHA256 and scan counts) written to $ARLog" -ForegroundColor Gray
    Write-Log INFO "Scanned $($dirs.Count) dirs, $($files.Count) files. Flagged $($flagged.Count). JSON written."
}
catch {
    Write-Log ERROR "Failed to complete secret inventory: $_"
    Write-Host "ERROR: Inventory failed. See $LogPath for details." -ForegroundColor Red
}

Write-Log INFO "=== SCRIPT END : List Weak Secrets ==="
