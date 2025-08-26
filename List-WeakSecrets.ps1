[CmdletBinding()]
param(
  [string]$LogPath="$env:TEMP\List-WeakSecrets.log",
  [string]$ARLog='C:\Program Files (x86)\ossec-agent\active-response\active-responses.log',
  [switch]$NoProgress
)

$ErrorActionPreference='Stop'
$HostName=$env:COMPUTERNAME
$LogMaxKB=100
$LogKeep=5
$MaxSizeMB=50

$logDir=Split-Path -Path $LogPath -Parent
if(-not (Test-Path $logDir)){New-Item -Path $logDir -ItemType Directory -Force | Out-Null}
if(-not (Test-Path $LogPath)){New-Item -Path $LogPath -ItemType File -Force | Out-Null}

function Rotate-Log{
  param([string]$Path,[int]$MaxKB,[int]$Keep)
  if(Test-Path $Path){
    $SizeKB=[math]::Ceiling((Get-Item $Path).Length/1KB)
    if($SizeKB -ge $MaxKB){
      for($i=$Keep-1;$i -ge 1;$i--){$s="$Path.$i";$d="$Path." + ($i+1);if(Test-Path $s){Move-Item $s $d -Force}}
      Move-Item $Path "$Path.1" -Force
    }
  }
}

function Write-Log{
  param([string]$Level,[string]$Message)
  $Timestamp=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  Add-Content -Path $LogPath -Value "[$Timestamp][$Level] $Message" -Encoding utf8
}

function Get-FileHashSHA256{
  param([string]$FilePath)
  try{(Get-FileHash -Algorithm SHA256 -Path $FilePath -ErrorAction Stop).Hash}catch{$null}
}

function Write-NDJSONLines{
  param([string[]]$JsonLines)
  $tmp=Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  Set-Content -Path $tmp -Value ($JsonLines -join [Environment]::NewLine) -Encoding ascii -Force
  try{Move-Item -Path $tmp -Destination $ARLog -Force}catch{Move-Item -Path $tmp -Destination ($ARLog+'.new') -Force}
}

function Now-Timestamp{
  $tz=(Get-Date).ToString('zzz').Replace(':','')
  (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')+$tz
}

Rotate-Log -Path $LogPath -MaxKB $LogMaxKB -Keep $LogKeep
Write-Log INFO "BOOT"
Write-Host ("[{0}] Starting List-WeakSecrets full-system scan on C:\ (MaxSizeMB={1})" -f (Get-Date).ToString('HH:mm:ss'),$MaxSizeMB)

$searchPatterns=@('*.env','*.ini','*.txt','*.json')
$keywordPatterns=@('password\s*=','apikey\s*=','secret\s*=','token\s*=')

$ts=Now-Timestamp
$scannedFiles=0
$flagged=@()
$dirSet=[System.Collections.Generic.HashSet[string]]::new()
$sw=[System.Diagnostics.Stopwatch]::StartNew()

try{
  Get-ChildItem -Path 'C:\' -Recurse -Include $searchPatterns -File -Force -ErrorAction SilentlyContinue |
  ForEach-Object {
    $f=$_
    if($f.Length -ge ($MaxSizeMB*1MB)){ return }
    $null=$dirSet.Add($f.DirectoryName)
    $scannedFiles+=1
    if(-not $NoProgress -and ($scannedFiles % 200 -eq 0)){
      Write-Progress -Activity "Scanning C:\" -Status ("files={0} flagged={1}" -f $scannedFiles,$flagged.Count) -PercentComplete 0
      Write-Host -NoNewline "."
    }
    $content=''
    try{$content=Get-Content -Path $f.FullName -ErrorAction SilentlyContinue -Raw -Encoding UTF8}catch{}
    foreach($pattern in $keywordPatterns){
      if($content -match $pattern){
        $sha=Get-FileHashSHA256 -FilePath $f.FullName
        $flagged+=[PSCustomObject]@{FilePath=$f.FullName;SizeKB=[math]::Round($f.Length/1KB,2);Match=$pattern;SHA256=$sha}
        break
      }
    }
  }
}
catch{
  Write-Log ERROR ("Failure: {0}" -f $_)
  $err=([PSCustomObject]@{timestamp=Now-Timestamp;host=$HostName;action='List-WeakSecrets';copilot_action=$true;type='error';error=$_.Exception.Message}|ConvertTo-Json -Compress -Depth 3)
  Write-NDJSONLines -JsonLines @($err)
  if(-not $NoProgress){Write-Progress -Activity "Scanning C:\" -Completed}
  throw
}

if(-not $NoProgress){Write-Progress -Activity "Scanning C:\" -Completed}
$sw.Stop()
Write-Host ""
Write-Host ("[{0}] Scan finished in {1:n1}s. Files={2} Flagged={3}" -f (Get-Date).ToString('HH:mm:ss'),$sw.Elapsed.TotalSeconds,$scannedFiles,$flagged.Count)

$summary=[PSCustomObject]@{
  timestamp=$ts
  host=$HostName
  action='List-WeakSecrets'
  copilot_action=$true
  type='summary'
  root_dir='C:\'
  max_size_mb=$MaxSizeMB
  scanned_directories=$dirSet.Count
  scanned_files=$scannedFiles
  flagged_files=$flagged.Count
  duration_s=[math]::Round($sw.Elapsed.TotalSeconds,1)
}

$lines=@()
$lines+=($summary|ConvertTo-Json -Compress -Depth 4)
foreach($f in $flagged){
  $lines+=([PSCustomObject]@{
    timestamp=$ts
    host=$HostName
    action='List-WeakSecrets'
    copilot_action=$true
    type='weak_secret'
    file_path=$f.FilePath
    size_kb=$f.SizeKB
    match=$f.Match
    sha256=$f.SHA256
  }|ConvertTo-Json -Compress -Depth 4)
}

Write-NDJSONLines -JsonLines $lines
Write-Log INFO ("NDJSON written to {0}" -f $ARLog)
