param(
    [int]$TargetPid,
    [switch]$Follow
)

$runtimeRoot = Join-Path $env:TEMP "luna_extracted"
if (-not (Test-Path $runtimeRoot)) {
    Write-Host "Runtime log directory not found yet: $runtimeRoot"
    Write-Host "Start the DLL once, then run this script again."
    exit 0
}

function Get-LatestRuntimeDir {
    Get-ChildItem -Path $runtimeRoot -Directory |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

if ($TargetPid) {
    $targetDir = Join-Path $runtimeRoot $TargetPid
    if (-not (Test-Path $targetDir)) {
        Write-Error "PID directory not found: $targetDir"
        exit 1
    }
} else {
    $latest = Get-LatestRuntimeDir
    if (-not $latest) {
        Write-Host "No runtime directories found in $runtimeRoot"
        Write-Host "Start the DLL once, then run this script again."
        exit 0
    }
    $targetDir = $latest.FullName
}

$logPath = Join-Path $targetDir "runtime.log"
if (-not (Test-Path $logPath)) {
    Write-Host "Runtime log not found yet: $logPath"
    Write-Host "Wait until the DLL writes its first confirmed events."
    exit 0
}

Write-Host "Runtime log: $logPath"

if ($Follow) {
    Get-Content -Path $logPath -Wait
} else {
    Get-Content -Path $logPath
}
