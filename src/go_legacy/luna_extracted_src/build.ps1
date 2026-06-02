Set-Location -Path $PSScriptRoot
$projectRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$sourceFile = Join-Path $projectRoot "src\native\luna_extracted_native.cpp"
$outputDir = Join-Path $projectRoot "bin"
$outputDll = Join-Path $outputDir "luna_extracted_native.dll"

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

if (-not (Test-Path $sourceFile)) {
    Write-Error "Native DLL source not found: $sourceFile"
    exit 1
}

if (Get-Command g++ -ErrorAction SilentlyContinue) {
    g++ -std=c++17 -O2 -shared $sourceFile -o $outputDll -static-libgcc -static-libstdc++
    if ($LASTEXITCODE -eq 0) {
        $gppPath = (Get-Command g++).Source
        $gppDir = Split-Path -Parent $gppPath
        $pthreadDll = Join-Path $gppDir "libwinpthread-1.dll"
        if (Test-Path $pthreadDll) {
            Copy-Item $pthreadDll (Join-Path $outputDir "libwinpthread-1.dll") -Force
            Write-Host "Runtime copied: $(Join-Path $outputDir 'libwinpthread-1.dll')"
        }
        Write-Host "Build completed: $outputDll"
        exit 0
    }
}

if (Get-Command cl.exe -ErrorAction SilentlyContinue) {
    Push-Location (Join-Path $projectRoot "src\native")
    cl /std:c++17 /EHsc /O2 /LD luna_extracted_native.cpp /link /OUT:$outputDll
    $exitCode = $LASTEXITCODE
    Pop-Location
    if ($exitCode -eq 0) {
        Write-Host "Build completed: $outputDll"
        exit 0
    }
}

Write-Error "Failed to build native luna_extracted runtime. Install MinGW-w64 g++ or MSVC Build Tools."
exit 1
