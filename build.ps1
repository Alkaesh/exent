# build.ps1
# Run: powershell -ExecutionPolicy Bypass -File build.ps1

$Root = $PSScriptRoot
$Native = "$Root\src\native"
$Bin = "$Root\bin"

New-Item -ItemType Directory -Force -Path $Bin | Out-Null

Write-Host '=== BUILD Luna Extracted (64-bit) ===' -ForegroundColor Cyan
Write-Host "Root: $Root"

if (Get-Command cl.exe -ErrorAction SilentlyContinue) {
    $compiler = 'msvc'
    Write-Host 'Compiler: MSVC' -ForegroundColor Green
} elseif (Get-Command g++ -ErrorAction SilentlyContinue) {
    $compiler = 'mingw'
    $gppVer = & g++ --version 2>&1 | Select-Object -First 1
    Write-Host "Compiler: MinGW - $gppVer" -ForegroundColor Green
} else {
    Write-Host 'ERROR: No compiler found!' -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host '[1/2] DLL (dynamic UCRT, fully static MinGW runtime)...'

if ($compiler -eq 'msvc') {
    cl /std:c++17 /EHsc /O2 /MD /DLL "$Native\luna_extracted_native.cpp" /link /OUT:"$Bin\luna_extracted_native.dll" /MACHINE:X64 2>&1
} else {
    # -static links libgcc, libstdc++ AND libwinpthread statically (no DLL deps from MinGW runtime)
    $gccArgs = @(
        '-std=c++17', '-O2', '-m64', '-shared',
        "$Native\luna_extracted_native.cpp",
        '-static',
        '-o', "$Bin\luna_extracted_native.dll"
    )
    & g++ @gccArgs 2>&1
}

if ($LASTEXITCODE -ne 0) { Write-Host 'DLL FAIL' -ForegroundColor Red; exit 1 }
Write-Host '  DLL: OK' -ForegroundColor Green

$deps = & objdump -p "$Bin\luna_extracted_native.dll" 2>&1 | Select-String 'DLL Name'
if ($deps) {
    $deps | ForEach-Object { Write-Host "    $($_.Line.Trim())" }
} else {
    Write-Host '    (KERNEL32 + ucrtbase only)' -ForegroundColor Green
}

Write-Host '[2/2] Injector...'
if (Test-Path "$Native\manual_map.cpp") {
    if ($compiler -eq 'msvc') {
        cl /std:c++17 /EHsc /O2 "$Native\manual_map.cpp" /link /OUT:"$Bin\manual_map.exe" /MACHINE:X64 2>&1
    } else {
        $injArgs = @(
            '-std=c++17', '-O2', '-m64', '-municode',
            "$Native\manual_map.cpp",
            '-static',
            '-o', "$Bin\manual_map.exe"
        )
        & g++ @injArgs 2>&1
    }
    if ($LASTEXITCODE -ne 0) { Write-Host 'Injector FAIL' -ForegroundColor Red; exit 1 }
    Write-Host '  Injector: OK' -ForegroundColor Green
}

Write-Host ''
Write-Host '=== DONE ===' -ForegroundColor Green
Write-Host 'Run: .\bin\manual_map.exe .\bin\luna_extracted_native.dll --process RobloxPlayerBeta.exe' -ForegroundColor Yellow
