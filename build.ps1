# build.ps1
# Run: powershell -ExecutionPolicy Bypass -File build.ps1

$Root = 'C:\Users\alga\Downloads\exent-main\exent-main'
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
    $machine = & g++ -dumpmachine 2>&1
    Write-Host "  Target: $machine"
    if ($machine -match 'i686') {
        Write-Host '  WARN: 32-bit compiler! 64-bit DLL may fail.' -ForegroundColor Red
    }
} else {
    Write-Host 'ERROR: No compiler found!' -ForegroundColor Red
    exit 1
}

Write-Host ''

if (-not (Test-Path "$Native\injector.cpp")) {
    Write-Host "ERROR: $Native\injector.cpp not found!" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path "$Native\luna_extracted_native.cpp")) {
    Write-Host "ERROR: $Native\luna_extracted_native.cpp not found!" -ForegroundColor Red
    exit 1
}

# === DLL ===
Write-Host '[1/2] DLL...'
if ($compiler -eq 'msvc') {
    cl /std:c++17 /EHsc /O2 /MD /DLL "$Native\luna_extracted_native.cpp" /link /OUT:"$Bin\luna_extracted_native.dll" /MACHINE:X64 2>&1
} else {
    g++ -std=c++17 -O2 -m64 -shared "$Native\luna_extracted_native.cpp" -static-libgcc -static-libstdc++ -o "$Bin\luna_extracted_native.dll" 2>&1
}
if ($LASTEXITCODE -ne 0) { Write-Host 'FAIL' -ForegroundColor Red; exit 1 }

$arch = & objdump -f "$Bin\luna_extracted_native.dll" 2>&1 | Select-String 'architecture'
Write-Host "  $($arch.Line.Trim())"
if ($arch -match 'x86-64') {
    Write-Host '  DLL: 64-bit OK' -ForegroundColor Green
} elseif ($arch -match 'i386' -and $arch -notmatch 'x86-64') {
    Write-Host '  ERROR: DLL is 32-bit!' -ForegroundColor Red
    Write-Host '  Install 64-bit MinGW: https://winlibs.com/ (x86_64-posix-seh)' -ForegroundColor Yellow
    exit 1
} else {
    Write-Host '  DLL: OK' -ForegroundColor Green
}

# === INJECTOR ===
Write-Host '[2/2] Injector...'
if ($compiler -eq 'msvc') {
    cl /std:c++17 /EHsc /O2 "$Native\injector.cpp" /link /OUT:"$Bin\injector_cli.exe" /MACHINE:X64 2>&1
} else {
    g++ -std=c++17 -O2 -m64 -municode "$Native\injector.cpp" -static-libgcc -static-libstdc++ -o "$Bin\injector_cli.exe" 2>&1
}
if ($LASTEXITCODE -ne 0) { Write-Host 'FAIL' -ForegroundColor Red; exit 1 }

$arch = & objdump -f "$Bin\injector_cli.exe" 2>&1 | Select-String 'architecture'
Write-Host "  $($arch.Line.Trim())"
if ($arch -match 'x86-64') {
    Write-Host '  Injector: 64-bit OK' -ForegroundColor Green
} elseif ($arch -match 'i386' -and $arch -notmatch 'x86-64') {
    Write-Host '  ERROR: 32-bit!' -ForegroundColor Red; exit 1
} else {
    Write-Host '  Injector: OK' -ForegroundColor Green
}

Write-Host ''
Write-Host '=== DONE ===' -ForegroundColor Green
Write-Host 'Run: .\bin\injector_cli.exe .\bin\luna_extracted_native.dll --process RobloxPlayerBeta.exe' -ForegroundColor Yellow
