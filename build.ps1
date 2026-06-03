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
} else {
    Write-Host 'ERROR: No compiler found!' -ForegroundColor Red
    exit 1
}

Write-Host ''

# === DLL with FULL static linking ===
Write-Host '[1/3] DLL (full static)...'
if ($compiler -eq 'msvc') {
    cl /std:c++17 /EHsc /O2 /MT /DLL "$Native\luna_extracted_native.cpp" /link /OUT:"$Bin\luna_extracted_native.dll" /MACHINE:X64 2>&1
} else {
    # FULL static: -static links EVERYTHING statically (libgcc, libstdc++, libwinpthread)
    # -Wl,--exclude-all-symbols reduces export table size
    g++ -std=c++17 -O2 -m64 -shared "$Native\luna_extracted_native.cpp" -static -o "$Bin\luna_extracted_native.dll" 2>&1
}
if ($LASTEXITCODE -ne 0) { Write-Host 'FAIL' -ForegroundColor Red; exit 1 }

$arch = & objdump -f "$Bin\luna_extracted_native.dll" 2>&1 | Select-String 'architecture'
Write-Host "  $($arch.Line.Trim())"
if ($arch -match 'x86-64') { Write-Host '  DLL: 64-bit OK' -ForegroundColor Green }
elseif ($arch -match 'i386' -and $arch -notmatch 'x86-64') { Write-Host '  ERROR: 32-bit!' -ForegroundColor Red; exit 1 }
else { Write-Host '  DLL: OK' -ForegroundColor Green }

# Check for dynamic deps we don't want
$deps = & objdump -p "$Bin\luna_extracted_native.dll" 2>&1 | Select-String 'DLL Name'
Write-Host '  DLL deps:'
$deps | ForEach-Object { Write-Host "    $($_.Line.Trim())" }
if ($deps -match 'libwinpthread' -or $deps -match 'libstdc\+\+' -or $deps -match 'libgcc') {
    Write-Host '  WARN: Dynamic runtime dep detected! Should be static.' -ForegroundColor Yellow
}

# === CLI Injector ===
if (Test-Path "$Native\injector.cpp") {
    Write-Host '[2/3] CLI Injector...'
    if ($compiler -eq 'msvc') {
        cl /std:c++17 /EHsc /O2 "$Native\injector.cpp" /link /OUT:"$Bin\injector_cli.exe" /MACHINE:X64 2>&1
    } else {
        g++ -std=c++17 -O2 -m64 -municode "$Native\injector.cpp" -static -o "$Bin\injector_cli.exe" 2>&1
    }
    if ($LASTEXITCODE -ne 0) { Write-Host 'FAIL' -ForegroundColor Red; exit 1 }
    $arch = & objdump -f "$Bin\injector_cli.exe" 2>&1 | Select-String 'architecture'
    Write-Host "  $($arch.Line.Trim())"
    if ($arch -match 'x86-64') { Write-Host '  Injector: 64-bit OK' -ForegroundColor Green }
    else { Write-Host '  Injector: OK' -ForegroundColor Green }
}

# === Manual Map ===
if (Test-Path "$Native\manual_map.cpp") {
    Write-Host '[3/3] Manual Map...'
    if ($compiler -eq 'msvc') {
        cl /std:c++17 /EHsc /O2 "$Native\manual_map.cpp" /link /OUT:"$Bin\manual_map.exe" /MACHINE:X64 2>&1
    } else {
        g++ -std=c++17 -O2 -m64 -municode "$Native\manual_map.cpp" -static -o "$Bin\manual_map.exe" 2>&1
    }
    if ($LASTEXITCODE -ne 0) { Write-Host 'FAIL' -ForegroundColor Red; exit 1 }
    $arch = & objdump -f "$Bin\manual_map.exe" 2>&1 | Select-String 'architecture'
    Write-Host "  $($arch.Line.Trim())"
    if ($arch -match 'x86-64') { Write-Host '  Manual Map: 64-bit OK' -ForegroundColor Green }
    else { Write-Host '  Manual Map: OK' -ForegroundColor Green }
}

Write-Host ''
Write-Host '=== DONE ===' -ForegroundColor Green
Write-Host 'Run: .\bin\manual_map.exe .\bin\luna_extracted_native.dll --process RobloxPlayerBeta.exe' -ForegroundColor Yellow
