# build.ps1
# Save this file to C:\Users\alga\Downloads\exent-main\exent-main\
# Then run: powershell -ExecutionPolicy Bypass -File build.ps1

$Root = "C:\Users\alga\Downloads\exent-main\exent-main"
$Native = "$Root\src\native"
$Bin = "$Root\bin"

New-Item -ItemType Directory -Force -Path $Bin | Out-Null

Write-Host "=== BUILD Luna Extracted (64-bit) ===" -ForegroundColor Cyan
Write-Host "Root: $Root"

if (Get-Command cl.exe -ErrorAction SilentlyContinue) {
    $compiler = "msvc"
    Write-Host "Compiler: MSVC" -ForegroundColor Green
} elseif (Get-Command g++ -ErrorAction SilentlyContinue) {
    $compiler = "mingw"
    Write-Host "Compiler: MinGW" -ForegroundColor Green
} else {
    Write-Host "ERROR: No compiler found!" -ForegroundColor Red
    exit 1
}

Write-Host "[1/2] Building DLL..."
if ($compiler -eq "msvc") {
    cl /std:c++17 /EHsc /O2 /MD /DLL "$Native\luna_extracted_native.cpp" /link /OUT:"$Bin\luna_extracted_native.dll" /MACHINE:X64 2>&1
} else {
    g++ -std=c++17 -O2 -m64 -shared "$Native\luna_extracted_native.cpp" -static-libgcc -static-libstdc++ -o "$Bin\luna_extracted_native.dll" 2>&1
}
if ($LASTEXITCODE -ne 0) { Write-Host "DLL build FAILED" -ForegroundColor Red; exit 1 }
Write-Host "  OK: $Bin\luna_extracted_native.dll" -ForegroundColor Green

Write-Host "[2/2] Building injector..."
if ($compiler -eq "msvc") {
    cl /std:c++17 /EHsc /O2 "$Native\injector.cpp" /link /OUT:"$Bin\injector_cli.exe" /MACHINE:X64 2>&1
} else {
    g++ -std=c++17 -O2 -m64 -municode "$Native\injector.cpp" -static-libgcc -static-libstdc++ -o "$Bin\injector_cli.exe" 2>&1
}
if ($LASTEXITCODE -ne 0) { Write-Host "Injector build FAILED" -ForegroundColor Red; exit 1 }
Write-Host "  OK: $Bin\injector_cli.exe" -ForegroundColor Green

Write-Host ""
Write-Host "=== DONE ===" -ForegroundColor Green
Write-Host "Run: $Bin\injector_cli.exe $Bin\luna_extracted_native.dll --process RobloxPlayerBeta.exe" -ForegroundColor Yellow
