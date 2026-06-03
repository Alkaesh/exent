# build.ps1 — Force 64-bit build with verification
# Run: powershell -ExecutionPolicy Bypass -File build.ps1

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
    
    # CHECK: does g++ support 64-bit?
    $gppVer = & g++ --version 2>&1 | Select-Object -First 1
    Write-Host "  $gppVer"
    
    # Test if -m64 works
    $testSrc = "$env:TEMP\_arch_test.cpp"
    $testOut = "$env:TEMP\_arch_test.exe"
    "int main(){return 0;}" | Out-File -Encoding ASCII $testSrc
    & g++ -m64 $testSrc -o $testOut 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: g++ does not support -m64!" -ForegroundColor Red
        Write-Host "You have 32-bit MinGW installed." -ForegroundColor Red
        Write-Host "Download 64-bit MinGW from: https://winlibs.com/" -ForegroundColor Yellow
        Write-Host "Choose: GCC x86_64-posix-seh + LLVM" -ForegroundColor Yellow
        Write-Host "Add its bin/ folder to PATH and restart terminal." -ForegroundColor Yellow
        Remove-Item $testSrc -Force -ErrorAction SilentlyContinue
        exit 1
    }
    Remove-Item $testSrc, $testOut -Force -ErrorAction SilentlyContinue
    Write-Host "  64-bit support: OK" -ForegroundColor Green
} else {
    Write-Host "ERROR: No compiler found!" -ForegroundColor Red
    Write-Host "Download: https://winlibs.com/ (x86_64-posix-seh)" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

if (-not (Test-Path "$Native\injector.cpp")) {
    Write-Host "ERROR: $Native\injector.cpp not found!" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path "$Native\luna_extracted_native.cpp")) {
    Write-Host "ERROR: $Native\luna_extracted_native.cpp not found!" -ForegroundColor Red
    exit 1
}

Write-Host "[1/2] Building DLL..."
if ($compiler -eq "msvc") {
    cl /std:c++17 /EHsc /O2 /MD /DLL "$Native\luna_extracted_native.cpp" /link /OUT:"$Bin\luna_extracted_native.dll" /MACHINE:X64 2>&1
} else {
    g++ -std=c++17 -O2 -m64 -shared "$Native\luna_extracted_native.cpp" -static-libgcc -static-libstdc++ -o "$Bin\luna_extracted_native.dll" 2>&1
}
if ($LASTEXITCODE -ne 0) { Write-Host "FAIL" -ForegroundColor Red; exit 1 }

# VERIFY DLL architecture
$objResult = & objdump -f "$Bin\luna_extracted_native.dll" 2>&1 | Select-String "architecture"
Write-Host "  $objResult"
if ($objResult -match "i386") {
    Write-Host "  ERROR: DLL built as 32-bit!" -ForegroundColor Red
    Write-Host "  Your MinGW is 32-bit only. Install 64-bit version." -ForegroundColor Red
    Write-Host "  https://winlibs.com/ — choose x86_64-posix-seh" -ForegroundColor Yellow
    exit 1
}
Write-Host "  OK: $Bin\luna_extracted_native.dll" -ForegroundColor Green

Write-Host "[2/2] Building injector..."
if ($compiler -eq "msvc") {
    cl /std:c++17 /EHsc /O2 "$Native\injector.cpp" /link /OUT:"$Bin\injector_cli.exe" /MACHINE:X64 2>&1
} else {
    g++ -std=c++17 -O2 -m64 -municode "$Native\injector.cpp" -static-libgcc -static-libstdc++ -o "$Bin\injector_cli.exe" 2>&1
}
if ($LASTEXITCODE -ne 0) { Write-Host "FAIL" -ForegroundColor Red; exit 1 }

$objResult = & objdump -f "$Bin\injector_cli.exe" 2>&1 | Select-String "architecture"
Write-Host "  $objResult"
if ($objResult -match "i386") {
    Write-Host "  ERROR: Built as 32-bit!" -ForegroundColor Red; exit 1
}
Write-Host "  OK: $Bin\injector_cli.exe" -ForegroundColor Green

Write-Host ""
Write-Host "=== DONE ===" -ForegroundColor Green
Write-Host ""
Write-Host "Run:" -ForegroundColor White
Write-Host "  python src\python\custom_injector.py --process RobloxPlayerBeta --check-arch" -ForegroundColor Yellow
Write-Host "  .\bin\injector_cli.exe .\bin\luna_extracted_native.dll --process RobloxPlayerBeta.exe" -ForegroundColor Yellow
