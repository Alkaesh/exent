$projectRoot = Split-Path -Parent $PSScriptRoot
$sourceRoot = Join-Path $projectRoot "src\native"
$binRoot = Join-Path $projectRoot "bin"

New-Item -ItemType Directory -Force -Path $binRoot | Out-Null

if (Get-Command g++ -ErrorAction SilentlyContinue) {
    Push-Location $projectRoot
    g++ -std=c++17 -O2 -municode -mwindows (Join-Path $sourceRoot "injector_ui.cpp") -lcomdlg32 -lgdi32 -lshell32 -o (Join-Path $binRoot "injector.exe")
    $guiExit = $LASTEXITCODE
    if ($guiExit -eq 0) {
        g++ -std=c++17 -O2 -municode (Join-Path $sourceRoot "injector.cpp") -o (Join-Path $binRoot "injector_cli.exe")
        $cliExit = $LASTEXITCODE
        Pop-Location
        if ($cliExit -eq 0) {
            Write-Host "Build completed:"
            Write-Host "  $binRoot\injector.exe"
            Write-Host "  $binRoot\injector_cli.exe"
            exit 0
        }
        Write-Error "CLI injector build failed."
        exit $cliExit
    }
    Pop-Location
    Write-Error "GUI injector build failed."
    exit $guiExit
}

if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    Write-Error "No supported compiler found. Install MinGW-w64 g++ or MSVC Build Tools."
    exit 1
}

Push-Location $sourceRoot
cl /std:c++17 /EHsc /W4 /O2 injector_ui.cpp /link /SUBSYSTEM:WINDOWS /OUT:$binRoot\injector.exe
$guiExit = $LASTEXITCODE
if ($guiExit -eq 0) {
    cl /std:c++17 /EHsc /W4 /O2 injector.cpp /link /OUT:$binRoot\injector_cli.exe
    $cliExit = $LASTEXITCODE
    Pop-Location
    if ($cliExit -eq 0) {
        Write-Host "Build completed:"
        Write-Host "  $binRoot\injector.exe"
        Write-Host "  $binRoot\injector_cli.exe"
        exit 0
    }
    Write-Error "CLI injector build failed."
    exit $cliExit
}
Pop-Location
Write-Error "GUI injector build failed."
exit $guiExit
