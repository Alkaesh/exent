# Build Instructions

Project layout:

- `src/native`: C++ sources
- `src/python`: Python helper
- `src/go_legacy/luna_extracted_src`: legacy Go source tree
- `bin`: built executables and DLLs
- `scripts`: helper PowerShell scripts

## GUI injector

```powershell
cd /d D:\roblox\analysis\injector_project
g++ -std=c++17 -O2 -municode -mwindows .\src\native\injector_ui.cpp -lcomdlg32 -lgdi32 -lshell32 -o .\bin\injector.exe
```

## CLI injector

```powershell
cd /d D:\roblox\analysis\injector_project
g++ -std=c++17 -O2 -municode .\src\native\injector.cpp -o .\bin\injector_cli.exe
```

## Native DLL

```powershell
cd /d D:\roblox\analysis\injector_project\src\go_legacy\luna_extracted_src
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

If built with MinGW-w64, keep `bin\libwinpthread-1.dll` next to `bin\luna_extracted_native.dll`.

Equivalent direct build:

```powershell
cd /d D:\roblox\analysis\injector_project
g++ -std=c++17 -O2 -shared .\src\native\luna_extracted_native.cpp -o .\bin\luna_extracted_native.dll -static-libgcc -static-libstdc++
```

## Runtime contract

After `StartRuntimeThreadProc` runs inside the injected module:

- ready file: `%TEMP%\luna_extracted\<pid>\ready.json`
- command queue: `%TEMP%\luna_extracted\<pid>\commands\<command-id>.json`
- acknowledgements: `%TEMP%\luna_extracted\<pid>\acks\<command-id>.json`
- confirmed runtime log: `%TEMP%\luna_extracted\<pid>\runtime.log`

Confirmed states:

- `module loaded`
- `runtime ready`
- `accepted`
- `executed`
