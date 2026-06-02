# luna_extracted runtime

The injected runtime is now provided by the native C++ DLL source in:

- [luna_extracted_native.cpp](D:/roblox/analysis/injector_project/src/native/luna_extracted_native.cpp)

This Go source tree remains here as legacy/reference material. The active build output used by the injector is [luna_extracted_native.dll](D:/roblox/analysis/injector_project/bin/luna_extracted_native.dll).

## Build

```powershell
cd /d D:\roblox\analysis\injector_project\src\go_legacy\luna_extracted_src
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

If the DLL is built with MinGW-w64, `bin\libwinpthread-1.dll` should stay next to `bin\luna_extracted_native.dll`. The build script copies it automatically when available.

## Runtime behavior

- `LoadLibraryW` only loads the module.
- `StartRuntimeThreadProc` starts the worker thread and writes `ready.json`.
- command files are consumed from `%TEMP%\luna_extracted\<pid>\commands`
- ack files are written to `%TEMP%\luna_extracted\<pid>\acks`
- confirmed runtime events are appended to `%TEMP%\luna_extracted\<pid>\runtime.log`

## Exported symbols

- `DllMain`
- `StartRuntimeThreadProc`
- `ExecuteScript`
- `ProcessQ`
- `GoDrawLoop`
- `GoIndex`
- `GoLunaGateway`
- `GoNamecall`
- `GoStepHookPayload`
- `free_go_handle`
- `go_lua_callback`
