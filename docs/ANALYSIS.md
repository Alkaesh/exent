# Luna — Reverse Engineering Analysis

> Roblox script executor. Wails (Go) GUI launcher + injected Go `c-shared` DLL core.
> Analysis combines static artifacts (strings, exports/imports, Go buildinfo) and
> a live IDA Pro session over the IDA-Pro-MCP JSON-RPC endpoint (`http://localhost:13337/mcp`).

## 1. Artifacts / Identity

| Item | Value |
|---|---|
| DLL | `luna_extracted.dll` (~9.68 MB) |
| EXE | `Luna_unpacked.exe` (Wails v3 launcher) |
| DLL toolchain | Go 1.24.13, `-buildmode=c-shared`, CGO_ENABLED=1, GOARCH=amd64, GOOS=windows |
| EXE toolchain | Go 1.26.3, `-buildmode=exe`, `-tags=production`, Wails v3.0.0-alpha.96 + webview2 |
| DLL base (IDA) | `0x2061c0000` |
| DLL SHA-256 | `21e0d572354eb8fe0fa1371648da7ea45b668ef9979660fcc6ec469d4e919840` |
| DLL MD5 | `030334d345657e9af2ae88f800376d3a` |
| Product | `Luna.exe`, version `0.1.0` |

Frontend (`reference/frontend/`): single-page app, `<title>Luna</title>`, Monaco editor,
`luaparse`, jQuery. Editor scripts stored under `luna/workspace`.

## 2. Exports (injection-side entry points)

| Export | Ordinal | RVA | Role |
|---|---|---|---|
| `DllMain` | 1 | 0x2f24c0 | DLL entry |
| `GoDrawLoop` | 2 | 0x2f2480 | ImGui overlay render loop |
| `GoIndex` | 3 | 0x3cfc90 | Luau `__index` metamethod hook |
| `GoLunaGateway` | 4 | 0x3cfb40 | main command gateway |
| `GoNamecall` | 5 | 0x3cfce0 | Luau `__namecall` metamethod hook |
| `GoStepHookPayload` | 6 | 0x3cfba0 | engine step/heartbeat hook (runs queued work) |
| `ProcessQ` | 7 | 0x2f2440 | process task queue |
| `_cgo_dummy_export` | 8 | 0x97d230 | cgo |
| `free_go_handle` | 9 | 0x3cfc50 | release cgo handle |
| `go_lua_callback` | 10 | 0x3cfbf0 | C→Go Lua callback dispatch |

IDA also shows `TlsCallback_0..2` (Go runtime init / anti-debug hooks) and `DllEntryPoint`.

## 3. Go package layout (`main/packages/...`)

- `onyx/mem` — process memory: `ReadProcessMemory[T]`, `WriteProcessMemory`, `GetModuleBase`,
  `EnumModules`, `ValidPtr`, `(*Luna).ReadRaw`.
- `onyx/mem/aob` — AOB scanner: `OptimizedScan`, `OptimizedCompiledPattern.FastScan`,
  `ExactMatch`, `RangedMatch`, `NewPatternFromBytes`, `PointerWalk[T]`, `reconstructPath`,
  `getMemoryRegions`, `RTTIScanMatcher`.
- `onyx/mem/rtti` — MSVC RTTI parse + demangle (`Demangle`, `extractRTTIName`,
  `fixRTTIDemangling`, `removeTypePrefix`) via cgo `demangleMSVC`.
- `onyx/mem/renderview` — `RenderView`, `(*Render).DataModel`, `(*Render).Container`,
  `(*Container).Jobs/Job` → roots of the game tree (RenderJob → DataModel).
- `onyx/instance` — Roblox Instance wrapper: `Name`, `ClassName`, `Children`, `Traverse`,
  `NewInstance`.
- `onyx/logic` — `Session`, `GetHWNDFromPID`, `Task`.
- `onyx/logic/luau/Api` — full Luau C API binding + executor logic (see §5).
- `api/managers/imgui` — ImGui overlay (`Editor_Init/Render/SetText/GetText`,
  `Im_Begin/Button/End/Notify/Separator/Spacing/SetNextWindowSize`), notify queue.
- `api/env/*` — sandbox env: `closures`, `scripts`, `filesystem`, `websocket`, `misc`.

## 4. Injection technique (decomp `injector_WriteProcessMemory.c`, sub_140BE8800)

Manual section mapping (not LoadLibrary):
1. `GetModuleHandleA("ntdll.dll")`, resolve `NtCreateSection` + `NtMapViewOfSection` via `GetProcAddress`.
2. `NtCreateSection` (size 4568 = 0x11D8) → `NtMapViewOfSection` into target.
3. `WriteProcessMemory(hProcess, lpBaseAddress, sub_140BE6440, 0x1000, 0)` — shellcode page.
4. `WriteProcessMemory(hProcess, base+0x1000, Buffer, 0x1D8, 0)` — payload.
5. Builds a trampoline stub (`0xE0FF...` = `jmp` gate, `xmmword_1431B60D0` template).
6. `helper_wpm.c` (sub_140BE62E0) = thin `WriteProcessMemory` wrapper.

Shared memory channel: `LUNA_SHARED_MEM`. Also referenced: `NtSuspendProcess`, `SeDebugPrivilege`,
`VirtualAllocEx`, `ReadProcessMemory`, `Get/SetThreadContext`, `Suspend/ResumeThread`.

## 5. Luau C API bridge (`onyx/logic/luau/Api`)

cgo `_Cfunc_` bindings present for the full Luau API, incl.:
`lua_call/pcall`, `luau_load`, `luau_compile`, `lua_clonefunction`, `lua_clonecfunction`,
`lua_get/setreadonly`, `lua_get/setmetatable`, `lua_ref/unref`, `lua_newthread`,
`lua_newuserdatatagged`, `lua_settable/getfield/setfield`, `luaL_where`,
`luaM_getpagewalkinfo` (`LuaPage.GetPageWalkInfo`), plus Luna-specific:
`luna_register_function`, `set_caps`, `set_original_step`, `setup_sc_callback`,
`get_hook_ptr`, `Hook_Calls`, `trigger_luna_error_bridge`.

High-level Go wrappers: `(*LuaState).{PCall,Call,Load,Compile,...}`, `RegisterFunction`,
`IdentityToCapabilities`, `SetCaps`, `GoNamecall`, `GoIndex`, `GoStepHookPayload`,
`ScriptContextResume`, `HttpGet`, `GetObjects`, `getGameIds`, `Headers`.

## 6. Exposed Lua globals (executor API)

`loadstring`, `newcclosure`, `checkcaller`, `islclosure`, `setreadonly`,
`hookmetamethod`, `getnamecallmethod`, `getgenv`, `hookfunction` (alias `replaceclosure`),
`setclipboard` (alias `toclipboard`), `makefolder` (alias `make_folder`),
`readfile`, `writefile`, `isfile`, `listfiles`, `HttpGet`/`request`, `GetObjects`,
`RobloxWebSocket`. Internal: `luna_internal_httpget`.

## 7. Dependencies → capabilities

- `gorilla/websocket` + `crazywolf132/conduit` (client+server) — IPC/C2 between launcher & DLL.
- `sandipmavani/hardwareid` — HWID (`ID`, `ProtectedID`) for licensing/ban.
- `shirou/gopsutil/v3` — process/cpu/mem enumeration.
- `klauspost/compress` + `pierrec/lz4` — payload compression.
- `sirupsen/logrus` — logging. `bitcask` — local KV store. `go-ole`/`wmi` — COM/WMI.

## 8. Live IDA findings — export trampolines → real handlers

All `Go*` exports are thin CGO trampolines (`sub_2064B2750` = enter Go runtime,
`sub_2064B2610` = leave) forwarding to the real Go handler:

| Export | Trampoline | Real handler |
|---|---|---|
| `GoLunaGateway` | `sub_206443BC0` | `sub_20643CFE0` |
| `GoNamecall` | `sub_206443D40` | `sub_206441E60` |
| `GoIndex` | `sub_206443D00` | `sub_206441D00` |
| `GoStepHookPayload` | `sub_206443C20` | `sub_20643EBA0` |

### 8.1 `__namecall` hook — `sub_206441E60`
Reads method-name length at `+20`, then looks the method name up in a Go map via
`sub_2061C8A80` (see §8.5). Special-cases the method name inline:
```
len == 10 && bytes == "getobjec" (0x63656A626F746567) + "ts" (0x7374) → sub_206442A80 (GetObjects)
```
Other matched names dispatch via `sub_206442C20`. Deny/sentinel path returns 16
(return value is a status code consumed by the CGO trampoline, not a Lua result count).

### 8.2 `__index` hook — `sub_206441D00`
Checks a custom flag (`sub_20643C2E0`), looks the field name up via `sub_2061C8A80`; on hit
calls `sub_20643DDE0(21)` and returns 1 (handled), else 0 (fall through to original engine
`__index`). Pattern = intercepting/serving executor-injected fields.

### 8.3 step hook — `sub_20643EBA0`
Engine step/heartbeat interception: sets entry flag, `sub_206443E00` (work pending?),
builds payload (`sub_206443300`) and dispatches task (`sub_20643EE40`) on `v22==1 && v23`,
else calls original step via vtable `off_20672C178`. This is how queued scripts run inside
the Luau VM (ties to `ProcessQ`).

### 8.4 `GoLunaGateway` real handler — `sub_20643CFE0`
`sub_20622CB60(0)` (lock/setup) → `sub_20643B1E0` (prep) → `sub_206232120` (get arg) →
`sub_2061C8D20(arg)` returns a vtable `v3`; if global flag `qword_206AE7080` set, calls the
resolved handler `(**v3)()` and returns its result, else returns 0. Finalizer `sub_206443AE0`
runs on both paths. So the gateway = command/handler-vtable dispatch keyed off the incoming arg.

### 8.5 map lookup core — `sub_2061C8A80`
NOT a bespoke caps routine — it is a Go map access (`runtime.mapaccess`-style swiss table):
`_mm_cmpeq_epi8` + `_mm_movemask_epi8` over an 8-byte tophash group, `0x80...80` empty-slot
sentinel, `_BitScanForward64` to iterate matches, key compare via `sub_2061C3D00`, returns
`value+16` on hit or zero-value `&unk_206B309C0` on miss. Used by the namecall/index hooks to
resolve method/field name → registered handler entry.

### 8.6 `GetObjects` impl — `sub_206442A80`
Builds the `getobjects` result: sequence of Lua-stack/object builder calls
(`sub_20643E560`, `sub_20643DDE0`, `sub_20643DC60`, `sub_2064419C0`, `sub_20643EFC0`,
`sub_20643D8E0`). References `LoadLocalAsset` / `Roblox/WinInet` rodata → resolves/loads
assets by id. On `sub_20643C100() == 6` takes an alternate branch (`sub_20643F2A0(-1,...)`).
Returns 1.

### 8.7 task dispatch — `sub_20643EE40(a1,a2,a3,a4)`
If `a3` (length) != 0 picks buffer `v6` (or empty sentinel `&unk_206B2F320`), then tail-calls
`sub_2062338E0(6, buf, a3, a4, qword_2066ED878 + qword_206AE8A88, ...)` — a runtime
slice/channel op (first arg 6) that enqueues the work item processed by the step hook / `ProcessQ`.

## 8b. Init / bootstrap chain (live IDA)

`DllMain` (export, `0x2064b24c0`) is a CGO trampoline → real handler `sub_206455300`
→ `sub_206454BE0(fdwReason)`:
```c
if (fdwReason == 1 /* DLL_PROCESS_ATTACH */) {
    sub_206454680();   // bootstrap: spawns main goroutine via sub_20622CA40 (runtime.newproc / `go`)
    sub_206209420();   // registers deferred/exit handler: sub_206235840(sub_2062094A0)
}
return 1;
```
- `sub_206454680` = on-attach bootstrap; its only job is to `go`-spawn the Luna main goroutine
  (calls `sub_20622CA40`, the Go runtime goroutine-creation helper — heavily xref'd). So DllMain
  returns immediately and all heavy work (AOB scan, RTTI resolve, hook install, conduit/websocket
  server, ImGui overlay) runs on Go-scheduled threads, not in loader lock.
- `sub_206209420` → `sub_206235840(sub_2062094A0)` = registers a shutdown/atexit callback.

`ProcessQ` (export, `0x2064b2440`) → real handler `sub_2064552C0` → `sub_2062A1EE0`:
drains/services the task queue (paired with the step hook §8.3 that enqueues, and `sub_20643EE40`
§8.7 dispatch). Exported so the injected stub / launcher can pump the queue on demand.

`GoDrawLoop` (export, `0x2064b2480`) — overlay render tick, drives `api/managers/imgui`
(`Editor_Render`, `ProcessNotifications`).

Note: the section-mapping injector (`sub_140BE8800`, `WriteProcessMemory`/`NtMapViewOfSection`)
lives in `Luna_unpacked.exe` (image base `0x140000000`), NOT in this DLL — the EXE injects, the
DLL is the injected payload. That decomp came from the EXE-side artifacts.

## 9. Tooling

### 9.1 Go symbol recovery (KEY)
IDA did not symbolize the Go functions (all showed as `sub_`). Recovered them by parsing
the DLL's `.gopclntab` directly: `_gopclntab.py` → `analysis/go_symbols.json` (6909 funcs)
and `analysis/go_main_symbols.txt` (413 `main*` funcs). Header found at file offset `0x6c21a0`
(magic `0xFFFFFFF1`, go1.20+ layout), `textStart=0x2061c1340`, IDA base `0x2061c0000`.
Note: in go1.18+ the per-func `funcoff` is relative to the functab (pclnOffset) start, not the
pclntab base.

These symbols CORRECT several earlier guesses made from raw decompilation:

| Address | Earlier guess | Actual Go symbol |
|---|---|---|
| `0x20643ee40` | "task dispatch" | `Api.ScriptContextResume` |
| `0x206442c20` | "generic namecall dispatch" | `Api.HttpGet` |
| `0x2061c8a80` | "caps/identity check" | `runtime.mapaccess1_faststr` |
| `0x2061c8d20` | "gateway cmd resolver" | `runtime.mapaccess2_faststr` |
| `0x206454680` | "bootstrap goroutine spawn" | `main._Cfunc_InstallVEH` |

So the namecall/index hooks do a Go **string-keyed map lookup** (`mapaccess*_faststr`) to find
the registered handler for a method/field name — confirming the executor registers its globals
into a Go map and the metamethod hooks resolve names through it.

### 9.2 IDA MCP helper
`_ida_mcp.ps1 -Method <m> -ParamsFile <json>`. Methods used: `get_metadata`,
`list_functions{offset,count}`, `get_entry_points`, `decompile_function{address}`,
`get_function_by_name{name}`, `get_xrefs_to{address}`, `rename_function{function_address,new_name}`.
WARNING: the server is single-threaded — do NOT flood it with thousands of sequential
`rename_function` calls; it will time out / drop the connection. Batch with delays or apply
names in IDA via a local IDAPython script instead.

## 11. Recovered executor API surface (from Go symbols)

### 11.1 Top-level `main.*` (native glue / hooks)
- `main.DllMain`, `main.main` (+ `main.main.func1/func2`, gowraps) — entry & main goroutine.
- `main.GoDrawLoop` — overlay render tick.
- `main.D3DHook` (`0x206454b40`) — DirectX present/render hook (overlay draws through it).
- `main._Cfunc_InstallVEH` (`0x206454680`) — installs a **Vectored Exception Handler**
  (called on DLL attach; used for the CPP hook / page-guard or breakpoint-based hooks).
- `main._Cfunc_InstallCPP_Hook` (`0x2064545e0`) — installs the native C++ hook (engine-side).
- `main._Cfunc_GetProp` (`0x206454500`) — `GetPropA`-style window prop access (HWND wiring).
- `main.init.func1*` — package init (spawns a goroutine via gowrap1).

### 11.2 `api/env/closures` — closure/hook primitives (`ClosureOps`)
Backs the Lua globals. Methods: `Init`, `checkCaller`, `cloneFunction`, `cloneRef`,
`getNamecallMethod`, `hookFunction`, `hookMetaMethod`, `isCClosure`, `isLClosure`, `isReadOnly`,
`newCClosure`, `patchLClosure`, `restoreFunction`, `setReadOnly`. Each has a `-fm` method-value
trampoline (the actual `lua_CFunction` registered).
- `HookDispatcher.dispatcher` / `.getCallback` — routes hooked calls back to user callbacks;
  `_Cfunc_bridge_push_newcclosure` pushes a C closure into the VM.
- `ClosureCache[*uint8]` / `[bool]` — Get/Set/Delete caches mapping originals↔hooks.

#### 11.2a `ClosureOps.Init` exact registration order (IDA MCP, 2026-06-01)

`main/packages/api/env/closures.(*ClosureOps).Init` at `0x20644a8a0` constructs 12
method-value closures in this exact order, then passes the reflected value into
`Api.Register` (`0x2064408c0`). The public Lua names come from Go reflection tags
(`lua:"..."`, optional `alias:"..."`) embedded in the type metadata.

| # | method-value trampoline | method | Lua name | Alias |
|---|---:|---|---|---|
| 1 | `0x20644c500` | `restoreFunction` | `restorefunction` | - |
| 2 | `0x20644c560` | `cloneRef` | `cloneref` | `clonereference` |
| 3 | `0x20644c5c0` | `hookFunction` | `hookfunction` | `replaceclosure` |
| 4 | `0x20644c620` | `hookMetaMethod` | `hookmetamethod` | - |
| 5 | `0x20644c680` | `newCClosure` | `newcclosure` | - |
| 6 | `0x20644c6e0` | `cloneFunction` | `clonefunction` | - |
| 7 | `0x20644c740` | `isCClosure` | `iscclosure` | - |
| 8 | `0x20644c7a0` | `isLClosure` | `islclosure` | - |
| 9 | `0x20644c800` | `checkCaller` | `checkcaller` | - |
| 10 | `0x20644c860` | `getNamecallMethod` | `getnamecallmethod` | - |
| 11 | `0x20644c8c0` | `setReadOnly` | `setreadonly` | - |
| 12 | `0x20644c920` | `isReadOnly` | `isreadonly` | - |

Related wrapper `main/packages/api/env/closures.Init` (`0x20644be40`) creates the backing
maps with `runtime.makemap_small` and then calls `(*ClosureOps).Init`. This confirms the
closure environment registration is reflection-driven, not a manually written list of
`luna_register_function` calls.

### 11.3 `api/env/filesystem` — sandboxed FS
`Init` (registers `readfile/writefile/listfiles/makefolder/isfile/appendfile/...` as funcs 1..11),
`RootDir`, `Path`, `CreateFolder`, `CreateFileWithDir`, `AppendToFile`. Jailed under workspace
root (`Path`/`RootDir`).

### 11.4 `api/env/websocket` — Lua `WebSocket`
`connect` builds an Event table with `Send`/`Close` + `OnMessage`/`OnClose` (`Event.Table.func4..9`),
`Client.readLoop` (goroutine) → `queueEvent`/`fireEvent`/`Poll` pumps events back to Lua thread.
Uses `gorilla/websocket` Dialer.

### 11.5 `api/env/misc` — misc globals
`Init` registers funcs 1..10 (clipboard/identity/HttpGet/etc.; ties to `setclipboard`,
`getgenv`, `request`).

### 11.6 `onyx/mem/aob` — scanner (addresses)
`OptimizedScan` `0x2062f0960`, `(*OptimizedCompiledPattern).FastScan` `0x2062f04a0`,
`getMemoryRegions` `0x2062f0740`, `PointerWalk[string]` `0x2062f2760`. Used with
`renderview.*.RTTIScanMatcher` to locate engine objects by RTTI class name.

### 11.7 `onyx/mem/renderview` — engine roots
`RenderView` `0x2062f1340` → `(*Render).DataModel` `0x2062f1f60`, `(*Render).Container`,
`(*Container).Jobs/Job`. RTTI-driven (`RTTIScanMatcher`) discovery of RenderJob→DataModel.

### 11.8 `onyx/mem/rtti` — `Demangle` `0x2062eea80`, `RTTIInformation` `0x2062ee760`,
`extractRTTIName`, `fixRTTIDemangling`, `removeTypePrefix`, cgo `demangleMSVC`.

### 11.9 `onyx/logic/luau/Api` — confirmed addresses
`GoLunaGateway` `0x20643cfe0`, `GoNamecall` `0x206441e60`, `GoIndex` `0x206441d00`,
`GoStepHookPayload` `0x20643eba0`, `GetObjects` `0x206442a80`, `HttpGet` `0x206442c20`,
`ScriptContextResume` `0x20643ee40`, `(*Luau).Hook` `0x20643ea60`, `Api.Hook` `0x206441c80`,
cgo `Hook_Calls` `0x206438dc0`, `set_original_step` `0x20643bec0`, `setup_sc_callback` `0x20643bf60`.

## 11b. `main.main` bootstrap chain (IDA MCP, 2026-06-01)

`main.main` is `0x206454c60`. Its high-level sequence:

1. Calls `windows.GetCurrentProcessId` (`0x2062ea140`).
2. Builds the global `logic.Session` (`0x206437440`), which calls
   `renderview.RenderView` and stores render/session state.
3. Registers deferred/new goroutine work through `runtime.newproc` (`0x206209420`).
4. Resolves render container/job through `(*Render).Container` (`0x2062f1840`) and
   `(*Container).Job` (`0x2062f1e80`, called with selector/count `9`).
5. Spawns `main.main.gowrap1` (`0x206454e00`) which calls `main.D3DHook` (`0x206454b40`).
6. Spawns `main.main.gowrap2` (`0x206454da0`) over `off_20672BD48` / `off_20680E1D8`
   (next target for IPC/server bring-up analysis).

This confirms the heavy runtime path is outside `DllMain`: `DllMain`/attach only reaches
the Go bootstrap, while `main.main` performs session creation, render-job discovery, and
D3D overlay hook startup.


## 11c. Native hook chain: `InstallVEH` / `InstallCPP_Hook` (IDA MCP, 2026-06-01)

The Go cgo wrappers are thin and the useful native targets are behind cgo function-pointer slots:

- `main._Cfunc_InstallVEH` (`0x206454680`) loads `off_20672BD30`, then calls `runtime.cgocall`.
  `off_20672BD30 -> 0x2064b25c0`.
- `0x2064b25c0` is the real native VEH installer. It is idempotent on `qword_206B3D210` and calls
  `AddVectoredExceptionHandler(1, Handler)`, storing the returned handle in `qword_206B3D210`.
- The installed `Handler` at `0x2064b2570` is currently a no-op (`xor eax,eax; ret`, i.e. continue
  search). So this build wires VEH infrastructure but does not contain an active page-guard/breakpoint
  dispatcher in that handler.

`main._Cfunc_InstallCPP_Hook` (`0x2064545e0`) loads `off_20672BD28`, then calls `runtime.cgocall`.
`off_20672BD28 -> 0x2064b2560`, a tiny native thunk that unwraps the Go/cgo argument and jumps to
`0x206566b60`.

`0x206566b60` is the real C++/DX hook installer:

1. Walks an object chain from the Render/engine argument: `a1 + 0x1d0 -> +8 -> +0xc8`.
2. Treats that as a vtable pointer slot, saves it in `qword_206B3D2E0`, and copies the original
   `0x90`-byte vtable.
3. Saves original vtable entries:
   - `qword_206B3D2D8 = original[0x40]`
   - `qword_206B3D2C8 = original[0x68]`
4. Replaces copied entries:
   - `[+0x40] = 0x20661bfd0`
   - `[+0x68] = 0x20661c000`
5. Swaps the object to the copied vtable.

Hook callbacks:

- `0x20661bfd0` calls `0x20661bbd0` first, then tail-jumps to `qword_206B3D2D8`.
- `0x20661c000` releases/clears `qword_206B3D2F0` if present, then tail-calls `qword_206B3D2C8`.
- `0x20661bbd0` is the overlay/task-pump body: initializes/updates ImGui state, optionally renders
  branding (`v1.0 .gg/getluna`), calls exported `ProcessQ`, and calls exported `GoDrawLoop` when
  `byte_206B3D2D0` is set.

Conclusion: the active hook in this sample is a copied-vtable hook on the render/DX object. VEH is
installed once but its handler is inert in the analyzed DLL.

## 11d. IPC / conduit execution path (DLL + EXE, IDA MCP/static, 2026-06-01)

DLL side:

- `main/packages/api/managers/tpc.Server` (`0x2064479a0`) builds a conduit server config via
  `conduit.DefaultServerConfig` (`0x20631f260`), sets `MaxDatafileSize = 0x5000000` (80 MiB),
  constructs handler maps/channel state, registers handler id/key `7` through
  `conduit/server.(*Server).Handle` (`0x206446700`), then starts it with
  `conduit/server.(*Server).Start` (`0x206446880`).
- The server blocks on a channel after startup and cleans up through defer wrapper `0x206447d00`.
- `tpc.Server.func1` (`0x206447d60`) decodes incoming messages. The exact command checked is
  `CTR-EXECUTE` (11 bytes; little-endian constants `0x434558452d525443`, `0x5455`, `0x45`) — the ASCII string is `CTR-EXECUTE`.
- On `CTR-EXECUTE`, the payload/source is wrapped as an `Api.Queue` item and pushed through
  `main/packages/onyx/logic/luau/Api.(*Queue).Push` (`0x2064441c0`). That queue is later drained
  by the hooked render/step path (`ProcessQ` / script context resume chain).

EXE side:

- Recovered a separate EXE Go symbol table from `Luna_unpacked.exe`: `analysis/go_symbols_exe.json`
  contains 27614 symbols; `analysis/go_main_symbols_exe.txt` is the filtered main package view.
- Relevant launcher functions:
  - `main/onyx/logic.(*App).Attach` `0x140ae8980`
  - `main/onyx/logic.(*App).Execute` `0x140ae8ba0`
  - `main/onyx/mem.(*Luna).Inject` `0x14045c160`
  - `main/onyx/mem/injector.Inject` `0x14056b440`
  - `github.com/crazywolf132/conduit.DefaultClientConfig` `0x14055a000`
  - `github.com/crazywolf132/conduit/client.(*Client).ConnectWithRetry` `0x14055b040`
  - `github.com/crazywolf132/conduit/client.(*Client).Send` `0x14055b4a0`

High-level flow: Wails frontend calls the bound `App.Attach` / `App.Execute` methods; launcher injects
`luna_extracted.dll` into Roblox, creates/connects a conduit client, then `Execute` sends a
`CTR-EXECUTE` message to the DLL server. The DLL queues the source for Luau execution instead of
executing directly on the conduit thread.

- The raw ASCII string `CTR-EXECUTE` is present in `Luna_unpacked.exe`; `LUNA_SHARED_MEM` appears in
  both `Luna_unpacked.exe` and `luna_extracted.dll` string data as the shared-memory conduit channel.
## 11e. Registered Lua globals dump (2026-06-01)

A clean dump was written to:

- `analysis/registered_lua_globals.txt`
- `analysis/registered_lua_globals.json`

The recovered public API groups are:

- Closures/hooks: `restorefunction`, `cloneref`/`clonereference`, `hookfunction`/`replaceclosure`,
  `hookmetamethod`, `newcclosure`, `clonefunction`, `iscclosure`, `islclosure`, `checkcaller`,
  `getnamecallmethod`, `setreadonly`, `isreadonly`.
- Filesystem: `readfile`, `loadfile`, `writefile`, `listfiles`, `makefolder`/`make_folder`,
  `delfolder`/`deletefolder`, `delfile`/`deletefile`, `isfile`, `isfolder`, `appendfile`,
  `exists`/`ispath`.
- Misc/executor: `getgc`, `setfpscap`, `loadstring`, `messagebox`, `setclipboard`/`toclipboard`,
  `identifyexecutor`/`getexecutorname`, `queue_on_teleport`/`queueonteleport`, `gethwid`,
  `request`/`http_request`, `lz4compress`, `lz4decompress`.
- WebSocket/events: `WebSocket`, `connect`, `Send`, `Close`, `OnMessage`, `OnClose`, `Connect`,
  `Once`, `Wait`, `Disconnect`.
- Request/response fields: `Url`, `Method`, `Body`, `Headers`, `Cookies`, `Success`, `StatusCode`,
  `StatusMessage`.

## 11f. Applying recovered symbols into IDA (2026-06-01)

DLL symbols: use `analysis/apply_go_symbols.py` inside IDA with `luna_extracted.dll` open.
EXE symbols: use `analysis/apply_go_symbols_exe.py` inside IDA with `Luna_unpacked.exe` open.

Reason: IDA MCP can rename single functions, but bulk-renaming thousands of Go functions through the
single-threaded HTTP server is slow and fragile. The local IDAPython route applies the same recovered
symbol JSON without flooding MCP. Important functions were still verified via MCP by address during
this pass.

## 12. Done / next
Resolved this session:
- [x] Full Go symbol recovery via gopclntab → `go_symbols.json` (6909) — §9.1
- [x] Corrected 5 mis-identified addresses — §9.1
- [x] Mapped full executor API surface (closures/fs/websocket/misc/aob/rtti) — §11
- [x] Found native hooks: D3DHook, InstallVEH, InstallCPP_Hook — §11.1

Next candidates:
- [x] decompile `main.main` + `closures.Init` for exact global-registration list & order
- [x] `_Cfunc_InstallVEH` / `InstallCPP_Hook` — native hook mechanism (page guard? trampoline?)
- [x] conduit/websocket server bring-up (IPC protocol with launcher)
- [x] dump the registered-globals Go map contents (keys = exposed Lua names)
- [x] prepare/apply path for recovered symbols in IDA (local IDAPython; MCP has no safe bulk executor)
