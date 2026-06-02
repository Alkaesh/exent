"""
Custom Roblox injector for `luna_extracted.dll`.

This script is a practical custom injector based on the recovered Luna analysis.
It supports a working `LoadLibrary` injection path for `luna_extracted.dll`.

The original launcher used a manual section-mapping injector with shellcode,
section size 0x11D8, and a remote payload. That path is documented in
`analysis/ANALYSIS.md` and the extracted binary artifacts under `analysis/extracted/`.
"""

import argparse
import ctypes
from ctypes import wintypes
from pathlib import Path
import time

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

PROCESS_ALL_ACCESS = 0x001F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
INFINITE = 0xFFFFFFFF
MODULE_VERIFY_TIMEOUT_MS = 5000
MODULE_VERIFY_RETRY_DELAY_MS = 0.1
DONT_RESOLVE_DLL_REFERENCES = 0x00000001

TOKEN_ADJUST_PRIVILEGES = 0x20
TOKEN_QUERY = 0x8
SE_PRIVILEGE_ENABLED = 0x2

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * wintypes.MAX_PATH),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * wintypes.MAX_PATH),
    ]

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID
kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE
kernel32.GetExitCodeThread.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetExitCodeThread.restype = wintypes.BOOL
kernel32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
kernel32.IsWow64Process.restype = wintypes.BOOL
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.GetLastError.argtypes = []
kernel32.GetLastError.restype = wintypes.DWORD
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = wintypes.HMODULE
kernel32.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
kernel32.LoadLibraryExW.restype = wintypes.HMODULE
kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
kernel32.GetProcAddress.restype = wintypes.LPVOID
kernel32.FreeLibrary.argtypes = [wintypes.HMODULE]
kernel32.FreeLibrary.restype = wintypes.BOOL
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wintypes.BOOL
kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32FirstW.restype = wintypes.BOOL
kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = wintypes.BOOL
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

kernel32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
kernel32.OpenProcessToken.restype = wintypes.BOOL
advapi32.LookupPrivilegeValueA.argtypes = [wintypes.LPCSTR, wintypes.LPCSTR, ctypes.POINTER(LUID)]
advapi32.LookupPrivilegeValueA.restype = wintypes.BOOL
advapi32.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID]
advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL


def format_error(msg: str) -> str:
    code = kernel32.GetLastError()
    return f"{msg} (error={code})"


def enable_debug_privilege() -> None:
    h_token = wintypes.HANDLE()
    if not kernel32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h_token)):
        raise OSError(format_error("OpenProcessToken failed"))
    luid = LUID()
    if not advapi32.LookupPrivilegeValueA(None, b"SeDebugPrivilege", ctypes.byref(luid)):
        raise OSError(format_error("LookupPrivilegeValueA failed"))
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    if not advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None):
        raise OSError(format_error("AdjustTokenPrivileges failed"))
    kernel32.CloseHandle(h_token)


def find_process_by_name(name: str):
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise OSError(format_error("CreateToolhelp32Snapshot failed"))
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            raise OSError(format_error("Process32FirstW failed"))
        while True:
            if entry.szExeFile.lower() == name.lower():
                return entry.th32ProcessID
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)
    return None


def open_process(pid: int):
    handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not handle:
        raise OSError(format_error(f"OpenProcess({pid}) failed"))
    return handle


def resolve_remote_loadlibrary_address(pid: int) -> int:
    local_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
    if not local_kernel32:
        raise OSError(format_error("GetModuleHandleW(kernel32.dll) failed"))
    local_loadlibrary = kernel32.GetProcAddress(local_kernel32, b"LoadLibraryW")
    if not local_loadlibrary:
        raise OSError(format_error("GetProcAddress(LoadLibraryW) failed"))
    remote_kernel32 = find_remote_module(pid, "kernel32.dll")
    if remote_kernel32 is None:
        raise OSError("Failed to locate kernel32.dll in target process")
    remote_kernel32_base, _ = remote_kernel32
    loadlibrary_offset = int(local_loadlibrary) - int(local_kernel32)
    return remote_kernel32_base + loadlibrary_offset


def resolve_remote_export_address(pid: int, dll_path: Path, export_name: bytes) -> int:
    remote_module = find_remote_module(pid, dll_path.name)
    if remote_module is None:
        raise OSError("Failed to locate target DLL in remote process for export resolution")
    remote_module_base, _ = remote_module
    local_module = kernel32.LoadLibraryExW(str(dll_path.resolve()), None, DONT_RESOLVE_DLL_REFERENCES)
    if not local_module:
        raise OSError(format_error("LoadLibraryExW(DONT_RESOLVE_DLL_REFERENCES) failed"))
    try:
        local_export = kernel32.GetProcAddress(local_module, export_name)
        if not local_export:
            raise OSError(format_error(f"GetProcAddress({export_name.decode(errors='ignore')}) failed"))
        export_offset = int(local_export) - int(local_module)
        return remote_module_base + export_offset
    finally:
        kernel32.FreeLibrary(local_module)


def start_remote_runtime(pid: int, dll_path: Path) -> None:
    process = open_process(pid)
    try:
        remote_start = resolve_remote_export_address(pid, dll_path, b"StartRuntimeThreadProc")
        thread_id = wintypes.DWORD(0)
        h_thread = kernel32.CreateRemoteThread(process, None, 0, remote_start, None, 0, ctypes.byref(thread_id))
        if not h_thread:
            raise OSError(format_error("CreateRemoteThread(StartRuntimeThreadProc) failed"))
        wait_result = kernel32.WaitForSingleObject(h_thread, INFINITE)
        if wait_result != 0:
            raise OSError(f"WaitForSingleObject(StartRuntimeThreadProc) returned {wait_result}")
        exit_code = wintypes.DWORD(0)
        if not kernel32.GetExitCodeThread(h_thread, ctypes.byref(exit_code)):
            raise OSError(format_error("GetExitCodeThread(StartRuntimeThreadProc) failed"))
        kernel32.CloseHandle(h_thread)
        if exit_code.value != 0:
            raise OSError(f"StartRuntimeThreadProc returned non-zero exit code: {exit_code.value}")
    finally:
        kernel32.CloseHandle(process)


def inject_via_loadlibrary(pid: int, dll_path: Path) -> int:
    if not dll_path.exists():
        raise FileNotFoundError(f"DLL not found: {dll_path}")
    dll_path_str = str(dll_path.resolve())
    dll_buffer = ctypes.create_unicode_buffer(dll_path_str)
    dll_buffer_bytes = ctypes.sizeof(dll_buffer)
    process = open_process(pid)
    try:
        remote_mem = kernel32.VirtualAllocEx(process, None, dll_buffer_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote_mem:
            raise OSError(format_error("VirtualAllocEx failed"))
        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(process, remote_mem, dll_buffer, dll_buffer_bytes, ctypes.byref(written)):
            raise OSError(format_error("WriteProcessMemory failed"))
        if written.value != dll_buffer_bytes:
            raise OSError(f"WriteProcessMemory wrote {written.value}/{dll_buffer_bytes} bytes")
        loadlib = resolve_remote_loadlibrary_address(pid)
        thread_id = wintypes.DWORD(0)
        h_thread = kernel32.CreateRemoteThread(process, None, 0, loadlib, remote_mem, 0, ctypes.byref(thread_id))
        if not h_thread:
            raise OSError(format_error("CreateRemoteThread failed"))
        wait_result = kernel32.WaitForSingleObject(h_thread, INFINITE)
        if wait_result != 0:
            raise OSError(f"WaitForSingleObject returned {wait_result}")
        exit_code = wintypes.DWORD(0)
        if kernel32.GetExitCodeThread(h_thread, ctypes.byref(exit_code)):
            print(f"Remote thread exit code: 0x{exit_code.value:x}")
            if exit_code.value == 0:
                raise OSError(format_error("Remote LoadLibraryW returned NULL (module failed to load)"))
        else:
            raise OSError(format_error("GetExitCodeThread failed"))
        kernel32.CloseHandle(h_thread)
        module = wait_for_remote_module(pid, dll_path.name)
        if module is None:
            print(
                "Post-injection verification did not confirm the DLL after "
                f"{MODULE_VERIFY_TIMEOUT_MS} ms. LoadLibraryW returned non-zero, but the module was not "
                "observable via Toolhelp snapshot. Proceeding with runtime-ready validation."
            )
        start_remote_runtime(pid, dll_path)
        return thread_id.value
    finally:
        kernel32.CloseHandle(process)


def find_remote_module(pid: int, module_name: str):
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snapshot == INVALID_HANDLE_VALUE:
        return None
    try:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(MODULEENTRY32W)
        if not kernel32.Module32FirstW(snapshot, ctypes.byref(me)):
            return None
        while True:
            if me.szModule.lower() == module_name.lower():
                return (ctypes.addressof(me.modBaseAddr.contents), me.modBaseSize)
            if not kernel32.Module32NextW(snapshot, ctypes.byref(me)):
                break
    finally:
        kernel32.CloseHandle(snapshot)
    return None


def wait_for_remote_module(pid: int, module_name: str, timeout_ms: int = MODULE_VERIFY_TIMEOUT_MS):
    deadline = time.monotonic() + (timeout_ms / 1000.0)
    while time.monotonic() < deadline:
        module = find_remote_module(pid, module_name)
        if module is not None:
            return module
        time.sleep(MODULE_VERIFY_RETRY_DELAY_MS)
    return None


def is_process_64bit(pid: int) -> bool:
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        raise OSError(format_error(f"OpenProcess({pid}) failed"))
    try:
        is_wow64 = wintypes.BOOL(False)
        if not kernel32.IsWow64Process(h, ctypes.byref(is_wow64)):
            raise OSError(format_error("IsWow64Process failed"))
        # If process is WOW64, it's 32-bit on 64-bit OS. If not WOW64 and host is 64-bit, process is 64-bit.
        return not is_wow64.value
    finally:
        kernel32.CloseHandle(h)


def dll_is_64bit(path: Path) -> bool:
    # Minimal PE header parse to check OptionalHeader.Magic
    with path.open('rb') as f:
        data = f.read(0x200)
    if len(data) < 0x40:
        raise ValueError("File too small to be PE")
    if data[0:2] != b'MZ':
        raise ValueError("Not a PE file")
    e_lfanew = int.from_bytes(data[0x3c:0x40], 'little')
    if len(data) < e_lfanew + 6:
        # read more
        with path.open('rb') as f:
            f.seek(e_lfanew)
            hdr = f.read(6)
    else:
        hdr = data[e_lfanew:e_lfanew+6]
    # Optional header magic at offset e_lfanew + 4
    magic = int.from_bytes(hdr[4:6], 'little')
    # 0x10b = PE32, 0x20b = PE32+
    return magic == 0x20b


def write_test_command_file(script: str):
    try:
        path = Path(r"C:\Windows\Temp\luna_extracted_cmd.json")
        payload = {"type": "execute", "script": script}
        import json
        path.write_text(json.dumps(payload))
        print(f"Wrote test command file to {path}")
    except Exception as e:
        print("Failed to write test command file:", e)


def main():
    parser = argparse.ArgumentParser(description="Custom injector for luna_extracted runtime DLL")
    parser.add_argument("--pid", type=int, help="Target process ID")
    parser.add_argument("--process", type=str, help="Target process executable name, e.g. RobloxPlayerBeta.exe")
    parser.add_argument("--dll", type=Path, default=Path(__file__).resolve().parents[2] / "bin" / "luna_extracted_native.dll",
                        help="DLL to inject (default: bin/luna_extracted_native.dll)")
    parser.add_argument("--test", action="store_true", help="Write a test command file instead of injecting")
    parser.add_argument("--script", type=str, default="print(\"hello from test\")", help="Script to write to test command file")
    parser.add_argument("--check-module", type=str, help="Check whether module is loaded in target process (module name)")
    parser.add_argument("--check-arch", action="store_true", help="Check architecture match between PID and DLL")
    parser.add_argument("--enable-debug", action="store_true", help="Enable SeDebugPrivilege before injection")
    parser.add_argument("--method", choices=["loadlibrary"], default="loadlibrary", help="Injection method")
    args = parser.parse_args()

    pid = args.pid
    if pid is None:
        if not args.process:
            parser.error("Either --pid or --process must be provided")
        pid = find_process_by_name(args.process)
        if pid is None:
            raise SystemExit(f"Process not found: {args.process}")

    if args.enable_debug:
        enable_debug_privilege()
    print(f"Injecting DLL '{args.dll}' into PID {pid} using method {args.method}")

    if args.test:
        write_test_command_file(args.script)
        return

    if args.check_module:
        module = args.check_module
        res = find_remote_module(pid, module)
        if res is None:
            print(f"Module not found in PID {pid}: {module}")
            return
        base, size = res
        print(f"Module {module} found in PID {pid} at base=0x{base:x} size={size}")
        return

    if args.check_arch:
        try:
            proc64 = is_process_64bit(pid)
        except Exception as e:
            print("Failed to query process architecture:", e)
            return
        try:
            dll64 = dll_is_64bit(args.dll)
        except Exception as e:
            print("Failed to query DLL architecture:", e)
            return
        print(f"Process PID {pid} is {'64-bit' if proc64 else '32-bit'}")
        print(f"DLL {args.dll} is {'64-bit' if dll64 else '32-bit'}")
        if proc64 != dll64:
            print("Architecture mismatch: injector will fail to load the DLL into the process.")
        else:
            print("Architecture matches.")
        return

    if args.method == "loadlibrary":
        thread_id = inject_via_loadlibrary(pid, args.dll)
        print(f"Remote thread created, thread id {thread_id}")
        print(f"Injection verified: module '{args.dll.name}' is present in PID {pid}")
    else:
        raise SystemExit("Unsupported method")

if __name__ == "__main__":
    main()
