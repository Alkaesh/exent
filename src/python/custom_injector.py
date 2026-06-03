"""
Custom Roblox injector for luna_extracted_native.dll.
Auto-checks DLL/process architecture before injecting.
"""

import argparse
import ctypes
from ctypes import wintypes
from pathlib import Path
import struct
import time
import sys

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
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
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

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


def info(msg): print(f"[INFO] {msg}")
def warn(msg): print(f"[WARN] {msg}")

def fmt_error(msg: str) -> str:
    return f"{msg} (code={kernel32.GetLastError()})"


# Architecture check

def dll_architecture(path: Path) -> str | None:
    with path.open('rb') as f:
        data = f.read(0x200)
    if len(data) < 0x40 or data[0:2] != b'MZ':
        return None
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if len(data) < e_lfanew + 26:
        with path.open('rb') as f:
            f.seek(e_lfanew)
            hdr = f.read(26)
    else:
        hdr = data[e_lfanew:e_lfanew + 26]
    magic = struct.unpack_from('<H', hdr, 24)[0]
    if magic == 0x20b: return 'x64'
    if magic == 0x10b: return 'x86'
    return None

def process_architecture(pid: int) -> str | None:
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h: return None
    wow64 = wintypes.BOOL(False)
    kernel32.IsWow64Process(h, ctypes.byref(wow64))
    kernel32.CloseHandle(h)
    return 'x86' if wow64.value else 'x64'

def check_architecture_match(pid: int, dll_path: Path) -> bool:
    print()
    print("=" * 44)
    print("  ARCHITECTURE CHECK")
    print("=" * 44)
    pa = process_architecture(pid)
    da = dll_architecture(dll_path)
    print(f"  Process (PID {pid}):  {pa or '???'}")
    print(f"  DLL:                  {da or '???'}")
    if pa is None or da is None:
        print("  ERROR: cannot determine architecture")
        return False
    if pa != da:
        print(f"  MISMATCH! DLL={da}  Process={pa}")
        print(f"  Fix: recompile DLL as {pa}")
        print(f"    MSVC:  /MACHINE:{'X64' if pa == 'x64' else 'X86'}")
        print(f"    MinGW: {'-m64' if pa == 'x64' else '-m32'}")
        return False
    print(f"  OK: both {pa}")
    print("=" * 44)
    return True


def enable_debug_privilege() -> None:
    h_token = wintypes.HANDLE()
    if not kernel32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h_token)):
        raise OSError(fmt_error("OpenProcessToken failed"))
    luid = LUID()
    if not advapi32.LookupPrivilegeValueA(None, b"SeDebugPrivilege", ctypes.byref(luid)):
        raise OSError(fmt_error("LookupPrivilegeValueA failed"))
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    if not advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None):
        raise OSError(fmt_error("AdjustTokenPrivileges failed"))
    kernel32.CloseHandle(h_token)


def find_process_by_name(name: str):
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise OSError(fmt_error("CreateToolhelp32Snapshot failed"))
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            raise OSError(fmt_error("Process32FirstW failed"))
        while True:
            if entry.szExeFile.lower() == name.lower():
                return entry.th32ProcessID
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
        return None
    finally:
        kernel32.CloseHandle(snapshot)

def open_process(pid: int):
    h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        raise OSError(fmt_error(f"OpenProcess({pid}) failed"))
    return h

def find_remote_module(pid: int, module_name: str):
    fl = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
    snapshot = kernel32.CreateToolhelp32Snapshot(fl, pid)
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
        return None
    finally:
        kernel32.CloseHandle(snapshot)

def wait_for_remote_module(pid: int, name: str, timeout_ms: int = MODULE_VERIFY_TIMEOUT_MS):
    deadline = time.monotonic() + timeout_ms / 1000.0
    while time.monotonic() < deadline:
        m = find_remote_module(pid, name)
        if m is not None: return m
        time.sleep(MODULE_VERIFY_RETRY_DELAY_MS)
    return None


def resolve_remote_loadlibrary(pid: int) -> int:
    local_k32 = kernel32.GetModuleHandleW("kernel32.dll")
    if not local_k32:
        raise OSError(fmt_error("GetModuleHandleW(kernel32.dll) failed"))
    local_ll = kernel32.GetProcAddress(local_k32, b"LoadLibraryW")
    if not local_ll:
        raise OSError(fmt_error("GetProcAddress(LoadLibraryW) failed"))
    remote = find_remote_module(pid, "kernel32.dll")
    if remote is None:
        raise OSError("Failed to locate kernel32.dll in target process")
    return remote[0] + (ctypes.cast(local_ll, ctypes.c_void_p).value - ctypes.cast(local_k32, ctypes.c_void_p).value)

def resolve_remote_export(pid: int, dll_path: Path, export_name: bytes) -> int:
    remote = find_remote_module(pid, dll_path.name)
    if remote is None:
        raise OSError("DLL not found in remote process")
    local_mod = kernel32.LoadLibraryExW(str(dll_path.resolve()), None, DONT_RESOLVE_DLL_REFERENCES)
    if not local_mod:
        raise OSError(fmt_error("LoadLibraryExW failed"))
    try:
        local_exp = kernel32.GetProcAddress(local_mod, export_name)
        if not local_exp:
            raise OSError(fmt_error(f"GetProcAddress({export_name.decode()}) failed"))
        return remote[0] + (ctypes.cast(local_exp, ctypes.c_void_p).value - ctypes.cast(local_mod, ctypes.c_void_p).value)
    finally:
        kernel32.FreeLibrary(local_mod)


def start_remote_runtime(pid: int, dll_path: Path) -> None:
    proc = open_process(pid)
    try:
        remote_start = resolve_remote_export(pid, dll_path, b"StartRuntimeThreadProc")
        tid = wintypes.DWORD(0)
        h = kernel32.CreateRemoteThread(proc, None, 0, remote_start, None, 0, ctypes.byref(tid))
        if not h:
            raise OSError(fmt_error("CreateRemoteThread(StartRuntimeThreadProc) failed"))
        if kernel32.WaitForSingleObject(h, INFINITE) != 0:
            raise OSError("WaitForSingleObject(StartRuntimeThreadProc) failed")
        ec = wintypes.DWORD(0)
        kernel32.GetExitCodeThread(h, ctypes.byref(ec))
        kernel32.CloseHandle(h)
        if ec.value != 0:
            raise OSError(f"StartRuntimeThreadProc exit code: {ec.value}")
        info("Remote runtime started")
    finally:
        kernel32.CloseHandle(proc)

def inject_dll(pid: int, dll_path: Path) -> None:
    if not dll_path.exists():
        raise FileNotFoundError(f"DLL not found: {dll_path}")
    print()
    print("=" * 44)
    print("  INJECTION")
    print("=" * 44)
    dll_str = str(dll_path.resolve())
    dll_buf = ctypes.create_unicode_buffer(dll_str)
    dll_bytes = ctypes.sizeof(dll_buf)
    proc = open_process(pid)
    try:
        remote_mem = kernel32.VirtualAllocEx(proc, None, dll_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote_mem:
            raise OSError(fmt_error("VirtualAllocEx failed"))
        info(f"Allocated {dll_bytes} bytes")
        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(proc, remote_mem, dll_buf, dll_bytes, ctypes.byref(written)):
            raise OSError(fmt_error("WriteProcessMemory failed"))
        info("DLL path written to remote memory")
        loadlib = resolve_remote_loadlibrary(pid)
        tid = wintypes.DWORD(0)
        h_thread = kernel32.CreateRemoteThread(proc, None, 0, loadlib, remote_mem, 0, ctypes.byref(tid))
        if not h_thread:
            raise OSError(fmt_error("CreateRemoteThread failed"))
        kernel32.WaitForSingleObject(h_thread, INFINITE)
        ec = wintypes.DWORD(0)
        kernel32.GetExitCodeThread(h_thread, ctypes.byref(ec))
        kernel32.CloseHandle(h_thread)
        print(f"  LoadLibraryW exit code: 0x{ec.value:x}")
        if ec.value == 0:
            raise OSError(
                "LoadLibraryW returned NULL!\n"
                "  Check: 1) Architecture  2) VCRUNTIME deps  3) Anticheat"
            )
        module = wait_for_remote_module(pid, dll_path.name)
        if module:
            info(f"Module confirmed at 0x{module[0]:x}")
        start_remote_runtime(pid, dll_path)
    finally:
        kernel32.CloseHandle(proc)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--pid", type=int)
    p.add_argument("--process", type=str)
    p.add_argument("--dll", type=Path)
    p.add_argument("--check-arch", action="store_true")
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()
    pid = args.pid
    if pid is None:
        if not args.process:
            p.error("--pid or --process required")
        pid = find_process_by_name(args.process)
        if pid is None:
            sys.exit(f"Process not found: {args.process}")
    dll_path = args.dll
    if dll_path is None:
        dll_path = Path(__file__).resolve().parent.parent / "bin" / "luna_extracted_native.dll"
    if args.debug:
        enable_debug_privilege()
    print(f"DLL: {dll_path}")
    print(f"PID: {pid}")
    if not check_architecture_match(pid, dll_path):
        if args.check_arch:
            sys.exit(1)
    if args.check_arch:
        return
    inject_dll(pid, dll_path)
    print("DONE!")

if __name__ == "__main__":
    main()
