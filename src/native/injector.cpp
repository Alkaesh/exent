// injector.cpp — with proper LoadLibraryW validation and Byfron awareness
// Compile with MinGW: g++ -std=c++17 -O2 -m64 -municode injector.cpp -static -o injector_cli.exe

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <iostream>
#include <optional>
#include <filesystem>
#include <fstream>

static const DWORD PROCESS_ALL_ACCESS_FLAGS = 0x001F0FFF;
static const DWORD MODULE_VERIFY_TIMEOUT_MS = 5000;
static const DWORD MODULE_VERIFY_RETRY_DELAY_MS = 100;
static const DWORD RUNTIME_READY_TIMEOUT_MS = 20000;

HANDLE create_remote_load_thread(HANDLE process, FARPROC load_library, LPVOID remote_address) {
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
    return CreateRemoteThread(process, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(load_library), remote_address, 0, nullptr);
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
}

void print_error(const std::string& prefix) {
    DWORD code = GetLastError();
    LPSTR buf = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buf, 0, nullptr);
    std::cerr << "[ERR] " << prefix << " (code=" << code << ")";
    if (buf) { std::cerr << ": " << buf; LocalFree(buf); }
    std::cerr << std::endl;
}

void info(const std::string& msg) { std::cout << "[OK]  " << msg << std::endl; }
void warn(const std::string& msg) { std::cout << "[WARN] " << msg << std::endl; }

// WIDE to narrow helper
std::string ws2s(const std::wstring& ws) {
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, &s[0], len, nullptr, nullptr);
    s.pop_back();
    return s;
}

// Architecture
enum Arch { ARCH_UNKNOWN, ARCH_X86, ARCH_X64 };

Arch dll_architecture(const std::wstring& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return ARCH_UNKNOWN;
    IMAGE_DOS_HEADER dos{}; f.read((char*)&dos, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return ARCH_UNKNOWN;
    f.seekg(dos.e_lfanew);
    DWORD sig; f.read((char*)&sig, sizeof(sig));
    if (sig != IMAGE_NT_SIGNATURE) return ARCH_UNKNOWN;
    IMAGE_FILE_HEADER fh{}; f.read((char*)&fh, sizeof(fh));
    WORD magic; f.read((char*)&magic, sizeof(magic));
    if (magic == 0x20b) return ARCH_X64;
    if (magic == 0x10b) return ARCH_X86;
    return ARCH_UNKNOWN;
}

Arch process_architecture(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return ARCH_UNKNOWN;
    BOOL w = FALSE; IsWow64Process(h, &w); CloseHandle(h);
    return w ? ARCH_X86 : ARCH_X64;
}

const wchar_t* arch_name(Arch a) {
    if (a == ARCH_X86) return L"32-bit";
    if (a == ARCH_X64) return L"64-bit";
    return L"?";
}

bool check_architecture(DWORD pid, const std::wstring& dll) {
    std::wcout << L"\n=== Architecture ===" << std::endl;
    Arch pa = process_architecture(pid), da = dll_architecture(dll);
    std::wcout << L"  Process: " << arch_name(pa) << L"\n  DLL:     " << arch_name(da) << std::endl;
    if (pa != da || pa == ARCH_UNKNOWN) {
        std::wcerr << L"  MISMATCH!" << std::endl; return false;
    }
    std::wcout << L"  OK" << std::endl;
    return true;
}

// Process
bool enable_debug_privilege() {
    HANDLE t; if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &t)) return false;
    LUID l; LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &l);
    TOKEN_PRIVILEGES tp{1, l, SE_PRIVILEGE_ENABLED};
    AdjustTokenPrivileges(t, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(t);
    return GetLastError() == ERROR_SUCCESS;
}

DWORD find_pid(const std::wstring& name) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W e{sizeof(e)};
    if (!Process32FirstW(s, &e)) { CloseHandle(s); return 0; }
    do { if (_wcsicmp(e.szExeFile, name.c_str()) == 0) { CloseHandle(s); return e.th32ProcessID; }
    } while (Process32NextW(s, &e));
    CloseHandle(s); return 0;
}

std::wstring basename(const std::wstring& p) {
    auto i = p.find_last_of(L"\\/");
    return i == std::wstring::npos ? p : p.substr(i + 1);
}

bool remote_module_base(DWORD pid, const std::wstring& name, uintptr_t& base) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (s == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W e{sizeof(e)};
    if (!Module32FirstW(s, &e)) { CloseHandle(s); return false; }
    do { if (_wcsicmp(e.szModule, name.c_str()) == 0) { base = (uintptr_t)e.modBaseAddr; CloseHandle(s); return true; }
    } while (Module32NextW(s, &e));
    CloseHandle(s); return false;
}

std::optional<std::wstring> fullpath(const std::wstring& p) {
    DWORD n = GetFullPathNameW(p.c_str(), 0, nullptr, nullptr);
    if (!n) return {};
    std::vector<wchar_t> buf(n);
    GetFullPathNameW(p.c_str(), n, buf.data(), nullptr);
    return std::wstring(buf.data());
}

bool resolve_loadlibrary(DWORD pid, uintptr_t& addr) {
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32) return false;
    FARPROC ll = GetProcAddress(k32, "LoadLibraryW");
    if (!ll) return false;
    uintptr_t rk32 = 0;
    if (!remote_module_base(pid, L"kernel32.dll", rk32)) return false;
    addr = rk32 + ((uintptr_t)ll - (uintptr_t)k32);
    return true;
}

bool resolve_export(DWORD pid, const std::wstring& dll, const char* exp, uintptr_t& addr) {
    uintptr_t base = 0;
    if (!remote_module_base(pid, basename(dll), base)) {
        warn("DLL hidden from snapshot (Byfron). Export resolution not possible.");
        return false;
    }
    HMODULE m = LoadLibraryExW(dll.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!m) return false;
    FARPROC e = GetProcAddress(m, exp);
    if (!e) { FreeLibrary(m); return false; }
    addr = base + ((uintptr_t)e - (uintptr_t)m);
    FreeLibrary(m);
    return true;
}

bool start_runtime(DWORD pid, const std::wstring& dll) {
    uintptr_t start = 0;
    if (!resolve_export(pid, dll, "StartRuntimeThreadProc", start)) return false;
    HANDLE p = OpenProcess(PROCESS_ALL_ACCESS_FLAGS, FALSE, pid);
    if (!p) return false;
    HANDLE t = CreateRemoteThread(p, nullptr, 0, (LPTHREAD_START_ROUTINE)start, nullptr, 0, nullptr);
    if (!t) { CloseHandle(p); return false; }
    WaitForSingleObject(t, INFINITE);
    DWORD ec; GetExitCodeThread(t, &ec);
    CloseHandle(t); CloseHandle(p);
    if (ec != 0) { std::cerr << "Runtime start exit: " << ec << std::endl; return false; }
    info("Runtime started");
    return true;
}

std::wstring runtime_dir(DWORD pid) {
    wchar_t tmp[MAX_PATH]; GetTempPathW(MAX_PATH, tmp);
    std::wstring d(tmp);
    if (!d.empty() && (d.back() == L'\\' || d.back() == L'/')) d.pop_back();
    return d + L"\\luna_extracted\\" + std::to_wstring(pid);
}

void clear_runtime(DWORD pid) { std::filesystem::remove_all(runtime_dir(pid)); }

bool wait_ready(DWORD pid, DWORD timeout) {
    std::wstring rd = runtime_dir(pid);
    std::wstring rp = rd + L"\\ready.json";
    ULONGLONG dl = GetTickCount64() + timeout;
    info("Waiting for ready.json...");

    while (GetTickCount64() < dl) {
        std::ifstream f(rp, std::ios::binary);
        if (f.is_open()) {
            std::string d((std::istreambuf_iterator<char>(f)), {});
            std::cout << "  ready.json: " << d << std::endl;
            if (d.find("runtime_ready") != std::string::npos) return true;
            warn("ready.json found but status is not runtime_ready");
            return true;
        }
        if (GetTickCount64() >= dl) {
            std::error_code ec;
            if (!std::filesystem::exists(rd, ec)) {
                std::cerr << "\nRuntime folder never created! DLL blocked by Byfron." << std::endl;
                std::cerr << "LoadLibrary-based injection is detected and blocked." << std::endl;
                std::cerr << "You need manual mapping injection to bypass it." << std::endl;
            } else {
                std::cerr << "\nRuntime folder exists but no ready.json. Check: " << ws2s(rd) << "\\runtime.log" << std::endl;
            }
            return false;
        }
        Sleep(MODULE_VERIFY_RETRY_DELAY_MS);
    }
    return false;
}

bool inject(DWORD pid, const std::wstring& dll) {
    std::cout << "\n=== Injection ===" << std::endl;

    HANDLE p = OpenProcess(PROCESS_ALL_ACCESS_FLAGS, FALSE, pid);
    if (!p) { print_error("OpenProcess — run as ADMIN!"); return false; }

    SIZE_T sz = (dll.size() + 1) * sizeof(wchar_t);
    LPVOID mem = VirtualAllocEx(p, nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { print_error("VirtualAllocEx"); CloseHandle(p); return false; }

    SIZE_T wr;
    if (!WriteProcessMemory(p, mem, dll.c_str(), sz, &wr) || wr != sz) {
        print_error("WriteProcessMemory"); VirtualFreeEx(p, mem, 0, MEM_RELEASE); CloseHandle(p); return false;
    }
    info("Path written to remote process");

    uintptr_t ll = 0;
    if (!resolve_loadlibrary(pid, ll)) { VirtualFreeEx(p, mem, 0, MEM_RELEASE); CloseHandle(p); return false; }

    info("CreateRemoteThread -> LoadLibraryW...");
    HANDLE t = CreateRemoteThread(p, nullptr, 0, (LPTHREAD_START_ROUTINE)ll, mem, 0, nullptr);
    if (!t) { print_error("CreateRemoteThread"); VirtualFreeEx(p, mem, 0, MEM_RELEASE); CloseHandle(p); return false; }

    WaitForSingleObject(t, INFINITE);
    DWORD res; GetExitCodeThread(t, &res);
    CloseHandle(t);
    VirtualFreeEx(p, mem, 0, MEM_RELEASE);
    CloseHandle(p);

    std::wcout << L"  Exit code: 0x" << std::hex << res << std::dec << std::endl;

    // On x64, valid HMODULEs are in range 0x10000 to 0x00007FFFFFFFFFFF
    // Anything 0xC0000000+ is an NTSTATUS error — DLL blocked
    if (res == 0 || res >= 0xC0000000) {
        std::cerr << "\nLoadLibraryW FAILED! Byfron blocked the DLL." << std::endl;
        if (res >= 0xC0000000)
            std::cerr << "Exit code is an NTSTATUS error (0x" << std::hex << res << std::dec << ")." << std::endl;
        std::cerr << "\nSimple LoadLibrary injection is detected by Byfron." << std::endl;
        std::cerr << "You need manual mapping: inject the DLL by manually" << std::endl;
        std::cerr << "allocating memory, writing PE sections, handling relocations" << std::endl;
        std::cerr << "and imports — without calling LoadLibraryW." << std::endl;
        return false;
    }

    info("LoadLibraryW OK");

    uintptr_t dummy;
    if (remote_module_base(pid, basename(dll), dummy))
        info("Module visible in snapshot");
    else
        warn("Module hidden (Byfron) — normal");

    start_runtime(pid, dll); // Try, may fail due to Byfron
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        std::wcout << L"Usage: injector.exe <dll> (--pid N | --process name) [--debug]\n";
        return 1;
    }

    std::wstring dll; DWORD pid = 0; std::wstring pname; bool dbg = false;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--pid" && i + 1 < argc) pid = _wtoi(argv[++i]);
        else if (a == L"--process" && i + 1 < argc) pname = argv[++i];
        else if (a == L"--debug") dbg = true;
        else if (dll.empty()) dll = argv[i];
    }

    if (dll.empty()) { std::cerr << "DLL path required" << std::endl; return 1; }
    if (!pid && pname.empty()) { std::cerr << "--pid or --process required" << std::endl; return 1; }

    auto fp = fullpath(dll); if (!fp) return 1; dll = *fp;
    if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) { std::wcerr << L"DLL not found" << std::endl; return 1; }
    if (dbg) enable_debug_privilege();
    if (!pid) { pid = find_pid(pname); if (!pid) { std::wcerr << L"Process not found" << std::endl; return 1; } }

    if (!check_architecture(pid, dll)) { std::cerr << "Architecture mismatch" << std::endl; return 1; }

    clear_runtime(pid);
    std::wcout << L"\nInjecting " << basename(dll) << L" into PID " << pid << std::endl;

    if (!inject(pid, dll)) { std::cerr << "\nInjection failed." << std::endl; return 1; }

    if (!wait_ready(pid, RUNTIME_READY_TIMEOUT_MS)) {
        std::cerr << "\nRuntime not confirmed." << std::endl;
        return 1;
    }

    std::cout << "\nOK!" << std::endl;
    return 0;
}
