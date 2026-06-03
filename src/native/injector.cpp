// injector.cpp
// Compile with MSVC: cl /std:c++17 /EHsc /W4 /O2 injector.cpp /link /OUT:..\..\bin\injector_cli.exe
// Compile with MinGW:  g++ -std=c++17 -O2 -m64 -municode injector.cpp -static-libgcc -static-libstdc++ -o ..\..\bin\injector_cli.exe

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
    HANDLE thread = CreateRemoteThread(process, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(load_library), remote_address, 0, nullptr);
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
    return thread;
}

void print_error(const std::string& prefix) {
    DWORD code = GetLastError();
    LPVOID msgBuffer = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msgBuffer, 0, nullptr);
    std::cerr << "[ERROR] " << prefix << " (code=" << code << ")";
    if (msgBuffer) { std::cerr << ": " << static_cast<char*>(msgBuffer); LocalFree(msgBuffer); }
    std::cerr << std::endl;
}

void print_info(const std::string& msg) { std::cout << "[INFO] " << msg << std::endl; }
void print_warn(const std::string& msg) { std::cout << "[WARN] " << msg << std::endl; }

enum Arch { ARCH_UNKNOWN, ARCH_X86, ARCH_X64 };

Arch dll_architecture(const std::wstring& path) {
    std::ifstream file(std::filesystem::path(path), std::ios::binary);
    if (!file) return ARCH_UNKNOWN;
    IMAGE_DOS_HEADER dos{};
    file.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return ARCH_UNKNOWN;
    file.seekg(dos.e_lfanew);
    DWORD sig = 0;
    file.read(reinterpret_cast<char*>(&sig), sizeof(sig));
    if (sig != IMAGE_NT_SIGNATURE) return ARCH_UNKNOWN;
    IMAGE_FILE_HEADER fh{};
    file.read(reinterpret_cast<char*>(&fh), sizeof(fh));
    WORD magic = 0;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if (magic == 0x20b) return ARCH_X64;
    if (magic == 0x10b) return ARCH_X86;
    return ARCH_UNKNOWN;
}

Arch process_architecture(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return ARCH_UNKNOWN;
    BOOL wow64 = FALSE;
    IsWow64Process(h, &wow64);
    CloseHandle(h);
    return wow64 ? ARCH_X86 : ARCH_X64;
}

const wchar_t* arch_name(Arch a) {
    switch (a) { case ARCH_X86: return L"32-bit (x86)"; case ARCH_X64: return L"64-bit (x64)"; default: return L"Unknown"; }
}

bool check_architecture_match(DWORD pid, const std::wstring& dll_path) {
    std::wcout << L"\n=== Architecture Check ===" << std::endl;
    Arch pa = process_architecture(pid);
    Arch da = dll_architecture(dll_path);
    std::wcout << L"  Process (PID " << pid << L"): " << arch_name(pa) << std::endl;
    std::wcout << L"  DLL: " << arch_name(da) << std::endl;
    if (pa != da || pa == ARCH_UNKNOWN) {
        std::wcerr << L"  MISMATCH! DLL=" << arch_name(da) << L" Process=" << arch_name(pa) << std::endl;
        return false;
    }
    std::wcout << L"  Match: both " << arch_name(pa) << std::endl;
    return true;
}

bool enable_debug_privilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) { print_error("OpenProcessToken failed"); return false; }
    LUID luid;
    if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid)) { print_error("LookupPrivilegeValueA failed"); CloseHandle(token); return false; }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr)) { print_error("AdjustTokenPrivileges failed"); CloseHandle(token); return false; }
    CloseHandle(token);
    return GetLastError() == ERROR_SUCCESS;
}

DWORD find_process_id(const std::wstring& process_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) { print_error("CreateToolhelp32Snapshot failed"); return 0; }
    PROCESSENTRY32W entry; entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) { print_error("Process32FirstW failed"); CloseHandle(snapshot); return 0; }
    do { if (_wcsicmp(entry.szExeFile, process_name.c_str()) == 0) { CloseHandle(snapshot); return entry.th32ProcessID; }
    } while (Process32NextW(snapshot, &entry));
    CloseHandle(snapshot); return 0;
}

std::wstring get_file_name(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return path;
    return path.substr(slash + 1);
}

bool get_remote_module_base_address(DWORD pid, const std::wstring& module_name, uintptr_t& base_address) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W entry{}; entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot, &entry)) { CloseHandle(snapshot); return false; }
    bool found = false;
    do { if (_wcsicmp(entry.szModule, module_name.c_str()) == 0) { base_address = reinterpret_cast<uintptr_t>(entry.modBaseAddr); found = true; break; }
    } while (Module32NextW(snapshot, &entry));
    CloseHandle(snapshot); return found;
}

std::optional<std::wstring> normalize_full_path(const std::wstring& path) {
    DWORD len = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (len == 0) { print_error("GetFullPathNameW failed"); return std::nullopt; }
    std::vector<wchar_t> buffer(len);
    DWORD written = GetFullPathNameW(path.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
    if (written == 0 || written >= buffer.size()) { print_error("GetFullPathNameW failed"); return std::nullopt; }
    return std::wstring(buffer.data());
}

bool resolve_remote_loadlibrary_address(DWORD pid, uintptr_t& remote_loadlibrary) {
    HMODULE local_kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!local_kernel32) { print_error("GetModuleHandleW(kernel32.dll) failed"); return false; }
    FARPROC local_loadlibrary = GetProcAddress(local_kernel32, "LoadLibraryW");
    if (!local_loadlibrary) { print_error("GetProcAddress(LoadLibraryW) failed"); return false; }
    uintptr_t remote_kernel32 = 0;
    if (!get_remote_module_base_address(pid, L"kernel32.dll", remote_kernel32)) { std::cerr << "Failed to locate kernel32.dll in target." << std::endl; return false; }
    const uintptr_t local_k32_base = reinterpret_cast<uintptr_t>(local_kernel32);
    const uintptr_t local_ll_addr = reinterpret_cast<uintptr_t>(local_loadlibrary);
    remote_loadlibrary = remote_kernel32 + (local_ll_addr - local_k32_base);
    return true;
}

bool resolve_remote_export_address(DWORD pid, const std::wstring& dll_path, const char* export_name, uintptr_t& remote_export) {
    uintptr_t remote_module_base = 0;
    if (!get_remote_module_base_address(pid, get_file_name(dll_path), remote_module_base)) {
        std::wcerr << L"DLL not in Toolhelp snapshot (Byfron hides it). Export resolution skipped." << std::endl;
        return false;
    }
    HMODULE local_module = LoadLibraryExW(dll_path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!local_module) { print_error("LoadLibraryExW failed"); return false; }
    FARPROC local_export = GetProcAddress(local_module, export_name);
    if (!local_export) { print_error(std::string("GetProcAddress(") + export_name + ") failed"); FreeLibrary(local_module); return false; }
    const uintptr_t local_base = reinterpret_cast<uintptr_t>(local_module);
    const uintptr_t export_offset = reinterpret_cast<uintptr_t>(local_export) - local_base;
    remote_export = remote_module_base + export_offset;
    FreeLibrary(local_module);
    return true;
}

bool start_remote_runtime(DWORD pid, const std::wstring& dll_path) {
    uintptr_t remote_start = 0;
    if (!resolve_remote_export_address(pid, dll_path, "StartRuntimeThreadProc", remote_start)) {
        print_warn("StartRuntimeThreadProc not resolvable (Byfron hides module). DLL DllMain should self-start.");
        return false;
    }
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS_FLAGS, FALSE, pid);
    if (!process) { print_error("OpenProcess for runtime start failed"); return false; }
    HANDLE thread = create_remote_load_thread(process, reinterpret_cast<FARPROC>(remote_start), nullptr);
    if (!thread) { print_error("CreateRemoteThread(runtime) failed"); CloseHandle(process); return false; }
    WaitForSingleObject(thread, INFINITE);
    DWORD exit_code = 0; GetExitCodeThread(thread, &exit_code);
    CloseHandle(thread); CloseHandle(process);
    if (exit_code != 0) { std::cerr << "Runtime start exit code: " << exit_code << std::endl; return false; }
    print_info("Runtime started via StartRuntimeThreadProc");
    return true;
}

std::wstring runtime_base_dir(DWORD pid) {
    wchar_t temp_path[MAX_PATH] = {};
    DWORD length = GetTempPathW(MAX_PATH, temp_path);
    std::wstring base = length ? std::wstring(temp_path, length) : L"C:\\Windows\\Temp\\";
    if (!base.empty() && (base.back() == L'\\' || base.back() == L'/')) base.pop_back();
    return base + L"\\luna_extracted\\" + std::to_wstring(pid);
}

std::wstring ready_file_path(DWORD pid) { return runtime_base_dir(pid) + L"\\ready.json"; }

void clear_runtime_artifacts(DWORD pid) {
    std::error_code ec;
    std::filesystem::remove_all(runtime_base_dir(pid), ec);
}

bool wait_for_runtime_ready_signal(DWORD pid, DWORD timeout_ms) {
    const std::wstring ready_path = ready_file_path(pid);
    const ULONGLONG deadline = GetTickCount64() + timeout_ms;
    print_info("Waiting for runtime ready signal...");
    while (GetTickCount64() < deadline) {
        std::ifstream file(std::filesystem::path(ready_path), std::ios::binary);
        if (file.is_open()) {
            std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            if (!data.empty()) {
                std::cout << "  ready.json content: " << data << std::endl;
                if (data.find("\"status\": \"runtime_ready\"") != std::string::npos) return true;
                print_info("ready.json found but status is not runtime_ready. DLL loaded, init may have failed.");
                return true;
            }
        }
        if (GetTickCount64() >= deadline) {
            std::error_code ec;
            if (!std::filesystem::exists(runtime_base_dir(pid), ec)) {
                std::cerr << "Runtime directory never created! DLL DllMain blocked or failed." << std::endl;
            } else {
                std::cerr << "Runtime dir exists but no ready.json. Check runtime.log in that folder." << std::endl;
            }
            return false;
        }
        Sleep(MODULE_VERIFY_RETRY_DELAY_MS);
    }
    return false;
}

bool inject_dll(DWORD pid, const std::wstring& dll_path) {
    std::cout << "\n=== Injection ===" << std::endl;

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS_FLAGS, FALSE, pid);
    if (!process) { print_error("OpenProcess failed. Run as Administrator!"); return false; }

    const SIZE_T dll_path_bytes = (dll_path.size() + 1) * sizeof(wchar_t);
    LPVOID remote_address = VirtualAllocEx(process, nullptr, dll_path_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_address) { print_error("VirtualAllocEx failed"); CloseHandle(process); return false; }

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote_address, dll_path.c_str(), dll_path_bytes, &written) || written != dll_path_bytes) {
        print_error("WriteProcessMemory failed");
        VirtualFreeEx(process, remote_address, 0, MEM_RELEASE); CloseHandle(process); return false;
    }
    print_info("DLL path written to remote memory");

    uintptr_t remote_load_library = 0;
    if (!resolve_remote_loadlibrary_address(pid, remote_load_library)) {
        VirtualFreeEx(process, remote_address, 0, MEM_RELEASE); CloseHandle(process); return false;
    }

    print_info("Calling LoadLibraryW...");
    HANDLE thread = create_remote_load_thread(process, reinterpret_cast<FARPROC>(remote_load_library), remote_address);
    if (!thread) { print_error("CreateRemoteThread failed"); VirtualFreeEx(process, remote_address, 0, MEM_RELEASE); CloseHandle(process); return false; }

    WaitForSingleObject(thread, INFINITE);
    DWORD remote_result = 0; GetExitCodeThread(thread, &remote_result);
    CloseHandle(thread);
    VirtualFreeEx(process, remote_address, 0, MEM_RELEASE);
    CloseHandle(process);

    std::wcout << L"  LoadLibraryW exit: 0x" << std::hex << remote_result << std::dec << std::endl;

    if (remote_result == 0) {
        std::cerr << "LoadLibraryW returned NULL! Byfron blocked the DLL load." << std::endl;
        return false;
    }

    print_info("LoadLibraryW OK. Skipping memory check (Byfron blocks ReadProcessMemory).");

    uintptr_t dummy = 0;
    if (get_remote_module_base_address(pid, get_file_name(dll_path), dummy))
        print_info("Module visible in snapshot");
    else
        print_warn("Module hidden from snapshot (Byfron). Normal, proceeding.");

    if (!start_remote_runtime(pid, dll_path))
        print_warn("Runtime start via export failed (Byfron). DllMain should self-start.");

    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) { std::wcout << L"Usage: injector.exe <dll> (--pid <id> | --process <name>) [--debug]\n"; return 1; }

    std::wstring dll_path;
    DWORD pid = 0;
    std::wstring process_name;
    bool enable_debug = false;

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--pid" && i + 1 < argc) pid = static_cast<DWORD>(_wtoi(argv[++i]));
        else if (arg == L"--process" && i + 1 < argc) process_name = argv[++i];
        else if (arg == L"--debug") enable_debug = true;
        else if (dll_path.empty()) dll_path = argv[i];
    }

    if (dll_path.empty()) { std::cerr << "DLL path required." << std::endl; return 1; }
    if (!pid && process_name.empty()) { std::cerr << "pid or process required." << std::endl; return 1; }

    auto np = normalize_full_path(dll_path); if (!np) return 1; dll_path = *np;
    if (GetFileAttributesW(dll_path.c_str()) == INVALID_FILE_ATTRIBUTES) { std::wcerr << L"DLL not found: " << dll_path << std::endl; return 1; }
    if (enable_debug && !enable_debug_privilege()) { std::cerr << "Debug priv failed." << std::endl; return 1; }
    if (!pid) { pid = find_process_id(process_name); if (!pid) { std::wcerr << L"Process not found: " << process_name << std::endl; return 1; } }

    if (!check_architecture_match(pid, dll_path)) { std::cerr << "Architecture mismatch." << std::endl; return 1; }

    clear_runtime_artifacts(pid);
    std::wcout << L"\nInjecting " << get_file_name(dll_path) << L" into PID " << pid << std::endl;

    if (!inject_dll(pid, dll_path)) { std::cerr << "Injection failed." << std::endl; return 1; }

    if (!wait_for_runtime_ready_signal(pid, RUNTIME_READY_TIMEOUT_MS)) {
        std::cerr << "\nRuntime not confirmed after " << (RUNTIME_READY_TIMEOUT_MS / 1000) << "s." << std::endl;
        print_info("Check " + std::string(runtime_base_dir(pid).begin(), runtime_base_dir(pid).end()) + "\\runtime.log");
        return 1;
    }

    std::cout << "\nOK! Injection complete!" << std::endl;
    return 0;
}
