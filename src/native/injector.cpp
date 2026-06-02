// injector.cpp
// Compile with MSVC:
//   cl /std:c++17 /EHsc /W4 /O2 injector.cpp /link /OUT:..\..\bin\injector_cli.exe
// Compile with MinGW-w64:
//   g++ -std=c++17 -O2 -municode injector.cpp -o ..\..\bin\injector_cli.exe

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

HANDLE create_remote_load_thread(HANDLE process, FARPROC load_library, LPVOID remote_address) {
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
    HANDLE thread = CreateRemoteThread(
        process,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(load_library),
        remote_address,
        0,
        nullptr);
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
    std::cerr << prefix << " (error=" << code << ")";
    if (msgBuffer) {
        std::cerr << ": " << static_cast<char*>(msgBuffer);
        LocalFree(msgBuffer);
    }
    std::cerr << std::endl;
}

bool enable_debug_privilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        print_error("OpenProcessToken failed");
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid)) {
        print_error("LookupPrivilegeValueA failed");
        CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        print_error("AdjustTokenPrivileges failed");
        CloseHandle(token);
        return false;
    }

    CloseHandle(token);
    return GetLastError() == ERROR_SUCCESS;
}

DWORD find_process_id(const std::wstring& process_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        print_error("CreateToolhelp32Snapshot failed");
        return 0;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) {
        print_error("Process32FirstW failed");
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (_wcsicmp(entry.szExeFile, process_name.c_str()) == 0) {
            CloseHandle(snapshot);
            return entry.th32ProcessID;
        }
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return 0;
}

std::wstring get_file_name(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return path;
    }
    return path.substr(slash + 1);
}

bool get_remote_module_base_address(DWORD pid, const std::wstring& module_name, uintptr_t& base_address) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        print_error("CreateToolhelp32Snapshot(module) failed");
        return false;
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot, &entry)) {
        print_error("Module32FirstW failed");
        CloseHandle(snapshot);
        return false;
    }

    bool found = false;
    do {
        if (_wcsicmp(entry.szModule, module_name.c_str()) == 0) {
            base_address = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
            found = true;
            break;
        }
    } while (Module32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return found;
}

std::optional<std::wstring> normalize_full_path(const std::wstring& path) {
    DWORD len = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (len == 0) {
        print_error("GetFullPathNameW failed");
        return std::nullopt;
    }

    std::vector<wchar_t> buffer(len);
    DWORD written = GetFullPathNameW(path.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
    if (written == 0 || written >= buffer.size()) {
        print_error("GetFullPathNameW failed");
        return std::nullopt;
    }

    return std::wstring(buffer.data());
}

bool is_module_loaded(DWORD pid, const std::wstring& expected_path, HMODULE* remote_module = nullptr) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        print_error("CreateToolhelp32Snapshot(module) failed");
        return false;
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot, &entry)) {
        print_error("Module32FirstW failed");
        CloseHandle(snapshot);
        return false;
    }

    const std::wstring expected_name = get_file_name(expected_path);
    bool found = false;
    do {
        if (_wcsicmp(entry.szExePath, expected_path.c_str()) == 0 || _wcsicmp(entry.szModule, expected_name.c_str()) == 0) {
            if (remote_module) {
                *remote_module = entry.hModule;
            }
            found = true;
            break;
        }
    } while (Module32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return found;
}

bool resolve_remote_loadlibrary_address(DWORD pid, uintptr_t& remote_loadlibrary) {
    HMODULE local_kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!local_kernel32) {
        print_error("GetModuleHandleW(kernel32.dll) failed");
        return false;
    }

    FARPROC local_loadlibrary = GetProcAddress(local_kernel32, "LoadLibraryW");
    if (!local_loadlibrary) {
        print_error("GetProcAddress(LoadLibraryW) failed");
        return false;
    }

    uintptr_t remote_kernel32 = 0;
    if (!get_remote_module_base_address(pid, L"kernel32.dll", remote_kernel32)) {
        std::cerr << "Failed to locate kernel32.dll in target process." << std::endl;
        return false;
    }

    const uintptr_t local_kernel32_base = reinterpret_cast<uintptr_t>(local_kernel32);
    const uintptr_t local_loadlibrary_addr = reinterpret_cast<uintptr_t>(local_loadlibrary);
    const uintptr_t loadlibrary_offset = local_loadlibrary_addr - local_kernel32_base;
    remote_loadlibrary = remote_kernel32 + loadlibrary_offset;
    return true;
}

bool resolve_remote_export_address(DWORD pid, const std::wstring& dll_path, const char* export_name, uintptr_t& remote_export) {
    uintptr_t remote_module_base = 0;
    if (!get_remote_module_base_address(pid, get_file_name(dll_path), remote_module_base)) {
        std::wcerr << L"Failed to locate target DLL in remote process for export resolution." << std::endl;
        return false;
    }

    HMODULE local_module = LoadLibraryExW(dll_path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!local_module) {
        print_error("LoadLibraryExW(DONT_RESOLVE_DLL_REFERENCES) failed");
        return false;
    }

    FARPROC local_export = GetProcAddress(local_module, export_name);
    if (!local_export) {
        print_error(std::string("GetProcAddress(") + export_name + ") failed");
        FreeLibrary(local_module);
        return false;
    }

    const uintptr_t local_base = reinterpret_cast<uintptr_t>(local_module);
    const uintptr_t local_export_addr = reinterpret_cast<uintptr_t>(local_export);
    const uintptr_t export_offset = local_export_addr - local_base;
    remote_export = remote_module_base + export_offset;
    FreeLibrary(local_module);
    return true;
}

bool start_remote_runtime(DWORD pid, const std::wstring& dll_path) {
    uintptr_t remote_start = 0;
    if (!resolve_remote_export_address(pid, dll_path, "StartRuntimeThreadProc", remote_start)) {
        return false;
    }

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS_FLAGS, FALSE, pid);
    if (!process) {
        print_error("OpenProcess for StartRuntimeThreadProc failed");
        return false;
    }

    HANDLE thread = create_remote_load_thread(process, reinterpret_cast<FARPROC>(remote_start), nullptr);
    if (!thread) {
        print_error("CreateRemoteThread(StartRuntimeThreadProc) failed");
        CloseHandle(process);
        return false;
    }

    if (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0) {
        print_error("WaitForSingleObject(StartRuntimeThreadProc) failed");
        CloseHandle(thread);
        CloseHandle(process);
        return false;
    }

    DWORD exit_code = 0;
    if (!GetExitCodeThread(thread, &exit_code)) {
        print_error("GetExitCodeThread(StartRuntimeThreadProc) failed");
        CloseHandle(thread);
        CloseHandle(process);
        return false;
    }

    CloseHandle(thread);
    CloseHandle(process);
    if (exit_code != 0) {
        std::cerr << "StartRuntimeThreadProc returned non-zero exit code: " << exit_code << std::endl;
        return false;
    }
    return true;
}

bool wait_for_module_loaded(DWORD pid, const std::wstring& expected_path, DWORD timeout_ms, HMODULE* remote_module = nullptr) {
    const ULONGLONG deadline = GetTickCount64() + timeout_ms;
    do {
        HMODULE current_module = nullptr;
        if (is_module_loaded(pid, expected_path, &current_module)) {
            if (remote_module) {
                *remote_module = current_module;
            }
            return true;
        }
        Sleep(MODULE_VERIFY_RETRY_DELAY_MS);
    } while (GetTickCount64() < deadline);

    return false;
}

bool validate_remote_module_memory(HANDLE process, DWORD remote_result) {
    if (remote_result == 0) {
        return false;
    }

    IMAGE_DOS_HEADER dos_header{};
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(remote_result)),
                           &dos_header, sizeof(dos_header), &bytes_read) ||
        bytes_read != sizeof(dos_header)) {
        return false;
    }

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE || dos_header.e_lfanew <= 0) {
        return false;
    }

    DWORD nt_signature = 0;
    const uintptr_t nt_addr = static_cast<uintptr_t>(remote_result) + static_cast<uintptr_t>(dos_header.e_lfanew);
    bytes_read = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(nt_addr), &nt_signature, sizeof(nt_signature), &bytes_read) ||
        bytes_read != sizeof(nt_signature)) {
        return false;
    }

    return nt_signature == IMAGE_NT_SIGNATURE;
}

std::wstring runtime_base_dir(DWORD pid) {
    wchar_t temp_path[MAX_PATH] = {};
    DWORD length = GetTempPathW(MAX_PATH, temp_path);
    std::wstring base = length ? std::wstring(temp_path, length) : L"C:\\Windows\\Temp\\";
    if (!base.empty() && (base.back() == L'\\' || base.back() == L'/')) {
        base.pop_back();
    }
    return base + L"\\luna_extracted\\" + std::to_wstring(pid);
}

std::wstring ready_file_path(DWORD pid) {
    return runtime_base_dir(pid) + L"\\ready.json";
}

void clear_runtime_artifacts(DWORD pid) {
    std::error_code ec;
    std::filesystem::remove_all(runtime_base_dir(pid), ec);
}

bool wait_for_runtime_ready_signal(DWORD pid, DWORD timeout_ms) {
    const std::wstring ready_path = ready_file_path(pid);
    const ULONGLONG deadline = GetTickCount64() + timeout_ms;
    do {
        std::ifstream file(std::filesystem::path(ready_path), std::ios::binary);
        if (file.is_open()) {
            std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            if (data.find("\"status\": \"runtime_ready\"") != std::string::npos) {
                return true;
            }
        }
        Sleep(MODULE_VERIFY_RETRY_DELAY_MS);
    } while (GetTickCount64() < deadline);
    return false;
}

bool inject_dll(DWORD pid, const std::wstring& dll_path) {
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS_FLAGS, FALSE, pid);
    if (!process) {
        print_error("OpenProcess failed");
        return false;
    }

    const SIZE_T dll_path_bytes = (dll_path.size() + 1) * sizeof(wchar_t);
    LPVOID remote_address = VirtualAllocEx(process, nullptr, dll_path_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_address) {
        print_error("VirtualAllocEx failed");
        CloseHandle(process);
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote_address, dll_path.c_str(), dll_path_bytes, &written) || written != dll_path_bytes) {
        print_error("WriteProcessMemory failed");
        VirtualFreeEx(process, remote_address, 0, MEM_RELEASE);
        CloseHandle(process);
        return false;
    }

    uintptr_t remote_load_library = 0;
    if (!resolve_remote_loadlibrary_address(pid, remote_load_library)) {
        VirtualFreeEx(process, remote_address, 0, MEM_RELEASE);
        CloseHandle(process);
        return false;
    }

    HANDLE thread = create_remote_load_thread(process, reinterpret_cast<FARPROC>(remote_load_library), remote_address);
    if (!thread) {
        print_error("CreateRemoteThread failed");
        VirtualFreeEx(process, remote_address, 0, MEM_RELEASE);
        CloseHandle(process);
        return false;
    }

    if (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0) {
        print_error("WaitForSingleObject failed");
        CloseHandle(thread);
        VirtualFreeEx(process, remote_address, 0, MEM_RELEASE);
        CloseHandle(process);
        return false;
    }

    DWORD remote_result = 0;
    if (!GetExitCodeThread(thread, &remote_result)) {
        print_error("GetExitCodeThread failed");
        CloseHandle(thread);
        VirtualFreeEx(process, remote_address, 0, MEM_RELEASE);
        CloseHandle(process);
        return false;
    }

    const bool remote_memory_valid = validate_remote_module_memory(process, remote_result);

    CloseHandle(thread);
    VirtualFreeEx(process, remote_address, 0, MEM_RELEASE);

    if (remote_result == 0) {
        CloseHandle(process);
        std::cerr << "Remote LoadLibraryW returned NULL." << std::endl;
        return false;
    }

    HMODULE verified_module = nullptr;
    if (!wait_for_module_loaded(pid, dll_path, MODULE_VERIFY_TIMEOUT_MS, &verified_module)) {
        std::wcerr << L"Module enumeration did not confirm the DLL after " << MODULE_VERIFY_TIMEOUT_MS
                   << L" ms. LoadLibraryW returned non-zero, but the module was not observable via Toolhelp snapshot."
                   << std::endl;
        if (remote_memory_valid) {
            std::wcerr << L"Returned HMODULE points to a valid PE image at 0x"
                       << std::hex << remote_result << std::dec
                       << L". Proceeding with runtime readiness validation." << std::endl;
        } else {
            std::wcerr << L"Returned HMODULE memory is not a valid PE image. The DLL may have been unloaded immediately, hidden from enumeration, or blocked during initialization. "
                       << L"Proceeding with runtime readiness validation anyway." << std::endl;
        }
        CloseHandle(process);
        start_remote_runtime(pid, dll_path);
        return true;
    }

    CloseHandle(process);
    std::wcout << L"Verified remote module base: 0x" << std::hex
               << reinterpret_cast<uintptr_t>(verified_module) << std::dec << std::endl;
    start_remote_runtime(pid, dll_path);
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        std::wcout << L"Usage: injector.exe <dll_path> (--pid <pid> | --process <name>) [--debug]" << std::endl;
        return 1;
    }

    std::wstring dll_path;
    DWORD pid = 0;
    std::wstring process_name;
    bool enable_debug = false;

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--pid" && i + 1 < argc) {
            pid = static_cast<DWORD>(_wtoi(argv[++i]));
        } else if (arg == L"--process" && i + 1 < argc) {
            process_name = argv[++i];
        } else if (arg == L"--debug") {
            enable_debug = true;
        } else if (dll_path.empty()) {
            dll_path = argv[i];
        }
    }

    if (dll_path.empty()) {
        std::cerr << "DLL path is required." << std::endl;
        return 1;
    }

    if (!pid && process_name.empty()) {
        std::cerr << "Either --pid or --process is required." << std::endl;
        return 1;
    }

    auto normalized_path = normalize_full_path(dll_path);
    if (!normalized_path) {
        return 1;
    }
    dll_path = *normalized_path;

    DWORD file_attributes = GetFileAttributesW(dll_path.c_str());
    if (file_attributes == INVALID_FILE_ATTRIBUTES || (file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        std::wcerr << L"DLL path is invalid: " << dll_path << std::endl;
        return 1;
    }

    if (enable_debug) {
        if (!enable_debug_privilege()) {
            std::cerr << "Failed to enable debug privilege." << std::endl;
            return 1;
        }
    }

    if (!pid) {
        pid = find_process_id(process_name);
        if (!pid) {
            std::wcerr << L"Could not find process: " << process_name << std::endl;
            return 1;
        }
    }

    clear_runtime_artifacts(pid);
    std::wcout << L"Injecting: " << dll_path << L" into PID " << pid << std::endl;
    if (!inject_dll(pid, dll_path)) {
        std::cerr << "Injection failed." << std::endl;
        return 1;
    }

    if (!wait_for_runtime_ready_signal(pid, 15000)) {
        std::wcerr << L"Runtime ready signal was not observed after injection within 15000 ms." << std::endl;
        return 1;
    }

    std::wcout << L"Injection succeeded and runtime ready signal was confirmed." << std::endl;
    return 0;
}
