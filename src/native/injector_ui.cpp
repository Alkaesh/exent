#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <optional>
#include <system_error>
#include <cstdint>

static const DWORD PROCESS_ALL_ACCESS_FLAGS = 0x001F0FFF;
static const DWORD MODULE_VERIFY_TIMEOUT_MS = 5000;
static const DWORD MODULE_VERIFY_RETRY_DELAY_MS = 100;

enum ControlId {
    IDC_SCRIPT_LIST = 101,
    IDC_ADD_SCRIPT = 102,
    IDC_REMOVE_SCRIPT = 103,
    IDC_EXECUTE_SCRIPT = 104,
    IDC_INJECT_DLL = 105,
    IDC_BROWSE_DLL = 106,
    IDC_ENABLE_DEBUG = 107,
    IDC_SCRIPT_EDITOR = 108,
    IDC_OPEN_RUNTIME_LOG = 109,
};

struct ScriptEntry {
    std::wstring name;
    std::wstring content;
};

enum class InjectionStage {
    Idle,
    ModuleLoaded,
    RuntimeReady,
};

static HWND hScriptList = nullptr;
static HWND hScriptEditor = nullptr;
static HWND hDllPathEdit = nullptr;
static HWND hProcessNameEdit = nullptr;
static HWND hPidEdit = nullptr;
static HWND hLogEdit = nullptr;
static HWND hRuntimeLogPathEdit = nullptr;
static HWND hAddScriptButton = nullptr;
static HWND hRemoveScriptButton = nullptr;
static HWND hExecuteScriptButton = nullptr;
static HWND hInjectButton = nullptr;
static HWND hBrowseDllButton = nullptr;
static HWND hOpenRuntimeLogButton = nullptr;
static HWND hEnableDebugCheckbox = nullptr;
static HWND hStatusStatic = nullptr;
static HWND hSubStatusStatic = nullptr;
static HWND hStageStatic = nullptr;
static HWND hRuntimeCardStatic = nullptr;
static HWND hModuleCardStatic = nullptr;
static HFONT hTitleFont = nullptr;
static HFONT hSectionFont = nullptr;
static HFONT hBodyFont = nullptr;
static HFONT hMonoFont = nullptr;
static HBRUSH hBackgroundBrush = nullptr;
static HBRUSH hPanelBrush = nullptr;
static HBRUSH hPanelSoftBrush = nullptr;
static HBRUSH hAccentBrush = nullptr;

static std::vector<ScriptEntry> scriptEntries;
static DWORD gInjectedPid = 0;
static std::wstring gInjectedDllPath;
static std::wstring gRuntimeLogPath;
static InjectionStage gInjectionStage = InjectionStage::Idle;
static unsigned long long gCommandCounter = 0;

HANDLE CreateRemoteLoadThread(HANDLE process, FARPROC loadLibrary, LPVOID remoteAddress) {
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
    HANDLE thread = CreateRemoteThread(
        process,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibrary),
        remoteAddress,
        0,
        nullptr);
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
    return thread;
}

COLORREF StageColor(InjectionStage stage) {
    switch (stage) {
    case InjectionStage::Idle:
        return RGB(137, 143, 161);
    case InjectionStage::ModuleLoaded:
        return RGB(240, 198, 116);
    case InjectionStage::RuntimeReady:
        return RGB(154, 208, 143);
    default:
        return RGB(137, 143, 161);
    }
}

std::wstring StageName(InjectionStage stage) {
    switch (stage) {
    case InjectionStage::Idle:
        return L"Idle";
    case InjectionStage::ModuleLoaded:
        return L"Module Loaded";
    case InjectionStage::RuntimeReady:
        return L"Runtime Ready";
    default:
        return L"Unknown";
    }
}

void SetControlFont(HWND hwnd, HFONT font) {
    if (hwnd && font) {
        SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    }
}

std::wstring GetWindowTextString(HWND hwnd) {
    int len = GetWindowTextLengthW(hwnd);
    std::wstring buffer(len + 1, L'\0');
    GetWindowTextW(hwnd, buffer.data(), len + 1);
    buffer.resize(len);
    return buffer;
}

std::string WideToUtf8(const std::wstring& wide) {
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return std::string();
    }
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, result.data(), size, nullptr, nullptr);
    result.pop_back();
    return result;
}

std::wstring Utf8ToWide(const std::string& utf8) {
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (size <= 0) {
        return std::wstring();
    }
    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, result.data(), size);
    result.pop_back();
    return result;
}

std::wstring GetFileNameFromPath(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

void AppendLog(const std::wstring& text) {
    int length = GetWindowTextLengthW(hLogEdit);
    SendMessageW(hLogEdit, EM_SETSEL, length, length);
    SendMessageW(hLogEdit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text.c_str()));
    SendMessageW(hLogEdit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(L"\r\n"));
}

void UpdateExecuteButtonState() {
    if (hExecuteScriptButton) {
        const bool hasScript = !GetWindowTextString(hScriptEditor).empty();
        EnableWindow(hExecuteScriptButton, hasScript && gInjectionStage == InjectionStage::RuntimeReady);
    }
    if (hOpenRuntimeLogButton) {
        EnableWindow(hOpenRuntimeLogButton, !gRuntimeLogPath.empty());
    }
}

void UpdateStageWidgets() {
    if (hStageStatic) {
        SetWindowTextW(hStageStatic, (L"Stage: " + StageName(gInjectionStage)).c_str());
    }
    if (hRuntimeCardStatic) {
        std::wstring runtimeSummary = gRuntimeLogPath.empty()
            ? L"Runtime log unavailable"
            : L"Runtime log connected";
        SetWindowTextW(hRuntimeCardStatic, runtimeSummary.c_str());
    }
    if (hModuleCardStatic) {
        std::wstring moduleSummary = gInjectedPid == 0
            ? L"No target attached"
            : L"PID " + std::to_wstring(gInjectedPid) + L" attached";
        SetWindowTextW(hModuleCardStatic, moduleSummary.c_str());
    }
}

void SetInjectionState(InjectionStage stage, DWORD pid = 0, const std::wstring& dllPath = L"") {
    gInjectionStage = stage;
    if (stage == InjectionStage::Idle) {
        gInjectedPid = 0;
        gInjectedDllPath.clear();
        gRuntimeLogPath.clear();
        SetWindowTextW(hStatusStatic, L"Ready");
        SetWindowTextW(hSubStatusStatic, L"Inject the DLL to start the runtime handshake.");
    } else {
        gInjectedPid = pid;
        gInjectedDllPath = dllPath;
        if (stage == InjectionStage::ModuleLoaded) {
            SetWindowTextW(hStatusStatic, L"Module Loaded");
            SetWindowTextW(hSubStatusStatic, L"DLL is present in the process. Waiting for runtime ready signal.");
        } else {
            SetWindowTextW(hStatusStatic, L"Runtime Ready");
            SetWindowTextW(hSubStatusStatic, L"DLL handshake completed. Script execution is now enabled.");
        }
    }

    if (hRuntimeLogPathEdit) {
        SetWindowTextW(hRuntimeLogPathEdit, gRuntimeLogPath.empty() ? L"" : gRuntimeLogPath.c_str());
    }

    UpdateStageWidgets();
    UpdateExecuteButtonState();
    InvalidateRect(GetParent(hStatusStatic), nullptr, TRUE);
}

bool ReadFileToString(const std::wstring& path, std::wstring& outContent) {
    std::ifstream file(std::filesystem::path(path), std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    outContent = Utf8ToWide(data);
    return true;
}

std::optional<std::wstring> NormalizeFullPath(const std::wstring& path) {
    DWORD len = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (len == 0) {
        return std::nullopt;
    }

    std::vector<wchar_t> buffer(len);
    DWORD written = GetFullPathNameW(path.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
    if (written == 0 || written >= buffer.size()) {
        return std::nullopt;
    }

    return std::wstring(buffer.data());
}

std::wstring ExtractJsonStringField(const std::string& json, const std::string& key) {
    const std::string pattern = "\"" + key + "\"";
    size_t keyPos = json.find(pattern);
    if (keyPos == std::string::npos) {
        return L"";
    }
    size_t colonPos = json.find(':', keyPos + pattern.size());
    if (colonPos == std::string::npos) {
        return L"";
    }
    size_t startQuote = json.find('"', colonPos + 1);
    if (startQuote == std::string::npos) {
        return L"";
    }
    size_t pos = startQuote + 1;
    std::string value;
    while (pos < json.size()) {
        char c = json[pos];
        if (c == '\\' && pos + 1 < json.size()) {
            char escaped = json[pos + 1];
            switch (escaped) {
            case '"': value.push_back('"'); break;
            case '\\': value.push_back('\\'); break;
            case 'n': value.push_back('\n'); break;
            case 'r': value.push_back('\r'); break;
            case 't': value.push_back('\t'); break;
            default: value.push_back(escaped); break;
            }
            pos += 2;
            continue;
        }
        if (c == '"') {
            break;
        }
        value.push_back(c);
        ++pos;
    }
    return Utf8ToWide(value);
}

std::wstring GetRuntimeBaseDir(DWORD pid) {
    wchar_t tempPath[MAX_PATH] = {0};
    DWORD len = GetTempPathW(MAX_PATH, tempPath);
    std::wstring base = len ? std::wstring(tempPath, len) : L"C:\\Windows\\Temp\\";
    if (!base.empty() && (base.back() == L'\\' || base.back() == L'/')) {
        base.pop_back();
    }
    return base + L"\\luna_extracted\\" + std::to_wstring(pid);
}

std::wstring GetReadyFilePath(DWORD pid) {
    return GetRuntimeBaseDir(pid) + L"\\ready.json";
}

void ClearRuntimeArtifacts(DWORD pid) {
    std::error_code ec;
    std::filesystem::remove_all(GetRuntimeBaseDir(pid), ec);
}

std::wstring GetCommandDir(DWORD pid) {
    return GetRuntimeBaseDir(pid) + L"\\commands";
}

std::wstring GetAckFilePath(DWORD pid, const std::wstring& commandId) {
    return GetRuntimeBaseDir(pid) + L"\\acks\\" + commandId + L".json";
}

bool EnsureDirectory(const std::wstring& path) {
    std::error_code ec;
    return std::filesystem::create_directories(std::filesystem::path(path), ec) ||
           std::filesystem::exists(std::filesystem::path(path));
}

bool WriteUtf8FileAtomic(const std::wstring& path, const std::string& content) {
    std::filesystem::path finalPath(path);
    if (!EnsureDirectory(finalPath.parent_path().wstring())) {
        return false;
    }

    const std::wstring tempPath = path + L".tmp";
    {
        std::ofstream file(std::filesystem::path(tempPath), std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            return false;
        }
        file.write(content.data(), static_cast<std::streamsize>(content.size()));
        if (!file.good()) {
            return false;
        }
    }

    return MoveFileExW(tempPath.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}

bool ReadUtf8File(const std::wstring& path, std::string& outContent) {
    std::ifstream file(std::filesystem::path(path), std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    outContent.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    return true;
}

bool GetRemoteModuleBaseAddress(DWORD pid, const std::wstring& moduleName, uintptr_t& baseAddress) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return false;
    }
    do {
        if (_wcsicmp(entry.szModule, moduleName.c_str()) == 0 || _wcsicmp(entry.szExePath, moduleName.c_str()) == 0) {
            baseAddress = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
            CloseHandle(snapshot);
            return true;
        }
    } while (Module32NextW(snapshot, &entry));
    CloseHandle(snapshot);
    return false;
}

bool ResolveRemoteLoadLibraryAddress(DWORD pid, uintptr_t& remoteLoadLibrary) {
    HMODULE localKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!localKernel32) {
        AppendLog(L"GetModuleHandleW(kernel32.dll) failed.");
        return false;
    }

    FARPROC localLoadLibrary = GetProcAddress(localKernel32, "LoadLibraryW");
    if (!localLoadLibrary) {
        AppendLog(L"GetProcAddress(LoadLibraryW) failed.");
        return false;
    }

    uintptr_t remoteKernel32 = 0;
    if (!GetRemoteModuleBaseAddress(pid, L"kernel32.dll", remoteKernel32)) {
        AppendLog(L"Failed to locate kernel32.dll in target process.");
        return false;
    }

    const uintptr_t localKernel32Base = reinterpret_cast<uintptr_t>(localKernel32);
    const uintptr_t localLoadLibraryAddr = reinterpret_cast<uintptr_t>(localLoadLibrary);
    const uintptr_t loadLibraryOffset = localLoadLibraryAddr - localKernel32Base;
    remoteLoadLibrary = remoteKernel32 + loadLibraryOffset;
    return true;
}

bool ResolveRemoteExportAddress(DWORD pid, const std::wstring& dllPath, const char* exportName, uintptr_t& remoteExport) {
    uintptr_t remoteModuleBase = 0;
    if (!GetRemoteModuleBaseAddress(pid, GetFileNameFromPath(dllPath), remoteModuleBase)) {
        AppendLog(L"Failed to locate target DLL in remote process for export resolution.");
        return false;
    }

    HMODULE localModule = LoadLibraryExW(dllPath.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!localModule) {
        AppendLog(L"LoadLibraryExW(DONT_RESOLVE_DLL_REFERENCES) failed.");
        return false;
    }

    FARPROC localExport = GetProcAddress(localModule, exportName);
    if (!localExport) {
        FreeLibrary(localModule);
        AppendLog(L"Failed to resolve DLL startup export.");
        return false;
    }

    const uintptr_t localBase = reinterpret_cast<uintptr_t>(localModule);
    const uintptr_t localExportAddr = reinterpret_cast<uintptr_t>(localExport);
    const uintptr_t exportOffset = localExportAddr - localBase;
    remoteExport = remoteModuleBase + exportOffset;
    FreeLibrary(localModule);
    return true;
}

bool StartRemoteRuntime(DWORD pid, const std::wstring& dllPath) {
    uintptr_t remoteStart = 0;
    if (!ResolveRemoteExportAddress(pid, dllPath, "StartRuntimeThreadProc", remoteStart)) {
        return false;
    }

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS_FLAGS, FALSE, pid);
    if (!process) {
        AppendLog(L"OpenProcess for StartRuntimeThreadProc failed.");
        return false;
    }

    HANDLE thread = CreateRemoteLoadThread(process, reinterpret_cast<FARPROC>(remoteStart), nullptr);
    if (!thread) {
        AppendLog(L"CreateRemoteThread(StartRuntimeThreadProc) failed.");
        CloseHandle(process);
        return false;
    }

    if (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0) {
        AppendLog(L"WaitForSingleObject(StartRuntimeThreadProc) failed.");
        CloseHandle(thread);
        CloseHandle(process);
        return false;
    }

    DWORD exitCode = 0;
    if (!GetExitCodeThread(thread, &exitCode)) {
        AppendLog(L"GetExitCodeThread(StartRuntimeThreadProc) failed.");
        CloseHandle(thread);
        CloseHandle(process);
        return false;
    }

    CloseHandle(thread);
    CloseHandle(process);

    if (exitCode != 0) {
        AppendLog(L"StartRuntimeThreadProc returned non-zero exit code: " + std::to_wstring(exitCode));
        return false;
    }

    AppendLog(L"Remote runtime startup thread completed successfully.");
    return true;
}

bool WaitForRemoteModule(DWORD pid, const std::wstring& moduleName, DWORD timeoutMs, uintptr_t& baseAddress) {
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    do {
        if (GetRemoteModuleBaseAddress(pid, moduleName, baseAddress)) {
            return true;
        }
        Sleep(MODULE_VERIFY_RETRY_DELAY_MS);
    } while (GetTickCount64() < deadline);

    return false;
}

bool ValidateRemoteModuleMemory(HANDLE process, DWORD remoteResult) {
    if (remoteResult == 0) {
        return false;
    }

    IMAGE_DOS_HEADER dosHeader{};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(remoteResult)),
                           &dosHeader, sizeof(dosHeader), &bytesRead) ||
        bytesRead != sizeof(dosHeader)) {
        return false;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew <= 0) {
        return false;
    }

    DWORD ntSignature = 0;
    const uintptr_t ntAddr = static_cast<uintptr_t>(remoteResult) + static_cast<uintptr_t>(dosHeader.e_lfanew);
    bytesRead = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(ntAddr), &ntSignature, sizeof(ntSignature), &bytesRead) ||
        bytesRead != sizeof(ntSignature)) {
        return false;
    }

    return ntSignature == IMAGE_NT_SIGNATURE;
}

void RefreshScriptList() {
    SendMessageW(hScriptList, LB_RESETCONTENT, 0, 0);
    if (scriptEntries.empty()) {
        SendMessageW(hScriptList, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"No scripts loaded"));
        EnableWindow(hRemoveScriptButton, FALSE);
    } else {
        for (const auto& entry : scriptEntries) {
            SendMessageW(hScriptList, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(entry.name.c_str()));
        }
        EnableWindow(hRemoveScriptButton, TRUE);
    }
    UpdateExecuteButtonState();
}

void LoadSelectedScript() {
    int index = SendMessageW(hScriptList, LB_GETCURSEL, 0, 0);
    if (index == LB_ERR || index < 0 || index >= static_cast<int>(scriptEntries.size())) {
        return;
    }
    SetWindowTextW(hScriptEditor, scriptEntries[index].content.c_str());
}

void AddScriptFile(HWND hwnd) {
    wchar_t buffer[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = buffer;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    ofn.lpstrFilter = L"Lua Files\0*.lua\0All Files\0*.*\0";
    if (!GetOpenFileNameW(&ofn)) {
        return;
    }
    std::wstring path(buffer);
    std::wstring content;
    if (!ReadFileToString(path, content)) {
        AppendLog(L"Failed to read script file: " + path);
        return;
    }
    scriptEntries.push_back({GetFileNameFromPath(path), content});
    RefreshScriptList();
    AppendLog(L"Loaded script: " + GetFileNameFromPath(path));
}

void RemoveSelectedScript() {
    int index = SendMessageW(hScriptList, LB_GETCURSEL, 0, 0);
    if (index == LB_ERR || index < 0 || index >= static_cast<int>(scriptEntries.size())) {
        return;
    }
    std::wstring name = scriptEntries[index].name;
    scriptEntries.erase(scriptEntries.begin() + index);
    RefreshScriptList();
    AppendLog(L"Removed script: " + name);
}

void BrowseDllPath(HWND hwnd) {
    wchar_t buffer[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = buffer;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    ofn.lpstrFilter = L"DLL Files\0*.dll\0All Files\0*.*\0";
    if (GetOpenFileNameW(&ofn)) {
        SetWindowTextW(hDllPathEdit, buffer);
    }
}

void OpenRuntimeLog() {
    if (gRuntimeLogPath.empty()) {
        AppendLog(L"Runtime log path is not available yet.");
        return;
    }
    HINSTANCE result = ShellExecuteW(nullptr, L"open", gRuntimeLogPath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(result) <= 32) {
        AppendLog(L"Failed to open runtime log: " + gRuntimeLogPath);
    }
}

void PrintError(const std::wstring& prefix) {
    DWORD code = GetLastError();
    LPWSTR msgBuffer = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&msgBuffer), 0, nullptr);
    std::wstring message = prefix + L" (error=" + std::to_wstring(code) + L")";
    if (msgBuffer) {
        message += L": ";
        message += msgBuffer;
        LocalFree(msgBuffer);
    }
    AppendLog(message);
}

bool EnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        PrintError(L"OpenProcessToken failed");
        return false;
    }
    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
        PrintError(L"LookupPrivilegeValue failed");
        CloseHandle(token);
        return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        PrintError(L"AdjustTokenPrivileges failed");
        CloseHandle(token);
        return false;
    }
    CloseHandle(token);
    return GetLastError() == ERROR_SUCCESS;
}

DWORD FindProcessIdByName(const std::wstring& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        PrintError(L"CreateToolhelp32Snapshot failed");
        return 0;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) {
        PrintError(L"Process32FirstW failed");
        CloseHandle(snapshot);
        return 0;
    }
    do {
        if (_wcsicmp(entry.szExeFile, processName.c_str()) == 0) {
            CloseHandle(snapshot);
            return entry.th32ProcessID;
        }
    } while (Process32NextW(snapshot, &entry));
    CloseHandle(snapshot);
    return 0;
}

bool InjectDll(DWORD pid, const std::wstring& dllPath) {
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS_FLAGS, FALSE, pid);
    if (!process) {
        PrintError(L"OpenProcess failed");
        return false;
    }

    const SIZE_T dllPathBytes = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remoteAddress = VirtualAllocEx(process, nullptr, dllPathBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteAddress) {
        CloseHandle(process);
        PrintError(L"VirtualAllocEx failed");
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remoteAddress, dllPath.c_str(), dllPathBytes, &written) || written != dllPathBytes) {
        PrintError(L"WriteProcessMemory failed");
        VirtualFreeEx(process, remoteAddress, 0, MEM_RELEASE);
        CloseHandle(process);
        return false;
    }

    uintptr_t remoteLoadLibrary = 0;
    if (!ResolveRemoteLoadLibraryAddress(pid, remoteLoadLibrary)) {
        VirtualFreeEx(process, remoteAddress, 0, MEM_RELEASE);
        CloseHandle(process);
        return false;
    }

    HANDLE thread = CreateRemoteLoadThread(process, reinterpret_cast<FARPROC>(remoteLoadLibrary), remoteAddress);
    if (!thread) {
        PrintError(L"CreateRemoteThread failed");
        VirtualFreeEx(process, remoteAddress, 0, MEM_RELEASE);
        CloseHandle(process);
        return false;
    }

    if (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0) {
        PrintError(L"WaitForSingleObject failed");
        CloseHandle(thread);
        VirtualFreeEx(process, remoteAddress, 0, MEM_RELEASE);
        CloseHandle(process);
        return false;
    }

    DWORD exitCode = 0;
    if (!GetExitCodeThread(thread, &exitCode)) {
        PrintError(L"GetExitCodeThread failed");
        CloseHandle(thread);
        VirtualFreeEx(process, remoteAddress, 0, MEM_RELEASE);
        CloseHandle(process);
        return false;
    }

    const bool remoteMemoryValid = ValidateRemoteModuleMemory(process, exitCode);

    CloseHandle(thread);
    VirtualFreeEx(process, remoteAddress, 0, MEM_RELEASE);

    if (exitCode == 0) {
        CloseHandle(process);
        AppendLog(L"Remote LoadLibraryW returned NULL; DLL was not loaded.");
        return false;
    }

    uintptr_t baseAddress = 0;
    if (!WaitForRemoteModule(pid, GetFileNameFromPath(dllPath), MODULE_VERIFY_TIMEOUT_MS, baseAddress)) {
        AppendLog(L"Post-injection verification did not confirm the DLL after " + std::to_wstring(MODULE_VERIFY_TIMEOUT_MS) +
                  L" ms. LoadLibraryW returned non-zero, but the module was not observable via Toolhelp snapshot.");
        if (remoteMemoryValid) {
            wchar_t fallbackBuffer[120] = {};
            swprintf_s(fallbackBuffer,
                       L"Returned HMODULE points to a valid PE image at 0x%p.",
                       reinterpret_cast<void*>(static_cast<uintptr_t>(exitCode)));
            AppendLog(fallbackBuffer);
        } else {
            AppendLog(L"Returned HMODULE memory is not a valid PE image. The target may have unloaded the DLL immediately, hidden it from enumeration, or blocked full initialization.");
        }
        AppendLog(L"Proceeding with runtime-ready validation; module snapshot is not treated as authoritative for this target.");
        CloseHandle(process);
        StartRemoteRuntime(pid, dllPath);
        return true;
    }

    wchar_t moduleBuffer[80] = {};
    swprintf_s(moduleBuffer, L"Verified remote module base: 0x%p", reinterpret_cast<void*>(baseAddress));
    AppendLog(moduleBuffer);

    CloseHandle(process);

    StartRemoteRuntime(pid, dllPath);
    return true;
}

bool WaitForRuntimeReady(DWORD pid, DWORD timeoutMs, std::wstring& message) {
    const std::wstring readyPath = GetReadyFilePath(pid);
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    while (GetTickCount64() < deadline) {
        std::string json;
        if (ReadUtf8File(readyPath, json)) {
            std::wstring status = ExtractJsonStringField(json, "status");
            message = ExtractJsonStringField(json, "message");
            gRuntimeLogPath = ExtractJsonStringField(json, "log_path");
            if (hRuntimeLogPathEdit) {
                SetWindowTextW(hRuntimeLogPathEdit, gRuntimeLogPath.c_str());
            }
            if (status == L"runtime_ready") {
                return true;
            }
        }
        Sleep(150);
    }
    message = L"Timed out waiting for runtime ready signal.";
    return false;
}

std::string EscapeJsonString(const std::string& value) {
    std::string escaped;
    for (char c : value) {
        switch (c) {
        case '"': escaped += "\\\""; break;
        case '\\': escaped += "\\\\"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default: escaped.push_back(c); break;
        }
    }
    return escaped;
}

std::wstring GenerateCommandId() {
    FILETIME fileTime{};
    GetSystemTimeAsFileTime(&fileTime);
    const unsigned long long timestamp =
        (static_cast<unsigned long long>(fileTime.dwHighDateTime) << 32) | fileTime.dwLowDateTime;
    ++gCommandCounter;
    return std::to_wstring(GetCurrentProcessId()) + L"_" +
           std::to_wstring(gInjectedPid) + L"_" +
           std::to_wstring(timestamp) + L"_" +
           std::to_wstring(gCommandCounter);
}

bool WaitForAckStatus(DWORD pid, const std::wstring& commandId, DWORD timeoutMs, const std::wstring& expectedStatus, std::wstring& message) {
    const std::wstring ackPath = GetAckFilePath(pid, commandId);
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    while (GetTickCount64() < deadline) {
        std::string json;
        if (ReadUtf8File(ackPath, json)) {
            std::wstring status = ExtractJsonStringField(json, "status");
            message = ExtractJsonStringField(json, "message");
            if (status == expectedStatus) {
                return true;
            }
            if (status == L"failed" || status == L"rejected") {
                return false;
            }
        }
        Sleep(100);
    }
    message = L"Timed out waiting for " + expectedStatus + L".";
    return false;
}

void SendScriptToDll(const std::wstring& script) {
    if (gInjectionStage != InjectionStage::RuntimeReady || gInjectedPid == 0 || gInjectedDllPath.empty()) {
        AppendLog(L"Runtime is not ready yet. Inject and wait for confirmation first.");
        return;
    }

    const std::wstring commandId = GenerateCommandId();
    const std::wstring commandPath = GetCommandDir(gInjectedPid) + L"\\" + commandId + L".json";
    const std::wstring ackPath = GetAckFilePath(gInjectedPid, commandId);
    const std::string payload =
        "{\"id\":\"" + WideToUtf8(commandId) + "\",\"type\":\"execute\",\"script\":\"" +
        EscapeJsonString(WideToUtf8(script)) + "\"}";

    DeleteFileW(ackPath.c_str());

    if (!WriteUtf8FileAtomic(commandPath, payload)) {
        AppendLog(L"Failed to write command file atomically.");
        return;
    }

    AppendLog(L"Command queued with id " + commandId + L". Waiting for DLL acknowledgement...");
    std::wstring message;
    if (!WaitForAckStatus(gInjectedPid, commandId, 3000, L"accepted", message)) {
        AppendLog(L"Command was not accepted: " + message);
        return;
    }
    AppendLog(L"Command accepted by DLL.");

    if (!WaitForAckStatus(gInjectedPid, commandId, 10000, L"executed", message)) {
        AppendLog(L"Script execution not confirmed: " + message);
        if (!gRuntimeLogPath.empty()) {
            AppendLog(L"DLL runtime log: " + gRuntimeLogPath);
        }
        return;
    }
    AppendLog(L"Script executed successfully.");
}

void CreateUiFonts() {
    hTitleFont = CreateFontW(28, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                             OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             VARIABLE_PITCH, L"Segoe UI Semibold");
    hSectionFont = CreateFontW(18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                               OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                               VARIABLE_PITCH, L"Segoe UI Semibold");
    hBodyFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                            OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                            VARIABLE_PITCH, L"Segoe UI");
    hMonoFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                            OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                            FIXED_PITCH, L"Consolas");
}

void ApplyFonts() {
    SetControlFont(hScriptList, hBodyFont);
    SetControlFont(hScriptEditor, hMonoFont);
    SetControlFont(hDllPathEdit, hBodyFont);
    SetControlFont(hProcessNameEdit, hBodyFont);
    SetControlFont(hPidEdit, hBodyFont);
    SetControlFont(hLogEdit, hMonoFont);
    SetControlFont(hRuntimeLogPathEdit, hBodyFont);
    SetControlFont(hAddScriptButton, hBodyFont);
    SetControlFont(hRemoveScriptButton, hBodyFont);
    SetControlFont(hExecuteScriptButton, hBodyFont);
    SetControlFont(hInjectButton, hBodyFont);
    SetControlFont(hBrowseDllButton, hBodyFont);
    SetControlFont(hOpenRuntimeLogButton, hBodyFont);
    SetControlFont(hEnableDebugCheckbox, hBodyFont);
    SetControlFont(hStatusStatic, hTitleFont);
    SetControlFont(hSubStatusStatic, hBodyFont);
    SetControlFont(hStageStatic, hBodyFont);
    SetControlFont(hRuntimeCardStatic, hBodyFont);
    SetControlFont(hModuleCardStatic, hBodyFont);
}

void PaintSectionFrame(HDC hdc, const RECT& rect, COLORREF fill, COLORREF border) {
    HBRUSH fillBrush = CreateSolidBrush(fill);
    FillRect(hdc, &rect, fillBrush);
    DeleteObject(fillBrush);
    HPEN pen = CreatePen(PS_SOLID, 1, border);
    HGDIOBJ oldPen = SelectObject(hdc, pen);
    HGDIOBJ oldBrush = SelectObject(hdc, GetStockObject(HOLLOW_BRUSH));
    Rectangle(hdc, rect.left, rect.top, rect.right, rect.bottom);
    SelectObject(hdc, oldBrush);
    SelectObject(hdc, oldPen);
    DeleteObject(pen);
}

void DrawTextBlock(HDC hdc, const RECT& rect, const std::wstring& text, HFONT font, COLORREF color, UINT format) {
    HFONT oldFont = reinterpret_cast<HFONT>(SelectObject(hdc, font));
    SetTextColor(hdc, color);
    SetBkMode(hdc, TRANSPARENT);
    RECT copy = rect;
    DrawTextW(hdc, text.c_str(), -1, &copy, format);
    SelectObject(hdc, oldFont);
}

void PaintDashboard(HWND hwnd, HDC hdc) {
    RECT client{};
    GetClientRect(hwnd, &client);
    FillRect(hdc, &client, hBackgroundBrush);

    RECT header{24, 20, client.right - 24, 122};
    PaintSectionFrame(hdc, header, RGB(21, 22, 29), RGB(34, 36, 46));

    RECT titleRect{44, 34, 500, 70};
    RECT subtitleRect{44, 72, 760, 100};
    DrawTextBlock(hdc, titleRect, L"Luna Workspace", hTitleFont, RGB(242, 243, 247), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    DrawTextBlock(hdc, subtitleRect, L"Confirmed injection states, runtime handshake, and real DLL execution logs.", hBodyFont,
                  RGB(138, 143, 161), DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    RECT stageChip{client.right - 268, 38, client.right - 44, 92};
    PaintSectionFrame(hdc, stageChip, RGB(16, 24, 28), RGB(48, 88, 96));
    RECT chipLabel{stageChip.left + 18, stageChip.top + 10, stageChip.right - 18, stageChip.top + 30};
    RECT chipValue{stageChip.left + 18, stageChip.top + 28, stageChip.right - 18, stageChip.bottom - 12};
    DrawTextBlock(hdc, chipLabel, L"CURRENT STAGE", hBodyFont, RGB(100, 215, 234), DT_LEFT | DT_SINGLELINE);
    DrawTextBlock(hdc, chipValue, StageName(gInjectionStage), hSectionFont, StageColor(gInjectionStage), DT_LEFT | DT_SINGLELINE);

    RECT leftPanel{24, 144, 338, 648};
    RECT editorPanel{356, 144, client.right - 24, 648};
    RECT controlPanel{356, 666, client.right - 24, 880};
    RECT logPanel{24, 666, 338, 880};

    PaintSectionFrame(hdc, leftPanel, RGB(21, 22, 29), RGB(34, 36, 46));
    PaintSectionFrame(hdc, editorPanel, RGB(21, 22, 29), RGB(34, 36, 46));
    PaintSectionFrame(hdc, controlPanel, RGB(21, 22, 29), RGB(34, 36, 46));
    PaintSectionFrame(hdc, logPanel, RGB(21, 22, 29), RGB(34, 36, 46));

    DrawTextBlock(hdc, RECT{44, 160, 320, 188}, L"Script Library", hSectionFont, RGB(242, 243, 247), DT_LEFT | DT_SINGLELINE);
    DrawTextBlock(hdc, RECT{44, 188, 320, 212}, L"Loaded Lua sources ready for execution.", hBodyFont, RGB(138, 143, 161), DT_LEFT | DT_SINGLELINE);

    DrawTextBlock(hdc, RECT{376, 160, 700, 188}, L"Script Editor", hSectionFont, RGB(242, 243, 247), DT_LEFT | DT_SINGLELINE);
    DrawTextBlock(hdc, RECT{376, 188, 760, 212}, L"Prepare the script payload before queueing it into the confirmed DLL runtime.", hBodyFont,
                  RGB(138, 143, 161), DT_LEFT | DT_SINGLELINE);

    DrawTextBlock(hdc, RECT{376, 682, 760, 710}, L"Injection Control", hSectionFont, RGB(242, 243, 247), DT_LEFT | DT_SINGLELINE);
    DrawTextBlock(hdc, RECT{376, 710, 980, 734}, L"Attach the module, verify runtime readiness, and inspect the runtime log path.", hBodyFont,
                  RGB(138, 143, 161), DT_LEFT | DT_SINGLELINE);

    DrawTextBlock(hdc, RECT{44, 682, 320, 710}, L"Activity Log", hSectionFont, RGB(242, 243, 247), DT_LEFT | DT_SINGLELINE);
    DrawTextBlock(hdc, RECT{44, 710, 320, 734}, L"Only confirmed local injector events are shown here.", hBodyFont, RGB(138, 143, 161),
                  DT_LEFT | DT_SINGLELINE);
}

void CreateStaticLabel(HWND parent, const wchar_t* text, int x, int y, int w, int h, HFONT font) {
    HWND hwnd = CreateWindowW(L"STATIC", text, WS_VISIBLE | WS_CHILD, x, y, w, h, parent, nullptr, nullptr, nullptr);
    SetControlFont(hwnd, font);
}

void CreateControls(HWND hwnd) {
    hStatusStatic = CreateWindowW(L"STATIC", L"Ready", WS_VISIBLE | WS_CHILD, 44, 34, 420, 34, hwnd, nullptr, nullptr, nullptr);
    hSubStatusStatic = CreateWindowW(L"STATIC", L"Inject the DLL to start the runtime handshake.", WS_VISIBLE | WS_CHILD, 44, 72, 680, 24, hwnd, nullptr, nullptr, nullptr);
    hStageStatic = CreateWindowW(L"STATIC", L"Stage: Idle", WS_VISIBLE | WS_CHILD, 376, 748, 240, 24, hwnd, nullptr, nullptr, nullptr);
    hRuntimeCardStatic = CreateWindowW(L"STATIC", L"Runtime log unavailable", WS_VISIBLE | WS_CHILD, 376, 776, 240, 24, hwnd, nullptr, nullptr, nullptr);
    hModuleCardStatic = CreateWindowW(L"STATIC", L"No target attached", WS_VISIBLE | WS_CHILD, 640, 776, 240, 24, hwnd, nullptr, nullptr, nullptr);

    hScriptList = CreateWindowW(L"LISTBOX", nullptr,
                                WS_VISIBLE | WS_CHILD | WS_BORDER | LBS_NOTIFY | WS_VSCROLL,
                                44, 222, 274, 330, hwnd, reinterpret_cast<HMENU>(IDC_SCRIPT_LIST), nullptr, nullptr);
    hAddScriptButton = CreateWindowW(L"BUTTON", L"Load Script", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                     44, 572, 128, 34, hwnd, reinterpret_cast<HMENU>(IDC_ADD_SCRIPT), nullptr, nullptr);
    hRemoveScriptButton = CreateWindowW(L"BUTTON", L"Remove", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                        190, 572, 128, 34, hwnd, reinterpret_cast<HMENU>(IDC_REMOVE_SCRIPT), nullptr, nullptr);

    hScriptEditor = CreateWindowW(L"EDIT", L"",
                                  WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL,
                                  376, 222, 836, 370, hwnd, reinterpret_cast<HMENU>(IDC_SCRIPT_EDITOR), nullptr, nullptr);

    hExecuteScriptButton = CreateWindowW(L"BUTTON", L"Execute Script", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                         376, 608, 180, 38, hwnd, reinterpret_cast<HMENU>(IDC_EXECUTE_SCRIPT), nullptr, nullptr);
    hInjectButton = CreateWindowW(L"BUTTON", L"Inject DLL", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                  576, 608, 180, 38, hwnd, reinterpret_cast<HMENU>(IDC_INJECT_DLL), nullptr, nullptr);
    hBrowseDllButton = CreateWindowW(L"BUTTON", L"Browse DLL", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                     776, 608, 140, 38, hwnd, reinterpret_cast<HMENU>(IDC_BROWSE_DLL), nullptr, nullptr);
    hEnableDebugCheckbox = CreateWindowW(L"BUTTON", L"Enable SeDebugPrivilege", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
                                         936, 614, 250, 30, hwnd, reinterpret_cast<HMENU>(IDC_ENABLE_DEBUG), nullptr, nullptr);

    CreateStaticLabel(hwnd, L"DLL Path", 376, 808, 120, 22, hBodyFont);
    hDllPathEdit = CreateWindowW(L"EDIT", L"D:\\roblox\\analysis\\injector_project\\bin\\luna_extracted_native.dll",
                                 WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                                 376, 832, 836, 28, hwnd, nullptr, nullptr, nullptr);

    CreateStaticLabel(hwnd, L"Process", 376, 872, 120, 22, hBodyFont);
    hProcessNameEdit = CreateWindowW(L"EDIT", L"RobloxPlayerBeta.exe",
                                     WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                                     376, 896, 290, 28, hwnd, nullptr, nullptr, nullptr);

    CreateStaticLabel(hwnd, L"PID", 694, 872, 60, 22, hBodyFont);
    hPidEdit = CreateWindowW(L"EDIT", L"",
                             WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                             694, 896, 180, 28, hwnd, nullptr, nullptr, nullptr);

    CreateStaticLabel(hwnd, L"Runtime Log", 902, 872, 140, 22, hBodyFont);
    hRuntimeLogPathEdit = CreateWindowW(L"EDIT", L"",
                                        WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL | ES_READONLY,
                                        902, 896, 220, 28, hwnd, nullptr, nullptr, nullptr);
    hOpenRuntimeLogButton = CreateWindowW(L"BUTTON", L"Open Log", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                          1136, 894, 76, 32, hwnd, reinterpret_cast<HMENU>(IDC_OPEN_RUNTIME_LOG), nullptr, nullptr);

    hLogEdit = CreateWindowW(L"EDIT", L"",
                             WS_VISIBLE | WS_CHILD | WS_BORDER | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                             44, 742, 274, 182, hwnd, nullptr, nullptr, nullptr);

    ApplyFonts();
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
        CreateUiFonts();
        CreateControls(hwnd);
        RefreshScriptList();
        SetInjectionState(InjectionStage::Idle);
        return 0;

    case WM_COMMAND: {
        WORD id = LOWORD(wParam);
        if (id == IDC_SCRIPT_LIST && HIWORD(wParam) == LBN_SELCHANGE) {
            LoadSelectedScript();
            return 0;
        }
        if (id == IDC_SCRIPT_EDITOR && HIWORD(wParam) == EN_CHANGE) {
            UpdateExecuteButtonState();
            return 0;
        }

        switch (id) {
        case IDC_ADD_SCRIPT:
            AddScriptFile(hwnd);
            break;
        case IDC_REMOVE_SCRIPT:
            RemoveSelectedScript();
            break;
        case IDC_EXECUTE_SCRIPT: {
            std::wstring script = GetWindowTextString(hScriptEditor);
            if (script.empty()) {
                AppendLog(L"Editor is empty. Load or write a script first.");
                break;
            }
            SendScriptToDll(script);
            break;
        }
        case IDC_INJECT_DLL: {
            SetInjectionState(InjectionStage::Idle);

            std::wstring dllPath = GetWindowTextString(hDllPathEdit);
            if (dllPath.empty()) {
                AppendLog(L"DLL path is required.");
                break;
            }
            auto normalizedDllPath = NormalizeFullPath(dllPath);
            if (!normalizedDllPath) {
                AppendLog(L"Failed to normalize DLL path.");
                break;
            }
            dllPath = *normalizedDllPath;

            DWORD attributes = GetFileAttributesW(dllPath.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                AppendLog(L"DLL path is invalid: " + dllPath);
                break;
            }

            DWORD pid = 0;
            std::wstring pidText = GetWindowTextString(hPidEdit);
            if (!pidText.empty()) {
                pid = static_cast<DWORD>(_wtoi(pidText.c_str()));
                if (pid == 0) {
                    AppendLog(L"Invalid PID.");
                    break;
                }
            } else {
                std::wstring processName = GetWindowTextString(hProcessNameEdit);
                if (processName.empty()) {
                    AppendLog(L"Process name is required.");
                    break;
                }
                AppendLog(L"Searching process by name: " + processName);
                pid = FindProcessIdByName(processName);
                if (pid == 0) {
                    AppendLog(L"Process not found.");
                    break;
                }
            }

            ClearRuntimeArtifacts(pid);
            if (SendMessageW(hEnableDebugCheckbox, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                AppendLog(L"Enabling SeDebugPrivilege...");
                if (!EnableDebugPrivilege()) {
                    AppendLog(L"Failed to enable debug privilege.");
                } else {
                    AppendLog(L"SeDebugPrivilege enabled.");
                }
            }

            AppendLog(L"Injecting DLL into PID " + std::to_wstring(pid) + L"...");
            if (!InjectDll(pid, dllPath)) {
                AppendLog(L"Injection failed.");
                break;
            }

            SetInjectionState(InjectionStage::ModuleLoaded, pid, dllPath);
            AppendLog(L"LoadLibrary stage completed; waiting for runtime ready signal.");

            std::wstring readyMessage;
            if (!WaitForRuntimeReady(pid, 15000, readyMessage)) {
                AppendLog(L"Runtime ready signal was not confirmed: " + readyMessage);
                break;
            }

            SetInjectionState(InjectionStage::RuntimeReady, pid, dllPath);
            AppendLog(L"Runtime ready signal confirmed.");
            if (!gRuntimeLogPath.empty()) {
                AppendLog(L"DLL runtime log: " + gRuntimeLogPath);
            }
            break;
        }
        case IDC_BROWSE_DLL:
            BrowseDllPath(hwnd);
            break;
        case IDC_OPEN_RUNTIME_LOG:
            OpenRuntimeLog();
            break;
        }
        return 0;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = reinterpret_cast<HDC>(wParam);
        HWND ctl = reinterpret_cast<HWND>(lParam);
        SetBkMode(hdc, TRANSPARENT);
        if (ctl == hStatusStatic) {
            SetTextColor(hdc, RGB(242, 243, 247));
        } else if (ctl == hSubStatusStatic) {
            SetTextColor(hdc, RGB(138, 143, 161));
        } else if (ctl == hStageStatic) {
            SetTextColor(hdc, StageColor(gInjectionStage));
        } else if (ctl == hRuntimeCardStatic) {
            SetTextColor(hdc, gRuntimeLogPath.empty() ? RGB(240, 198, 116) : RGB(154, 208, 143));
        } else if (ctl == hModuleCardStatic) {
            SetTextColor(hdc, gInjectedPid == 0 ? RGB(137, 143, 161) : RGB(100, 215, 234));
        } else {
            SetTextColor(hdc, RGB(220, 220, 220));
        }
        return reinterpret_cast<LRESULT>(hBackgroundBrush);
    }

    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        HDC hdc = reinterpret_cast<HDC>(wParam);
        HWND ctl = reinterpret_cast<HWND>(lParam);
        SetTextColor(hdc, RGB(240, 240, 240));
        if (ctl == hScriptEditor || ctl == hLogEdit) {
            SetBkColor(hdc, RGB(16, 17, 24));
        } else {
            SetBkColor(hdc, RGB(24, 25, 34));
        }
        return reinterpret_cast<LRESULT>(hPanelBrush);
    }

    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC hdc = BeginPaint(hwnd, &ps);
        PaintDashboard(hwnd, hdc);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DESTROY:
        if (hTitleFont) DeleteObject(hTitleFont);
        if (hSectionFont) DeleteObject(hSectionFont);
        if (hBodyFont) DeleteObject(hBodyFont);
        if (hMonoFont) DeleteObject(hMonoFont);
        if (hBackgroundBrush) DeleteObject(hBackgroundBrush);
        if (hPanelBrush) DeleteObject(hPanelBrush);
        if (hPanelSoftBrush) DeleteObject(hPanelSoftBrush);
        if (hAccentBrush) DeleteObject(hAccentBrush);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    const wchar_t CLASS_NAME[] = L"LunaInjectorWindowClass";
    hBackgroundBrush = CreateSolidBrush(RGB(12, 13, 18));
    hPanelBrush = CreateSolidBrush(RGB(24, 25, 34));
    hPanelSoftBrush = CreateSolidBrush(RGB(21, 22, 29));
    hAccentBrush = CreateSolidBrush(RGB(100, 215, 234));

    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = hBackgroundBrush;

    if (!RegisterClassW(&wc)) {
        return 0;
    }

    HWND hwnd = CreateWindowExW(
        0,
        CLASS_NAME,
        L"Luna Injector",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 1260, 980,
        nullptr,
        nullptr,
        hInstance,
        nullptr);

    if (!hwnd) {
        return 0;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}
