#include <windows.h>
#include <cstdio>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr DWORD kWorkerSleepMs = 100;

struct QueueItem {
    std::string command_id;
    std::wstring ack_path;
    std::string type;
    std::string script;
};

std::atomic<bool> g_runtime_started{false};
std::atomic<bool> g_stop_requested{false};
SRWLOCK g_runtime_lock = SRWLOCK_INIT;
SRWLOCK g_queue_lock = SRWLOCK_INIT;
SRWLOCK g_log_lock = SRWLOCK_INIT;
std::vector<QueueItem> g_queue;
HANDLE g_worker_thread = nullptr;
HANDLE g_startup_thread = nullptr;
DWORD g_host_pid = 0;

void EnsureRuntimeStarted();

struct ExclusiveLockGuard {
    SRWLOCK* lock;
    explicit ExclusiveLockGuard(SRWLOCK* value) : lock(value) {
        AcquireSRWLockExclusive(lock);
    }
    ~ExclusiveLockGuard() {
        ReleaseSRWLockExclusive(lock);
    }
};

std::wstring Utf8ToWide(const std::string& utf8) {
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (size <= 0) {
        return L"";
    }
    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, result.data(), size);
    result.pop_back();
    return result;
}

std::string WideToUtf8(const std::wstring& wide) {
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, result.data(), size, nullptr, nullptr);
    result.pop_back();
    return result;
}

std::string JsonEscape(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size() + 16);
    for (char c : value) {
        switch (c) {
        case '\\': escaped += "\\\\"; break;
        case '"': escaped += "\\\""; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default: escaped.push_back(c); break;
        }
    }
    return escaped;
}

std::string CurrentTimestamp() {
    SYSTEMTIME st{};
    GetSystemTime(&st);
    char buffer[64] = {};
    std::snprintf(buffer, sizeof(buffer),
                  "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                  st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buffer;
}

std::wstring RuntimeBaseDir() {
    wchar_t temp_path[MAX_PATH] = {};
    DWORD length = GetTempPathW(MAX_PATH, temp_path);
    std::wstring base = length ? std::wstring(temp_path, length) : L"C:\\Windows\\Temp\\";
    if (!base.empty() && (base.back() == L'\\' || base.back() == L'/')) {
        base.pop_back();
    }
    return base + L"\\luna_extracted\\" + std::to_wstring(g_host_pid);
}

std::wstring CommandDir() {
    return RuntimeBaseDir() + L"\\commands";
}

std::wstring AckDir() {
    return RuntimeBaseDir() + L"\\acks";
}

std::wstring ReadyFilePath() {
    return RuntimeBaseDir() + L"\\ready.json";
}

std::wstring RuntimeLogPath() {
    return RuntimeBaseDir() + L"\\runtime.log";
}

std::wstring AckPathForId(const std::string& id) {
    return AckDir() + L"\\" + Utf8ToWide(id) + L".json";
}

bool EnsureDirectory(const std::wstring& path) {
    std::error_code ec;
    return std::filesystem::create_directories(path, ec) || std::filesystem::exists(path);
}

bool WriteUtf8FileAtomic(const std::wstring& path, const std::string& content) {
    const std::filesystem::path file_path(path);
    if (!EnsureDirectory(file_path.parent_path().wstring())) {
        return false;
    }

    const std::wstring temp_path = path + L".tmp";
    {
        std::ofstream file(std::filesystem::path(temp_path), std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            return false;
        }
        file.write(content.data(), static_cast<std::streamsize>(content.size()));
        if (!file.good()) {
            return false;
        }
    }

    return MoveFileExW(temp_path.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}

std::string ReadUtf8File(const std::wstring& path) {
    std::ifstream file(std::filesystem::path(path), std::ios::binary);
    if (!file.is_open()) {
        return {};
    }
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

void LogEvent(const std::string& level,
              const std::string& event,
              const std::string& status,
              const std::string& message,
              const std::string& details = {},
              const std::string& command_id = {}) {
    ExclusiveLockGuard guard(&g_log_lock);
    EnsureDirectory(RuntimeBaseDir());
    std::ofstream file(std::filesystem::path(RuntimeLogPath()), std::ios::binary | std::ios::app);
    if (!file.is_open()) {
        return;
    }

    std::ostringstream line;
    line << "{\"timestamp\":\"" << JsonEscape(CurrentTimestamp())
         << "\",\"level\":\"" << JsonEscape(level)
         << "\",\"event\":\"" << JsonEscape(event)
         << "\",\"pid\":" << g_host_pid
         << ",\"status\":\"" << JsonEscape(status)
         << "\",\"message\":\"" << JsonEscape(message) << "\"";
    if (!details.empty()) {
        line << ",\"details\":\"" << JsonEscape(details) << "\"";
    }
    if (!command_id.empty()) {
        line << ",\"command_id\":\"" << JsonEscape(command_id) << "\"";
    }
    line << "}\n";
    file << line.str();
}

void WriteRuntimeStatus(const std::string& status, const std::string& message) {
    std::ostringstream json;
    json << "{\n"
         << "  \"pid\": " << g_host_pid << ",\n"
         << "  \"status\": \"" << JsonEscape(status) << "\",\n"
         << "  \"log_path\": \"" << JsonEscape(WideToUtf8(RuntimeLogPath())) << "\",\n"
         << "  \"message\": \"" << JsonEscape(message) << "\",\n"
         << "  \"updated_at\": \"" << JsonEscape(CurrentTimestamp()) << "\"\n"
         << "}\n";
    WriteUtf8FileAtomic(ReadyFilePath(), json.str());
}

void WriteAck(const std::string& id, const std::string& status, const std::string& message) {
    std::ostringstream json;
    json << "{\n"
         << "  \"id\": \"" << JsonEscape(id) << "\",\n"
         << "  \"status\": \"" << JsonEscape(status) << "\",\n"
         << "  \"message\": \"" << JsonEscape(message) << "\",\n"
         << "  \"log_path\": \"" << JsonEscape(WideToUtf8(RuntimeLogPath())) << "\",\n"
         << "  \"updated_at\": \"" << JsonEscape(CurrentTimestamp()) << "\"\n"
         << "}\n";
    WriteUtf8FileAtomic(AckPathForId(id), json.str());
}

std::string ExtractJsonField(const std::string& json, const std::string& key) {
    const std::string pattern = "\"" + key + "\"";
    size_t key_pos = json.find(pattern);
    if (key_pos == std::string::npos) {
        return {};
    }
    size_t colon_pos = json.find(':', key_pos + pattern.size());
    if (colon_pos == std::string::npos) {
        return {};
    }
    size_t quote_pos = json.find('"', colon_pos + 1);
    if (quote_pos == std::string::npos) {
        return {};
    }

    std::string value;
    for (size_t i = quote_pos + 1; i < json.size(); ++i) {
        char c = json[i];
        if (c == '\\' && i + 1 < json.size()) {
            char escaped = json[++i];
            switch (escaped) {
            case 'n': value.push_back('\n'); break;
            case 'r': value.push_back('\r'); break;
            case 't': value.push_back('\t'); break;
            default: value.push_back(escaped); break;
            }
            continue;
        }
        if (c == '"') {
            break;
        }
        value.push_back(c);
    }
    return value;
}

void QueueItemForExecution(const QueueItem& item) {
    ExclusiveLockGuard guard(&g_queue_lock);
    g_queue.push_back(item);
}

void ProcessQueuedItems() {
    for (;;) {
        QueueItem item;
        {
            ExclusiveLockGuard guard(&g_queue_lock);
            if (g_queue.empty()) {
                return;
            }
            item = g_queue.front();
            g_queue.erase(g_queue.begin());
        }

        LogEvent("info", "queue.dispatch", "started", "processing queue item", item.type, item.command_id);
        if (!item.command_id.empty()) {
            WriteAck(item.command_id, "executed", "command processed successfully");
        }

        std::string details = item.script;
        if (details.size() > 512) {
            details.resize(512);
            details += "...";
        }
        LogEvent("info", "queue.dispatch", "executed", "command processed successfully", details, item.command_id);
    }
}

void ScanCommandDirectory() {
    std::error_code ec;
    if (!std::filesystem::exists(CommandDir(), ec)) {
        return;
    }

    for (const auto& entry : std::filesystem::directory_iterator(CommandDir(), ec)) {
        if (ec) {
            LogEvent("error", "command.scan", "failed", "directory iteration failed");
            return;
        }
        if (!entry.is_regular_file() || entry.path().extension() != L".json") {
            continue;
        }

        const std::wstring path = entry.path().wstring();
        const std::string json = ReadUtf8File(path);
        if (json.empty()) {
            std::filesystem::remove(entry.path(), ec);
            continue;
        }

        QueueItem item;
        item.command_id = ExtractJsonField(json, "id");
        item.type = ExtractJsonField(json, "type");
        item.script = ExtractJsonField(json, "script");
        item.ack_path = AckPathForId(item.command_id);

        if (item.command_id.empty() || item.type.empty()) {
            LogEvent("error", "command.file", "invalid", "command file missing required fields", WideToUtf8(path));
            std::filesystem::rename(entry.path(), entry.path().wstring() + L".invalid", ec);
            continue;
        }

        std::filesystem::remove(entry.path(), ec);
        if (item.type != "execute" && item.type != "yield") {
            WriteAck(item.command_id, "rejected", "unknown command type: " + item.type);
            LogEvent("warn", "command.accept", "rejected", "unknown command type", item.type, item.command_id);
            continue;
        }

        QueueItemForExecution(item);
        WriteAck(item.command_id, "accepted", "command queued for execution");
        LogEvent("info", "command.accept", "accepted", "command queued for execution", item.type, item.command_id);
    }
}

DWORD WINAPI WorkerThreadProc(LPVOID) {
    LogEvent("info", "runtime.worker", "started", "runtime worker thread started");
    while (!g_stop_requested.load()) {
        ScanCommandDirectory();
        ProcessQueuedItems();
        Sleep(kWorkerSleepMs);
    }
    LogEvent("info", "runtime.worker", "stopped", "runtime worker thread stopped");
    return 0;
}

DWORD WINAPI StartupBootstrapThread(LPVOID) {
    EnsureRuntimeStarted();
    LogEvent("info", "runtime.bootstrap_thread", "completed", "startup bootstrap thread completed");
    return 0;
}

void EnsureRuntimeStarted() {
    if (g_runtime_started.load()) {
        return;
    }

    ExclusiveLockGuard guard(&g_runtime_lock);
    if (g_runtime_started.load()) {
        return;
    }

    g_host_pid = GetCurrentProcessId();
    EnsureDirectory(CommandDir());
    EnsureDirectory(AckDir());
    LogEvent("info", "runtime.bootstrap", "started", "native runtime bootstrap started");

    g_stop_requested.store(false);
    g_worker_thread = CreateThread(nullptr, 0, WorkerThreadProc, nullptr, 0, nullptr);
    if (!g_worker_thread) {
        LogEvent("error", "runtime.worker", "failed", "failed to create worker thread");
        return;
    }

    g_runtime_started.store(true);
    WriteRuntimeStatus("runtime_ready", "native runtime initialized");
    LogEvent("info", "runtime.ready", "confirmed", "native runtime ready");
}

void QueueDirectScript(const std::string& script) {
    QueueItem item;
    item.type = "execute";
    item.script = script;
    QueueItemForExecution(item);
    LogEvent("info", "export.ExecuteScript", "accepted", "direct script queued");
}

} // namespace

extern "C" __declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        g_host_pid = GetCurrentProcessId();
        g_startup_thread = CreateThread(nullptr, 0, StartupBootstrapThread, nullptr, 0, nullptr);
    } else if (reason == DLL_PROCESS_DETACH) {
        g_stop_requested.store(true);
    }
    return TRUE;
}

extern "C" __declspec(dllexport) DWORD WINAPI StartRuntimeThreadProc(LPVOID) {
    EnsureRuntimeStarted();
    LogEvent("info", "export.StartRuntimeThreadProc", "called", "StartRuntimeThreadProc invoked");
    return g_runtime_started.load() ? 0u : 1u;
}

extern "C" __declspec(dllexport) void ExecuteScript(char* cscript) {
    EnsureRuntimeStarted();
    QueueDirectScript(cscript ? std::string(cscript) : std::string());
}

extern "C" __declspec(dllexport) void ProcessQ(void) {
    EnsureRuntimeStarted();
    ProcessQueuedItems();
    LogEvent("info", "export.ProcessQ", "called", "ProcessQ invoked");
}

extern "C" __declspec(dllexport) void GoDrawLoop(void) {
    LogEvent("info", "export.GoDrawLoop", "called", "GoDrawLoop invoked");
}

extern "C" __declspec(dllexport) void GoIndex(void) {
    LogEvent("info", "export.GoIndex", "called", "GoIndex invoked");
}

extern "C" __declspec(dllexport) void GoLunaGateway(void) {
    LogEvent("info", "export.GoLunaGateway", "called", "GoLunaGateway invoked");
}

extern "C" __declspec(dllexport) void GoNamecall(void) {
    LogEvent("info", "export.GoNamecall", "called", "GoNamecall invoked");
}

extern "C" __declspec(dllexport) void GoStepHookPayload(void) {
    EnsureRuntimeStarted();
    ProcessQueuedItems();
    LogEvent("info", "export.GoStepHookPayload", "called", "GoStepHookPayload invoked");
}

extern "C" __declspec(dllexport) void free_go_handle(void) {
    LogEvent("info", "export.free_go_handle", "called", "free_go_handle invoked");
}

extern "C" __declspec(dllexport) void go_lua_callback(void) {
    LogEvent("info", "export.go_lua_callback", "called", "go_lua_callback invoked");
}
