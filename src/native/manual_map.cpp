// manual_map.cpp — Manual map injector (bypasses Byfron)
// Compile: g++ -std=c++17 -O2 -m64 -municode manual_map.cpp -static -o manual_map.exe

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>

static const DWORD PROCESS_ALL_ACCESS_FLAGS = 0x001F0FFF;

// NtCreateThreadEx for stealth thread creation (bypasses Byfron CreateRemoteThread hook)
typedef NTSTATUS (NTAPI* NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartAddress,
    PVOID Parameter,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

static NtCreateThreadEx_t pNtCreateThreadEx = nullptr;

HANDLE create_remote_thread_stealth(HANDLE process, PVOID start, PVOID param) {
    if (!pNtCreateThreadEx) {
        pNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
        if (!pNtCreateThreadEx) return nullptr;
    }
    HANDLE hThread = nullptr;
    NTSTATUS status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr,
        process, start, param, 0, 0, 0, 0, nullptr);
    return (status >= 0) ? hThread : nullptr;
}

void die(const std::string& msg) {
    DWORD code = GetLastError();
    LPSTR buf = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        nullptr, code, 0, (LPSTR)&buf, 0, nullptr);
    std::cerr << "[FATAL] " << msg << " (code=" << code << ")";
    if (buf) { std::cerr << ": " << buf; LocalFree(buf); }
    std::cerr << std::endl;
    exit(1);
}

void info(const std::string& msg) { std::cout << "[+] " << msg << std::endl; }
void warn(const std::string& msg) { std::cout << "[!] " << msg << std::endl; }

std::string hex_str(uintptr_t v) {
    char buf[32]; snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)v);
    return std::string(buf);
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

uintptr_t remote_module_base(DWORD pid, const std::string& name_lower) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (s == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W e{sizeof(e)};
    if (!Module32FirstW(s, &e)) { CloseHandle(s); return 0; }
    do {
        std::string mod_name;
        for (int i = 0; e.szModule[i]; i++) {
            char c = (char)(e.szModule[i] < 128 ? e.szModule[i] : '?');
            mod_name.push_back((char)tolower(c));
        }
        if (mod_name == name_lower) { uintptr_t b = (uintptr_t)e.modBaseAddr; CloseHandle(s); return b; }
    } while (Module32NextW(s, &e));
    CloseHandle(s); return 0;
}

const char* resolve_api_set(const char* name) {
    if (strstr(name, "api-ms-win-crt-") || strstr(name, "api-ms-win-core-"))
        return "ucrtbase.dll";
    if (strstr(name, "api-ms-win-eventing-"))
        return "sechost.dll";
    return name;
}

struct PeData {
    std::vector<uint8_t> raw;
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS64* nt;
    IMAGE_SECTION_HEADER* sections;
    size_t image_size;
};

uintptr_t rva_to_ptr(DWORD rva, const PeData& pe) {
    for (int i = 0; i < pe.nt->FileHeader.NumberOfSections; i++) {
        auto& s = pe.sections[i];
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.Misc.VirtualSize)
            return rva - s.VirtualAddress + s.PointerToRawData;
    }
    if (rva < pe.nt->OptionalHeader.SizeOfHeaders) return rva;
    return rva;
}

// Safe section name extractor — IMAGE_SECTION_HEADER.Name is 8 bytes with no null guarantee
std::string get_section_name(IMAGE_SECTION_HEADER& s) {
    char name[9] = {0};
    memcpy(name, s.Name, 8);
    return std::string(name);
}

bool section_name_is(const IMAGE_SECTION_HEADER& s, const char* name) {
    size_t len = strlen(name);
    if (len > 8) len = 8;
    return memcmp(s.Name, name, len) == 0 && (len == 8 || s.Name[len] == 0);
}

void dump_sections(const PeData& pe) {
    info("Sections: " + std::to_string(pe.nt->FileHeader.NumberOfSections) + " sections");
    for (int i = 0; i < pe.nt->FileHeader.NumberOfSections; i++) {
        std::string name = get_section_name(pe.sections[i]);
        info("  [" + std::to_string(i) + "] " + name +
             " VA=0x" + hex_str(pe.sections[i].VirtualAddress) +
             " size=" + std::to_string(pe.sections[i].SizeOfRawData));
    }
}

bool load_pe(const std::wstring& path, PeData& pe) {
    std::ifstream f(path.c_str(), std::ios::binary | std::ios::ate);
    if (!f) return false;
    size_t size = f.tellg(); f.seekg(0);
    pe.raw.resize(size);
    f.read((char*)pe.raw.data(), size);
    pe.dos = (IMAGE_DOS_HEADER*)pe.raw.data();
    if (pe.dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    pe.nt = (IMAGE_NT_HEADERS64*)(pe.raw.data() + pe.dos->e_lfanew);
    if (pe.nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (pe.nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;
    pe.sections = IMAGE_FIRST_SECTION(pe.nt);
    pe.image_size = pe.nt->OptionalHeader.SizeOfImage;
    return true;
}

// Build shellcode that calls DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL)
std::vector<uint8_t> build_shellcode(uintptr_t dl, uintptr_t dllmain_rva) {
    uintptr_t dllmain = dl + dllmain_rva;
    std::vector<uint8_t> sc = { 0x48, 0x83, 0xEC, 0x28, 0x48, 0xB9 };
    for (int i = 0; i < 8; i++) sc.push_back((dl >> (i*8)) & 0xFF);
    sc.push_back(0xBA); sc.push_back(0x01); sc.push_back(0x00); sc.push_back(0x00); sc.push_back(0x00);
    sc.push_back(0x45); sc.push_back(0x31); sc.push_back(0xC0);
    sc.push_back(0x48); sc.push_back(0xB8);
    for (int i = 0; i < 8; i++) sc.push_back((dllmain >> (i*8)) & 0xFF);
    sc.push_back(0xFF); sc.push_back(0xD0);
    sc.push_back(0x48); sc.push_back(0x83); sc.push_back(0xC4); sc.push_back(0x28);
    sc.push_back(0xC3);
    return sc;
}

// Build shellcode that calls a single function (for CRT init calls)
std::vector<uint8_t> build_call_shellcode(uintptr_t fn_addr) {
    std::vector<uint8_t> sc = { 0x48, 0x83, 0xEC, 0x28 };
    sc.push_back(0x48); sc.push_back(0xB8);
    for (int i = 0; i < 8; i++) sc.push_back((fn_addr >> (i*8)) & 0xFF);
    sc.push_back(0xFF); sc.push_back(0xD0);
    sc.push_back(0x48); sc.push_back(0x83); sc.push_back(0xC4); sc.push_back(0x28);
    sc.push_back(0xC3);
    return sc;
}

// Execute a single remote function via stealth thread
bool call_remote_fn(HANDLE p, uintptr_t fn_addr) {
    auto sc = build_call_shellcode(fn_addr);
    LPVOID sc_mem = VirtualAllocEx(p, nullptr, sc.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!sc_mem) return false;

    SIZE_T wr;
    WriteProcessMemory(p, sc_mem, sc.data(), sc.size(), &wr);

    HANDLE t = create_remote_thread_stealth(p, sc_mem, nullptr);
    if (t) {
        WaitForSingleObject(t, 5000);
        CloseHandle(t);
    }
    VirtualFreeEx(p, sc_mem, 0, MEM_RELEASE);
    return t != nullptr;
}

// Call CRT init functions in the remote process.
// Handles .init_array, .ctors, and .CRT$XC* sections used by various compilers.
bool call_crt_init(HANDLE p, uintptr_t base, PeData& pe) {
    bool found = false;

    for (int i = 0; i < pe.nt->FileHeader.NumberOfSections; i++) {
        auto& s = pe.sections[i];
        std::string name = get_section_name(s);

        bool is_init_array = section_name_is(s, ".init_array");
        bool is_ctors = section_name_is(s, ".ctors");
        // MinGW puts CRT init functions in sections like .CRT$XCA, .CRT$XCZ etc.
        bool is_crt_xc = (name.size() >= 6 && name.substr(0, 6) == ".CRT$X");

        if (!is_init_array && !is_ctors && !is_crt_xc) continue;

        size_t count = s.SizeOfRawData / sizeof(uintptr_t);
        if (count == 0) continue;

        uintptr_t* entries = (uintptr_t*)(pe.raw.data() + s.PointerToRawData);

        info(std::string("Init found: \"") + name + "\" (" + std::to_string(count) + " entries)");

        for (size_t j = 0; j < count; j++) {
            uintptr_t fn_rva = entries[j];
            if (fn_rva == 0 || fn_rva == (uintptr_t)-1) continue;

            uintptr_t fn_addr = base + fn_rva;
            info("  Calling constructor @ " + hex_str(fn_addr) + " (RVA " + hex_str(fn_rva) + ")");
            call_remote_fn(p, fn_addr);
        }
        found = true;
    }

    if (!found) {
        warn("No .init_array / .ctors / .CRT$XC* section — CRT init skipped");
        warn("The DLL entry point (DllMainCRTStartup) should handle CRT init internally");
    }
    return found;
}

bool resolve_imports(HANDLE p, DWORD pid, uintptr_t base, PeData& pe) {
    auto& dir = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.Size == 0) { info("No imports"); return true; }
    auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(pe.raw.data() + rva_to_ptr(dir.VirtualAddress, pe));
    while (desc->Name != 0) {
        const char* dn = (const char*)(pe.raw.data() + rva_to_ptr(desc->Name, pe));
        const char* rn = resolve_api_set(dn);
        std::string rl;
        for (const char* c = rn; *c; c++) rl.push_back((char)tolower(*c));
        uintptr_t rdb = remote_module_base(pid, rl);
        if (!rdb) { warn(std::string("Not in target: ") + dn); desc++; continue; }
        HMODULE hm = LoadLibraryA(rn);
        if (!hm) { warn(std::string("Can't load: ") + rn); desc++; continue; }
        info(std::string("Imports: ") + dn + " -> " + rn + " @ " + hex_str(rdb));
        auto* tk = (IMAGE_THUNK_DATA64*)(pe.raw.data() + rva_to_ptr(desc->FirstThunk, pe));
        auto* og = desc->OriginalFirstThunk
            ? (IMAGE_THUNK_DATA64*)(pe.raw.data() + rva_to_ptr(desc->OriginalFirstThunk, pe)) : tk;
        uintptr_t lb = (uintptr_t)hm;
        int ur = 0;
        while (og->u1.AddressOfData != 0) {
            uintptr_t lf = 0;
            if (og->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                lf = (uintptr_t)GetProcAddress(hm, MAKEINTRESOURCEA(og->u1.Ordinal & 0xFFFF));
            else {
                auto* nb = (IMAGE_IMPORT_BY_NAME*)(pe.raw.data() + rva_to_ptr((DWORD)og->u1.AddressOfData, pe));
                lf = (uintptr_t)GetProcAddress(hm, nb->Name);
            }
            uintptr_t rf = lf ? (rdb + (lf - lb)) : 0;
            if (!lf) ur++;
            uintptr_t ri = base + (desc->FirstThunk + (uintptr_t)tk
                - (uintptr_t)(IMAGE_THUNK_DATA64*)(pe.raw.data() + rva_to_ptr(desc->FirstThunk, pe)));
            SIZE_T wr;
            WriteProcessMemory(p, (LPVOID)ri, &rf, sizeof(rf), &wr);
            og++; tk++;
        }
        FreeLibrary(hm);
        if (ur > 0) warn(std::to_string(ur) + " unresolved from " + dn);
        desc++;
    }
    return true;
}

bool apply_relocs(HANDLE p, uintptr_t base, PeData& pe) {
    uintptr_t pref = pe.nt->OptionalHeader.ImageBase;
    if (base == pref) { info("No relocs"); return true; }
    intptr_t delta = (intptr_t)(base - pref);
    info("Relocs delta: " + hex_str((uintptr_t)delta));
    auto& dir = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir.Size == 0) { warn("No .reloc"); return false; }
    auto* blk = (IMAGE_BASE_RELOCATION*)(pe.raw.data() + rva_to_ptr(dir.VirtualAddress, pe));
    uint8_t* en = pe.raw.data() + rva_to_ptr(dir.VirtualAddress, pe) + dir.Size;
    while ((uint8_t*)blk < en && blk->SizeOfBlock > 0) {
        DWORD cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* e = (WORD*)(blk + 1);
        for (DWORD i = 0; i < cnt; i++) {
            if ((e[i] >> 12) != IMAGE_REL_BASED_DIR64) continue;
            uintptr_t a = base + blk->VirtualAddress + (e[i] & 0xFFF);
            uintptr_t v = 0; SIZE_T rd;
            ReadProcessMemory(p, (LPCVOID)a, &v, sizeof(v), &rd);
            v += delta;
            SIZE_T wr;
            WriteProcessMemory(p, (LPVOID)a, &v, sizeof(v), &wr);
        }
        blk = (IMAGE_BASE_RELOCATION*)((uint8_t*)blk + blk->SizeOfBlock);
    }
    info("Relocs applied");
    return true;
}

void protect_sections(HANDLE p, uintptr_t base, PeData& pe) {
    for (int i = 0; i < pe.nt->FileHeader.NumberOfSections; i++) {
        auto& s = pe.sections[i];
        if (s.SizeOfRawData == 0) continue;
        DWORD prot = PAGE_READONLY;
        if (s.Characteristics & IMAGE_SCN_MEM_EXECUTE)
            prot = (s.Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else if (s.Characteristics & IMAGE_SCN_MEM_WRITE)
            prot = PAGE_READWRITE;
        DWORD old;
        VirtualProtectEx(p, (LPVOID)(base + s.VirtualAddress), s.Misc.VirtualSize, prot, &old);
    }
}

bool manual_map(DWORD pid, const std::wstring& dll_path) {
    PeData pe;
    if (!load_pe(dll_path, pe)) { std::cerr << "Bad PE" << std::endl; return false; }
    info("PE: " + std::to_string(pe.image_size) + " bytes, " +
         std::to_string(pe.nt->FileHeader.NumberOfSections) + " sections");

    dump_sections(pe);

    HANDLE p = OpenProcess(PROCESS_ALL_ACCESS_FLAGS, FALSE, pid);
    if (!p) { std::cerr << "OpenProcess failed — run as ADMIN!" << std::endl; return false; }
    info("Opened PID " + std::to_string(pid));

    LPVOID mem = VirtualAllocEx(p, nullptr, pe.image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { die("VirtualAllocEx"); CloseHandle(p); return false; }
    uintptr_t base = (uintptr_t)mem;
    info("Allocated at " + hex_str(base));

    SIZE_T wr;
    WriteProcessMemory(p, mem, pe.raw.data(), pe.nt->OptionalHeader.SizeOfHeaders, &wr);
    for (int i = 0; i < pe.nt->FileHeader.NumberOfSections; i++) {
        auto& s = pe.sections[i];
        if (s.SizeOfRawData == 0) continue;
        WriteProcessMemory(p, (LPVOID)(base + s.VirtualAddress),
            pe.raw.data() + s.PointerToRawData, s.SizeOfRawData, &wr);
    }
    info("Sections mapped");

    apply_relocs(p, base, pe);
    resolve_imports(p, pid, base, pe);

    // CRT init: call global constructors BEFORE DllMain
    call_crt_init(p, base, pe);

    protect_sections(p, base, pe);

    uintptr_t entry = pe.nt->OptionalHeader.AddressOfEntryPoint;
    if (entry == 0) { warn("No entry point"); CloseHandle(p); return true; }
    info("Entry point RVA: " + hex_str(entry));

    // Use NtCreateThreadEx instead of CreateRemoteThread to bypass Byfron hooks
    auto sc = build_shellcode(base, entry);
    LPVOID sc_mem = VirtualAllocEx(p, nullptr, sc.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!sc_mem) { die("Shellcode alloc"); CloseHandle(p); return false; }
    WriteProcessMemory(p, sc_mem, sc.data(), sc.size(), &wr);

    HANDLE t = create_remote_thread_stealth(p, sc_mem, nullptr);
    if (!t) {
        warn("NtCreateThreadEx failed, falling back to CreateRemoteThread");
        t = CreateRemoteThread(p, nullptr, 0,
            (LPTHREAD_START_ROUTINE)sc_mem, nullptr, 0, nullptr);
    }
    if (!t) { die("CreateRemoteThread"); CloseHandle(p); return false; }

    info("Entry point thread running...");
    WaitForSingleObject(t, 15000);
    DWORD ec; GetExitCodeThread(t, &ec);
    CloseHandle(t);
    VirtualFreeEx(p, sc_mem, 0, MEM_RELEASE);
    CloseHandle(p);

    if (ec == 1 || ec == 0)
        info("Entry returned " + std::to_string(ec) + " — initialized!");
    else {
        warn("Entry returned " + std::to_string(ec) + " (" + hex_str(ec) + ")");
        if (ec == 0xC000071C || ec == 0xC0000428) {
            warn("This looks like an anti-cheat block (Byfron/Hyperion).");
            warn("Possible workarounds:");
            warn("  1. Use a different injection method (SetWindowsHookEx, queue APC)");
            warn("  2. Try thread hijacking instead of creating a new thread");
            warn("  3. Check if Roblox updates patched this method");
        }
    }
    info("DLL mapped at " + hex_str(base));
    return true;
}

bool is_x64_dll(const std::wstring& p) {
    std::ifstream f(p.c_str(), std::ios::binary);
    if (!f) return false;
    IMAGE_DOS_HEADER dos; f.read((char*)&dos, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
    f.seekg(dos.e_lfanew);
    DWORD sig; f.read((char*)&sig, sizeof(sig));
    if (sig != IMAGE_NT_SIGNATURE) return false;
    IMAGE_FILE_HEADER fh; f.read((char*)&fh, sizeof(fh));
    WORD magic; f.read((char*)&magic, sizeof(magic));
    return magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

bool is_x64_process(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    BOOL w = FALSE; IsWow64Process(h, &w); CloseHandle(h);
    return !w;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        std::wcout << L"Manual Map Injector\n\n"
                   << L"Usage: manual_map.exe <dll> --pid <id>\n"
                   << L"       manual_map.exe <dll> --process <name>\n";
        return 1;
    }
    std::wstring dll; DWORD pid = 0; std::wstring pname;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--pid" && i+1 < argc) pid = _wtoi(argv[++i]);
        else if (a == L"--process" && i+1 < argc) pname = argv[++i];
        else if (dll.empty()) dll = argv[i];
    }
    if (dll.empty()) { std::cerr << "DLL required" << std::endl; return 1; }
    if (!pid) {
        if (pname.empty()) { std::cerr << "--pid or --process required" << std::endl; return 1; }
        pid = find_pid(pname);
        if (!pid) { std::cerr << "Process not found" << std::endl; return 1; }
    }
    if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"DLL not found" << std::endl; return 1;
    }

    std::wcout << L"\n=== Architecture ===" << std::endl;
    bool d64 = is_x64_dll(dll), p64 = is_x64_process(pid);
    std::wcout << L"  DLL:     " << (d64 ? L"64-bit" : L"32-bit") << std::endl;
    std::wcout << L"  Process: " << (p64 ? L"64-bit" : L"32-bit") << std::endl;
    if (d64 != p64) { std::cerr << "MISMATCH!" << std::endl; return 1; }
    std::wcout << L"  OK" << std::endl;

    std::wcout << L"\nManual mapping PID " << pid << std::endl;
    if (!manual_map(pid, dll)) { std::cerr << "\nFailed." << std::endl; return 1; }
    std::cout << "\nDONE! %TEMP%\\luna_extracted\\" << pid << "\\runtime.log" << std::endl;
    return 0;
}
