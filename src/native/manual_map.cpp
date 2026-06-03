// manual_map.cpp — Manual map injector (APC, bypasses Byfron)
// Maps DLL into remote process and calls entry point via APC.
// No TLS setup needed — DLL uses dynamic UCRT (ucrtbase.dll already loaded).
// Compile: g++ -std=c++17 -O2 -m64 -municode manual_map.cpp -static -o manual_map.exe

#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>

static const DWORD PROCESS_ALL_ACCESS_FLAGS = 0x001F0FFF;

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

// ---- Process utils ----

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

// ---- PE parsing ----

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

void dump_sections(const PeData& pe) {
    info("Sections: " + std::to_string(pe.nt->FileHeader.NumberOfSections));
    for (int i = 0; i < pe.nt->FileHeader.NumberOfSections; i++) {
        auto& s = pe.sections[i];
        char name[9] = {0}; memcpy(name, s.Name, 8);
        info("  [" + std::to_string(i) + "] \"" + std::string(name) + "\"" +
             " VA=" + hex_str(s.VirtualAddress) +
             " raw=" + std::to_string(s.SizeOfRawData));
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

// ---- Import resolution ----

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
        info("  Import: " + std::string(dn) + " -> " + rn + " (" + hex_str(rdb) + ")");
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
            SIZE_T wr;
            WriteProcessMemory(p, (LPVOID)(base + (desc->FirstThunk +
                (uintptr_t)tk - (uintptr_t)(IMAGE_THUNK_DATA64*)
                (pe.raw.data() + rva_to_ptr(desc->FirstThunk, pe)))), &rf, sizeof(rf), &wr);
            og++; tk++;
        }
        FreeLibrary(hm);
        if (ur > 0) warn(std::to_string(ur) + " unresolved from " + dn);
        desc++;
    }
    return true;
}

// ---- Relocations ----

bool apply_relocs(HANDLE p, uintptr_t base, PeData& pe) {
    uintptr_t pref = pe.nt->OptionalHeader.ImageBase;
    if (base == pref) return true;
    intptr_t delta = (intptr_t)(base - pref);
    info("Relocs: delta=" + hex_str((uintptr_t)delta));
    auto& dir = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir.Size == 0) { warn("No .reloc section"); return false; }
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

// ---- Section protection ----

void protect_sections(HANDLE p, uintptr_t base, PeData& pe) {
    for (int i = 0; i < pe.nt->FileHeader.NumberOfSections; i++) {
        auto& s = pe.sections[i];
        if (s.SizeOfRawData == 0) continue;
        DWORD prot = PAGE_READONLY;
        if (s.Characteristics & IMAGE_SCN_MEM_EXECUTE)
            prot = (s.Characteristics & IMAGE_SCN_MEM_WRITE)
                ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else if (s.Characteristics & IMAGE_SCN_MEM_WRITE)
            prot = PAGE_READWRITE;
        DWORD old;
        VirtualProtectEx(p, (LPVOID)(base + s.VirtualAddress),
                        s.Misc.VirtualSize, prot, &old);
    }
}

// ---- APC injection (bypasses Byfron) ----

// Shellcode that calls DllMain(dll_base, DLL_PROCESS_ATTACH, NULL)
// Runs as APC callback: rcx = dll_base (ULONG_PTR param from QueueUserAPC)
std::vector<uint8_t> build_apc_shellcode(uintptr_t entry_addr) {
    std::vector<uint8_t> sc;
    sc.push_back(0x48); sc.push_back(0x83); sc.push_back(0xEC); sc.push_back(0x28); // sub rsp,0x28
    sc.push_back(0xBA); sc.push_back(0x01); sc.push_back(0x00); sc.push_back(0x00); sc.push_back(0x00); // mov edx,1
    sc.push_back(0x45); sc.push_back(0x31); sc.push_back(0xC0);                       // xor r8d,r8d
    sc.push_back(0x48); sc.push_back(0xB8);                                             // mov rax,imm64
    for (int i = 0; i < 8; i++) sc.push_back((entry_addr >> (i*8)) & 0xFF);
    sc.push_back(0xFF); sc.push_back(0xD0);                                             // call rax
    sc.push_back(0x48); sc.push_back(0x83); sc.push_back(0xC4); sc.push_back(0x28);     // add rsp,0x28
    sc.push_back(0xC3);                                                                 // ret
    return sc;
}

bool inject_via_apc(HANDLE p, DWORD pid, uintptr_t dll_base, uintptr_t entry_rva) {
    auto sc = build_apc_shellcode(dll_base + entry_rva);

    LPVOID sc_mem = VirtualAllocEx(p, nullptr, sc.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!sc_mem) { warn("APC alloc failed"); return false; }

    SIZE_T wr;
    WriteProcessMemory(p, sc_mem, sc.data(), sc.size(), &wr);

    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (s == INVALID_HANDLE_VALUE) { VirtualFreeEx(p, sc_mem, 0, MEM_RELEASE); return false; }

    THREADENTRY32 te{sizeof(te)};
    if (!Thread32First(s, &te)) { CloseHandle(s); VirtualFreeEx(p, sc_mem, 0, MEM_RELEASE); return false; }

    bool queued = false;
    int total = 0;
    do {
        if (te.th32OwnerProcessID != pid) continue;
        total++;
        if (queued) continue;  // only 1 APC — DllMain runs once

        HANDLE h = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
        if (!h) continue;

        if (QueueUserAPC((PAPCFUNC)sc_mem, h, (ULONG_PTR)dll_base)) {
            info("APC -> TID=" + std::to_string(te.th32ThreadID));
            queued = true;
        }
        CloseHandle(h);
    } while (Thread32Next(s, &te));
    CloseHandle(s);

    info(std::to_string(queued) + " APC queued / " + std::to_string(total) + " threads");

    if (!queued) {
        warn("QueueUserAPC failed on all threads — run as Administrator?");
        VirtualFreeEx(p, sc_mem, 0, MEM_RELEASE);
        return false;
    }
    return true;
}

// ---- Main ----

bool manual_map(DWORD pid, const std::wstring& dll_path) {
    PeData pe;
    if (!load_pe(dll_path, pe)) {
        std::cerr << "[ERROR] Bad PE file" << std::endl;
        return false;
    }

    info("DLL: " + std::to_string(pe.image_size) + " bytes, " +
         std::to_string(pe.nt->FileHeader.NumberOfSections) + " sections");
    dump_sections(pe);

    // Show TLS directory if present
    auto& tls_dir = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_dir.Size > 0 && tls_dir.VirtualAddress > 0) {
        auto* tls = (IMAGE_TLS_DIRECTORY64*)(pe.raw.data() + rva_to_ptr(tls_dir.VirtualAddress, pe));
        info("TLS: template=" + hex_str(tls->StartAddressOfRawData) +
             " size=" + std::to_string(tls->EndAddressOfRawData - tls->StartAddressOfRawData) +
             " zero=" + std::to_string(tls->SizeOfZeroFill));
    } else {
        info("TLS: none (dynamic CRT — no manual TLS setup needed)");
    }

    HANDLE p = OpenProcess(PROCESS_ALL_ACCESS_FLAGS, FALSE, pid);
    if (!p) { std::cerr << "[ERROR] OpenProcess failed — run as ADMIN!" << std::endl; return false; }
    info("Opened PID " + std::to_string(pid));

    LPVOID mem = VirtualAllocEx(p, nullptr, pe.image_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { die("VirtualAllocEx"); CloseHandle(p); return false; }
    uintptr_t base = (uintptr_t)mem;
    info("Mapped @ " + hex_str(base));

    SIZE_T wr;
    WriteProcessMemory(p, mem, pe.raw.data(), pe.nt->OptionalHeader.SizeOfHeaders, &wr);
    for (int i = 0; i < pe.nt->FileHeader.NumberOfSections; i++) {
        auto& s = pe.sections[i];
        if (s.SizeOfRawData == 0) continue;
        WriteProcessMemory(p, (LPVOID)(base + s.VirtualAddress),
            pe.raw.data() + s.PointerToRawData, s.SizeOfRawData, &wr);
    }

    apply_relocs(p, base, pe);
    resolve_imports(p, pid, base, pe);
    protect_sections(p, base, pe);

    uintptr_t entry = pe.nt->OptionalHeader.AddressOfEntryPoint;
    if (entry == 0) { warn("No entry point"); CloseHandle(p); return true; }
    info("Entry RVA: " + hex_str(entry));

    // APC injection — bypasses Byfron (they don't hook QueueUserAPC on main thread)
    info("APC injection (1 thread, bypasses Byfron)...");
    if (inject_via_apc(p, pid, base, entry)) {
        info("SUCCESS! DLL @ " + hex_str(base));
        info("APC fires when thread becomes alertable (~1-2 sec).");
        info("Runtime log: %TEMP%\\luna_extracted\\" +
             std::to_string(pid) + "\\runtime.log");
        CloseHandle(p);
        return true;
    }

    CloseHandle(p);
    return false;
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
        std::wcout << L"Manual Map Injector (APC, Byfron bypass)\n\n"
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

    if (dll.empty()) { std::cerr << "DLL path required" << std::endl; return 1; }
    if (!pid) {
        if (pname.empty()) { std::cerr << "--pid or --process required" << std::endl; return 1; }
        pid = find_pid(pname);
        if (!pid) { std::cerr << "Process '" << std::string(pname.begin(), pname.end()) << "' not found" << std::endl; return 1; }
    }
    if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"DLL not found: " << dll << std::endl; return 1;
    }

    std::wcout << L"\n=== Architecture ===" << std::endl;
    bool d64 = is_x64_dll(dll), p64 = is_x64_process(pid);
    std::wcout << L"  DLL:     " << (d64 ? L"64-bit" : L"32-bit") << std::endl;
    std::wcout << L"  Process: " << (p64 ? L"64-bit" : L"32-bit") << std::endl;
    if (d64 != p64) { std::cerr << "Architecture MISMATCH!" << std::endl; return 1; }
    std::wcout << L"  OK" << std::endl;

    std::wcout << L"\nInjecting into PID " << pid << L"..." << std::endl;
    if (!manual_map(pid, dll)) {
        std::cerr << "\nInjection FAILED." << std::endl;
        return 1;
    }

    std::wcout << L"\nDONE. Wait ~2 sec for APC to fire, then check %TEMP%\\luna_extracted\\"
               << pid << L"\\runtime.log" << std::endl;
    return 0;
}
