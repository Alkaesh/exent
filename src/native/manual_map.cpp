// manual_map.cpp — Manual map injector (bypasses Byfron)
// Compile: g++ -std=c++17 -O2 -m64 -municode manual_map.cpp -static -o manual_map.exe

#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>

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
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)v);
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

bool load_pe(const std::wstring& path, PeData& pe) {
    std::ifstream f(path.c_str(), std::ios::binary | std::ios::ate);
    if (!f) return false;
    size_t size = f.tellg();
    f.seekg(0);
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

std::vector<uint8_t> build_shellcode(uintptr_t dll_base, uintptr_t dllmain_rva) {
    uintptr_t dllmain = dll_base + dllmain_rva;
    std::vector<uint8_t> sc = { 0x48, 0x83, 0xEC, 0x28, 0x48, 0xB9 };
    for (int i = 0; i < 8; i++) sc.push_back((dll_base >> (i*8)) & 0xFF);
    sc.push_back(0xBA); sc.push_back(0x01); sc.push_back(0x00); sc.push_back(0x00); sc.push_back(0x00);
    sc.push_back(0x45); sc.push_back(0x31); sc.push_back(0xC0);
    sc.push_back(0x48); sc.push_back(0xB8);
    for (int i = 0; i < 8; i++) sc.push_back((dllmain >> (i*8)) & 0xFF);
    sc.push_back(0xFF); sc.push_back(0xD0);
    sc.push_back(0x48); sc.push_back(0x83); sc.push_back(0xC4); sc.push_back(0x28);
    sc.push_back(0xC3);
    return sc;
}

bool resolve_imports(HANDLE process, uintptr_t base, PeData& pe) {
    IMAGE_DATA_DIRECTORY& dir = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.Size == 0) { info("No imports"); return true; }
    auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(pe.raw.data() + rva_to_ptr(dir.VirtualAddress, pe));
    while (desc->Name != 0) {
        const char* dll_name = (const char*)(pe.raw.data() + rva_to_ptr(desc->Name, pe));
        HMODULE hMod = LoadLibraryA(dll_name);
        if (!hMod) { warn(std::string("Missing: ") + dll_name); desc++; continue; }
        info(std::string("Imports: ") + dll_name);
        auto* thunk = (IMAGE_THUNK_DATA64*)(pe.raw.data() + rva_to_ptr(desc->FirstThunk, pe));
        auto* orig = desc->OriginalFirstThunk
            ? (IMAGE_THUNK_DATA64*)(pe.raw.data() + rva_to_ptr(desc->OriginalFirstThunk, pe)) : thunk;
        while (orig->u1.AddressOfData != 0) {
            uintptr_t func_addr = 0;
            if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                func_addr = (uintptr_t)GetProcAddress(hMod, MAKEINTRESOURCEA(orig->u1.Ordinal & 0xFFFF));
            else {
                auto* nb = (IMAGE_IMPORT_BY_NAME*)(pe.raw.data() + rva_to_ptr((DWORD)orig->u1.AddressOfData, pe));
                func_addr = (uintptr_t)GetProcAddress(hMod, nb->Name);
            }
            uintptr_t remote_addr = base + (desc->FirstThunk + (uintptr_t)thunk
                - (uintptr_t)(IMAGE_THUNK_DATA64*)(pe.raw.data() + rva_to_ptr(desc->FirstThunk, pe)));
            SIZE_T wr;
            WriteProcessMemory(process, (LPVOID)remote_addr, &func_addr, sizeof(func_addr), &wr);
            orig++; thunk++;
        }
        desc++;
    }
    return true;
}

bool apply_relocs(HANDLE process, uintptr_t base, PeData& pe) {
    uintptr_t preferred = pe.nt->OptionalHeader.ImageBase;
    if (base == preferred) { info("No relocs needed"); return true; }
    intptr_t delta = (intptr_t)(base - preferred);
    info("Relocs delta: " + hex_str((uintptr_t)delta));
    IMAGE_DATA_DIRECTORY& dir = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir.Size == 0) { warn("No .reloc section"); return false; }
    auto* block = (IMAGE_BASE_RELOCATION*)(pe.raw.data() + rva_to_ptr(dir.VirtualAddress, pe));
    uint8_t* end = pe.raw.data() + rva_to_ptr(dir.VirtualAddress, pe) + dir.Size;
    while ((uint8_t*)block < end && block->SizeOfBlock > 0) {
        DWORD cnt = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)(block + 1);
        for (DWORD i = 0; i < cnt; i++) {
            WORD type = entries[i] >> 12;
            WORD off = entries[i] & 0xFFF;
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
            if (type != IMAGE_REL_BASED_DIR64) continue;
            uintptr_t addr = base + block->VirtualAddress + off;
            uintptr_t val = 0; SIZE_T rd;
            ReadProcessMemory(process, (LPCVOID)addr, &val, sizeof(val), &rd);
            val += delta;
            SIZE_T wr;
            WriteProcessMemory(process, (LPVOID)addr, &val, sizeof(val), &wr);
        }
        block = (IMAGE_BASE_RELOCATION*)((uint8_t*)block + block->SizeOfBlock);
    }
    info("Relocs applied");
    return true;
}

void protect_sections(HANDLE process, uintptr_t base, PeData& pe) {
    for (int i = 0; i < pe.nt->FileHeader.NumberOfSections; i++) {
        auto& s = pe.sections[i];
        if (s.SizeOfRawData == 0) continue;
        DWORD prot = PAGE_READONLY;
        if (s.Characteristics & IMAGE_SCN_MEM_EXECUTE)
            prot = (s.Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else if (s.Characteristics & IMAGE_SCN_MEM_WRITE)
            prot = PAGE_READWRITE;
        DWORD old;
        VirtualProtectEx(process, (LPVOID)(base + s.VirtualAddress), s.Misc.VirtualSize, prot, &old);
    }
}

bool manual_map(DWORD pid, const std::wstring& dll_path) {
    PeData pe;
    if (!load_pe(dll_path, pe)) { std::cerr << "Bad PE" << std::endl; return false; }
    info("PE: " + std::to_string(pe.image_size) + " bytes, " + std::to_string(pe.nt->FileHeader.NumberOfSections) + " sections");
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
        WriteProcessMemory(p, (LPVOID)(base + s.VirtualAddress), pe.raw.data() + s.PointerToRawData, s.SizeOfRawData, &wr);
    }
    info("Sections mapped");
    apply_relocs(p, base, pe);
    resolve_imports(p, base, pe);
    protect_sections(p, base, pe);
    uintptr_t entry = pe.nt->OptionalHeader.AddressOfEntryPoint;
    if (entry == 0) { warn("No DllMain"); CloseHandle(p); return true; }
    info("DllMain RVA: " + hex_str(entry));
    auto sc = build_shellcode(base, entry);
    LPVOID sc_mem = VirtualAllocEx(p, nullptr, sc.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!sc_mem) { die("Shellcode alloc"); CloseHandle(p); return false; }
    WriteProcessMemory(p, sc_mem, sc.data(), sc.size(), &wr);
    info("Shellcode written");
    HANDLE t = CreateRemoteThread(p, nullptr, 0, (LPTHREAD_START_ROUTINE)sc_mem, nullptr, 0, nullptr);
    if (!t) { die("CreateRemoteThread for DllMain"); CloseHandle(p); return false; }
    info("DllMain thread running...");
    WaitForSingleObject(t, 15000);
    DWORD ec; GetExitCodeThread(t, &ec);
    CloseHandle(t);
    VirtualFreeEx(p, sc_mem, 0, MEM_RELEASE);
    CloseHandle(p);
    info("DllMain returned " + std::to_string(ec) + " (" + (ec ? "TRUE)" : "FALSE)"));
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
        std::wcout << L"Manual Map Injector (bypasses Byfron)\n\n"
                   << L"Usage: manual_map.exe <dll> --pid <id>\n"
                   << L"       manual_map.exe <dll> --process <name>\n";
        return 1;
    }
    std::wstring dll; DWORD pid = 0; std::wstring pname;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--pid" && i + 1 < argc) pid = _wtoi(argv[++i]);
        else if (a == L"--process" && i + 1 < argc) pname = argv[++i];
        else if (dll.empty()) dll = argv[i];
    }
    if (dll.empty()) { std::cerr << "DLL required" << std::endl; return 1; }
    if (!pid) {
        if (pname.empty()) { std::cerr << "--pid or --process required" << std::endl; return 1; }
        pid = find_pid(pname);
        if (!pid) { std::cerr << "Process not found" << std::endl; return 1; }
    }
    if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) { std::wcerr << L"DLL not found" << std::endl; return 1; }

    std::wcout << L"\n=== Architecture ===" << std::endl;
    bool d64 = is_x64_dll(dll), p64 = is_x64_process(pid);
    std::wcout << L"  DLL:     " << (d64 ? L"64-bit" : L"32-bit") << std::endl;
    std::wcout << L"  Process: " << (p64 ? L"64-bit" : L"32-bit") << std::endl;
    if (d64 != p64) { std::cerr << "MISMATCH!" << std::endl; return 1; }
    std::wcout << L"  OK" << std::endl;

    std::wcout << L"\nManual mapping into PID " << pid << std::endl;
    if (!manual_map(pid, dll)) { std::cerr << "\nFailed." << std::endl; return 1; }
    std::cout << "\nDONE! Check: %TEMP%\\luna_extracted\\" << pid << "\\runtime.log" << std::endl;
    return 0;
}
