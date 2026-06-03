// manual_map.cpp — Manual map injector with APC injection (clean, doesn't corrupt threads)
// Compile: g++ -std=c++17 -O2 -m64 -municode manual_map.cpp -static -o manual_map.exe

#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstring>
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

// ---- PE ----

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
    for (int i = 0; i < pe.nt->FileHeader.NumberOfSections; i++) {
        auto& s = pe.sections[i];
        char name[9] = {0}; memcpy(name, s.Name, 8);
        std::string hn;
        for (int j = 0; j < 8 && s.Name[j]; j++) {
            char h[4]; snprintf(h, sizeof(h), "%02X ", (unsigned char)s.Name[j]); hn += h;
        }
        info("  [" + std::to_string(i) + "] '" + std::string(name) + "' (" + hn +
             ") VA=" + hex_str(s.VirtualAddress) + " size=" + std::to_string(s.SizeOfRawData));
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

// ---- SHELLCODE ----

// APC-compatible shellcode. Runs as an APC callback so signature is:
//   void CALLBACK ApcProc(ULONG_PTR param)
// The param is the DLL base address.
//
// The APC runs on the target thread's stack — safe because APC routines
// are designed to execute inline on alertable threads.
//
//   sub rsp, 0x28              ; shadow space
//   mov rcx, rcx               ; hinstDLL = param (already in rcx)
//   mov edx, 1                 ; DLL_PROCESS_ATTACH
//   xor r8d, r8d               ; reserved
//   mov rax, <dllmain>
//   call rax
//   add rsp, 0x28
//   ret
//
// NOTE: This calls DllMain directly, NOT the CRT entry point.
// For -static MinGW DLLs, the entry point IS DllMainCRTStartup which
// initializes CRT and then calls the user's DllMain.
// So we call DllMainCRTStartup (the entry point), not the user's DllMain.

std::vector<uint8_t> build_apc_shellcode(uintptr_t entry_addr) {
    std::vector<uint8_t> sc;

    // sub rsp, 0x28
    sc.push_back(0x48); sc.push_back(0x83); sc.push_back(0xEC); sc.push_back(0x28);

    // rcx already = DLL base (passed as APC param)
    // mov edx, 1  (DLL_PROCESS_ATTACH)
    sc.push_back(0xBA); sc.push_back(0x01); sc.push_back(0x00);
    sc.push_back(0x00); sc.push_back(0x00);

    // xor r8d, r8d  (lpReserved = NULL)
    sc.push_back(0x45); sc.push_back(0x31); sc.push_back(0xC0);

    // mov rax, entry_addr
    sc.push_back(0x48); sc.push_back(0xB8);
    for (int i = 0; i < 8; i++) sc.push_back((entry_addr >> (i*8)) & 0xFF);

    // call rax
    sc.push_back(0xFF); sc.push_back(0xD0);

    // add rsp, 0x28
    sc.push_back(0x48); sc.push_back(0x83); sc.push_back(0xC4); sc.push_back(0x28);

    // ret
    sc.push_back(0xC3);

    return sc;
}

// ---- INJECTION METHODS ----

// Method 1: APC injection via QueueUserAPC — cleanest approach.
// The target thread must be in an alertable state (most Roblox threads are).
bool inject_via_apc(HANDLE p, DWORD pid, uintptr_t dll_base, uintptr_t entry_rva) {
    uintptr_t entry_addr = dll_base + entry_rva;
    auto sc = build_apc_shellcode(entry_addr);

    LPVOID sc_mem = VirtualAllocEx(p, nullptr, sc.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!sc_mem) {
        warn("APC shellcode alloc failed");
        return false;
    }

    SIZE_T wr;
    WriteProcessMemory(p, sc_mem, sc.data(), sc.size(), &wr);

    // Enumerate threads
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (s == INVALID_HANDLE_VALUE) {
        VirtualFreeEx(p, sc_mem, 0, MEM_RELEASE);
        return false;
    }

    THREADENTRY32 te{sizeof(te)};
    if (!Thread32First(s, &te)) { CloseHandle(s); VirtualFreeEx(p, sc_mem, 0, MEM_RELEASE); return false; }

    int total = 0, queued = 0;
    do {
        if (te.th32OwnerProcessID != pid) continue;
        total++;

        HANDLE h = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                              FALSE, te.th32ThreadID);
        if (!h) continue;

        // QueueUserAPC requires THREAD_SET_CONTEXT access
        DWORD result = QueueUserAPC((PAPCFUNC)sc_mem, h, (ULONG_PTR)dll_base);
        if (result) {
            queued++;
            info("APC queued on TID=" + std::to_string(te.th32ThreadID));
        }
        CloseHandle(h);
    } while (Thread32Next(s, &te));

    CloseHandle(s);

    info("APCs queued: " + std::to_string(queued) + " / " + std::to_string(total) + " threads");

    if (queued == 0) {
        warn("QueueUserAPC failed on all threads — thread may need alertable state");
        VirtualFreeEx(p, sc_mem, 0, MEM_RELEASE);
        return false;
    }

    // APC will execute when thread enters alertable wait.
    // Most Roblox threads do this regularly (message pump, rendering, etc.)
    info("APC injection successful! DllMain will run when threads become alertable.");
    return true;
}

// Method 2: Thread hijacking with private stack (safe fallback if APC fails)
bool inject_via_hijack(HANDLE p, DWORD pid, uintptr_t dll_base, uintptr_t entry_rva) {
    uintptr_t entry_addr = dll_base + entry_rva;

    // Build shellcode for hijacking.
    // Layout: [0x00..0xFF] data area; [0x100] shellcode
    // Data area:
    //   +0x00: original RIP (8 bytes)
    //   +0x08: original RSP (8 bytes)
    //   +0x18: saved RAX
    //   +0x20: saved RCX
    //   +0x28: saved RDX
    //   +0x30: saved R8
    //   +0x38: saved R9
    //   +0x40: saved R10
    //   +0x48: saved R11
    //   +0x50: saved RFLAGS

    // Shellcode at +0x100 (absolute addresses — we know sc_mem):
    // We'll build it once we know sc_mem.

    // Shellcode:
    //   Save all regs to data area
    //   Switch to new stack (allocated separately)
    //   Call entry point
    //   Restore regs and orig stack
    //   jmp to orig RIP

    size_t page_size = 0x2000;  // 2 pages: one for data+shellcode, one for new stack
    LPVOID sc_mem = VirtualAllocEx(p, nullptr, page_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!sc_mem) {
        warn("Hijack alloc failed");
        return false;
    }

    uintptr_t data_area = (uintptr_t)sc_mem;
    uintptr_t shellcode_addr = data_area + 0x100;
    uintptr_t new_stack_top = data_area + 0x1000;  // second page as private stack

    // Build shellcode with absolute addresses
    std::vector<uint8_t> sc;

    // Save regs
    // mov [data+0x18], rax
    sc.push_back(0x48); sc.push_back(0xA3);
    for (int i = 0; i < 8; i++) sc.push_back((uint8_t)((data_area + 0x18) >> (i*8)));
    // mov [data+0x20], rcx
    sc.push_back(0x48); sc.push_back(0x89); sc.push_back(0x0D);
    { uint32_t o = (uint32_t)(data_area + 0x20); for (int i = 0; i < 4; i++) sc.push_back((uint8_t)(o >> (i*8))); }
    // mov [data+0x28], rdx
    sc.push_back(0x48); sc.push_back(0x89); sc.push_back(0x15);
    { uint32_t o = (uint32_t)(data_area + 0x28); for (int i = 0; i < 4; i++) sc.push_back((uint8_t)(o >> (i*8))); }
    // mov [data+0x30], r8
    sc.push_back(0x4C); sc.push_back(0x89); sc.push_back(0x05);
    { uint32_t o = (uint32_t)(data_area + 0x30); for (int i = 0; i < 4; i++) sc.push_back((uint8_t)(o >> (i*8))); }
    // mov [data+0x38], r9
    sc.push_back(0x4C); sc.push_back(0x89); sc.push_back(0x0D);
    { uint32_t o = (uint32_t)(data_area + 0x38); for (int i = 0; i < 4; i++) sc.push_back((uint8_t)(o >> (i*8))); }
    // mov [data+0x40], r10
    sc.push_back(0x4C); sc.push_back(0x89); sc.push_back(0x15);
    { uint32_t o = (uint32_t)(data_area + 0x40); for (int i = 0; i < 4; i++) sc.push_back((uint8_t)(o >> (i*8))); }
    // mov [data+0x48], r11
    sc.push_back(0x4C); sc.push_back(0x89); sc.push_back(0x1D);
    { uint32_t o = (uint32_t)(data_area + 0x48); for (int i = 0; i < 4; i++) sc.push_back((uint8_t)(o >> (i*8))); }
    // pushfq; pop [data+0x50]
    sc.push_back(0x9C); sc.push_back(0x8F); sc.push_back(0x05);
    { uint32_t o = (uint32_t)(data_area + 0x50); for (int i = 0; i < 4; i++) sc.push_back((uint8_t)(o >> (i*8))); }

    // Save original RSP to data+0x08
    // mov [data+0x08], rsp
    sc.push_back(0x48); sc.push_back(0x89); sc.push_back(0x25);
    { uint32_t o = (uint32_t)(data_area + 0x08); for (int i = 0; i < 4; i++) sc.push_back((uint8_t)(o >> (i*8))); }

    // Switch to private stack
    // mov rsp, new_stack_top
    sc.push_back(0x48); sc.push_back(0xBC);
    for (int i = 0; i < 8; i++) sc.push_back((uint8_t)(new_stack_top >> (i*8)));

    // sub rsp, 0x28 (shadow space)
    sc.push_back(0x48); sc.push_back(0x83); sc.push_back(0xEC); sc.push_back(0x28);

    // mov rcx, dll_base
    sc.push_back(0x48); sc.push_back(0xB9);
    for (int i = 0; i < 8; i++) sc.push_back((uint8_t)(dll_base >> (i*8)));

    // mov edx, 1
    sc.push_back(0xBA); sc.push_back(0x01); sc.push_back(0x00); sc.push_back(0x00); sc.push_back(0x00);

    // xor r8d, r8d
    sc.push_back(0x45); sc.push_back(0x31); sc.push_back(0xC0);

    // mov rax, entry_addr
    sc.push_back(0x48); sc.push_back(0xB8);
    for (int i = 0; i < 8; i++) sc.push_back((uint8_t)(entry_addr >> (i*8)));

    // call rax
    sc.push_back(0xFF); sc.push_back(0xD0);

    // add rsp, 0x28
    sc.push_back(0x48); sc.push_back(0x83); sc.push_back(0xC4); sc.push_back(0x28);

    // Restore original RSP
    // mov rsp, [data+0x08]
    sc.push_back(0x48); sc.push_back(0x8B); sc.push_back(0x25);
    { uint32_t o = (uint32_t)(data_area + 0x08); for (int i = 0; i < 4; i++) sc.push_back((uint8_t)(o >> (i*8))); }

    // Restore regs
    // mov rax, [data+0x18]
    sc.push_back(0x48); sc.push_back(0xA1);
    for (int i = 0; i < 8; i++) sc.push_back((uint8_t)((data_area + 0x18) >> (i*8)));
    // mov rcx, [data+0x20]
    sc.push_back(0x48); sc.push_back(0x8B); sc.push_back(0x0D);
    { uint32_t o = (uint32_t)(data_area + 0x20); for (int i = 0; i < 4; i++) sc.push_back((uint8_t)(o >> (i*8))); }
    // mov rdx, [data+0x28]
    sc.push_back(0x48); sc.push_back(0x8B); sc.push_back(0x15);
    { uint32_t o = (uint32_t)(data_area + 0x28); for (int i = 0; i < 4; i++) sc.push_back((uint8_t)(o >> (i*8))); }
    // mov r8, [data+0x30]
    sc.push_back(0x4C); sc.push_back(0x8B); sc.push_back(0x05);
    { uint32_t o = (uint32_t)(data_area + 0x30); for (int i = 0; i < 4; i++) sc.push_back((uint8_t)(o >> (i*8))); }
    // mov r9, [data+0x38]
    sc.push_back(0x4C); sc.push_back(0x8B); sc.push_back(0x0D);
    { uint32_t o = (uint32_t)(data_area + 0x38); for (int i = 0; i < 4; i++) sc.push_back((uint8_t)(o >> (i*8))); }
    // mov r10, [data+0x40]
    sc.push_back(0x4C); sc.push_back(0x8B); sc.push_back(0x15);
    { uint32_t o = (uint32_t)(data_area + 0x40); for (int i = 0; i < 4; i++) sc.push_back((uint8_t)(o >> (i*8))); }
    // mov r11, [data+0x48]
    sc.push_back(0x4C); sc.push_back(0x8B); sc.push_back(0x1D);
    { uint32_t o = (uint32_t)(data_area + 0x48); for (int i = 0; i < 4; i++) sc.push_back((uint8_t)(o >> (i*8))); }
    // push [data+0x50]; popfq
    sc.push_back(0xFF); sc.push_back(0x35);
    { uint32_t o = (uint32_t)(data_area + 0x50); for (int i = 0; i < 4; i++) sc.push_back((uint8_t)(o >> (i*8))); }
    sc.push_back(0x9D);

    // jmp to original RIP (absolute indirect)
    // ff 25 00 00 00 00 ; jmp [rip+0]
    sc.push_back(0xFF); sc.push_back(0x25);
    sc.push_back(0x00); sc.push_back(0x00); sc.push_back(0x00); sc.push_back(0x00);
    // 8 bytes: original RIP (patched per-thread)
    for (int i = 0; i < 8; i++) sc.push_back(0x00);

    // Find a thread to hijack
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { VirtualFreeEx(p, sc_mem, 0, MEM_RELEASE); return false; }

    THREADENTRY32 te{sizeof(te)};
    if (!Thread32First(snap, &te)) { CloseHandle(snap); VirtualFreeEx(p, sc_mem, 0, MEM_RELEASE); return false; }

    bool success = false;
    int thread_count = 0;
    std::vector<DWORD> tids;
    do {
        if (te.th32OwnerProcessID == pid) { tids.push_back(te.th32ThreadID); thread_count++; }
    } while (Thread32Next(snap, &te));
    CloseHandle(snap);

    info(std::to_string(thread_count) + " threads, trying hijack with private stack...");

    // Try threads from last to first (worker threads are usually at the end)
    for (int ti = (int)tids.size() - 1; ti >= 0 && !success; ti--) {
        DWORD tid = tids[ti];
        HANDLE h = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
        if (!h) continue;

        if (SuspendThread(h) == (DWORD)-1) { CloseHandle(h); continue; }

        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(h, &ctx)) {
            ResumeThread(h); CloseHandle(h); continue;
        }

        // Write original RIP and RSP to data area
        SIZE_T wr2;
        WriteProcessMemory(p, (LPVOID)(data_area + 0x00), &ctx.Rip, 8, &wr2);
        WriteProcessMemory(p, (LPVOID)(data_area + 0x08), &ctx.Rsp, 8, &wr2);

        // Patch the jmp target (last 8 bytes of shellcode)
        size_t sc_size = sc.size();
        for (int i = 0; i < 8; i++)
            sc[sc_size - 8 + i] = (uint8_t)((ctx.Rip >> (i * 8)) & 0xFF);

        WriteProcessMemory(p, (LPVOID)shellcode_addr, sc.data(), sc_size, &wr2);

        info("Hijacking TID=" + std::to_string(tid) +
             " RIP=" + hex_str(ctx.Rip) +
             " (private stack @ " + hex_str(new_stack_top) + ")");

        ctx.Rip = (DWORD64)shellcode_addr;
        // Don't change RSP — the shellcode switches to its own stack

        if (SetThreadContext(h, &ctx)) {
            ResumeThread(h);
            info("Thread hijacked! DLL runs on private stack, original stack untouched.");
            success = true;
        } else {
            ResumeThread(h);
            warn("SetThreadContext failed for TID=" + std::to_string(tid));
        }
        CloseHandle(h);
    }

    if (!success) {
        VirtualFreeEx(p, sc_mem, 0, MEM_RELEASE);
    }
    return success;
}

// ---- Standard stuff ----

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
    if (base == pref) { return true; }
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

// ==== MAIN ====

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
    protect_sections(p, base, pe);

    uintptr_t entry = pe.nt->OptionalHeader.AddressOfEntryPoint;
    if (entry == 0) { warn("No entry point"); CloseHandle(p); return true; }
    info("Entry point RVA: " + hex_str(entry));

    // Method 1: APC injection — cleanest, doesn't corrupt threads
    info("Trying APC injection (clean, alertable threads)...");
    if (inject_via_apc(p, pid, base, entry)) {
        info("DLL injected via APC!");
        info("DLL mapped at " + hex_str(base));
        info("APCs fire when threads enter alertable wait (message pump, SleepEx, etc.)");
        CloseHandle(p);
        return true;
    }

    // Method 2: Hijack with private stack — doesn't corrupt original thread
    warn("APC failed, trying hijack with private stack...");
    if (inject_via_hijack(p, pid, base, entry)) {
        info("DLL injected via hijack (private stack)!");
        info("DLL mapped at " + hex_str(base));
        CloseHandle(p);
        return true;
    }

    CloseHandle(p);
    warn("All injection methods failed.");
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
        std::wcout << L"Manual Map Injector (APC + hijack)\n\n"
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
