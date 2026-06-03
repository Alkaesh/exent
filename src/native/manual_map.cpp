// manual_map.cpp - Thread-hijack manual mapper.
// No new threads created in target process: hijacks existing thread's RIP,
// runs TLS + DllMain on a private stack, restores full context, jumps back.
// Compile: g++ -std=c++17 -O2 -m64 -municode manual_map.cpp -static -o manual_map.exe

#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>

static const DWORD PROCESS_ALL_ACCESS_FLAGS = 0x001FFFFF;

void info(const std::string& m){ std::cout<<"[+] "<<m<<std::endl; }
void warn(const std::string& m){ std::cout<<"[!] "<<m<<std::endl; }
void err (const std::string& m){ std::cerr<<"[ERROR] "<<m<<" (GLE=0x"<<std::hex<<GetLastError()<<std::dec<<")"<<std::endl; }
std::string hex_str(uintptr_t v){ char b[32]; snprintf(b,sizeof(b),"0x%llx",(unsigned long long)v); return b; }

DWORD find_pid(const std::wstring& name){
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(s==INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W e{sizeof(e)};
    if(!Process32FirstW(s,&e)){ CloseHandle(s); return 0; }
    do {
        if(_wcsicmp(e.szExeFile,name.c_str())==0){ CloseHandle(s); return e.th32ProcessID; }
    } while(Process32NextW(s,&e));
    CloseHandle(s);
    return 0;
}

uintptr_t remote_module_base(DWORD pid,const std::string& name_lower){
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);
    if(s==INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W e{sizeof(e)};
    if(!Module32FirstW(s,&e)){ CloseHandle(s); return 0; }
    do {
        std::string mn;
        for(int i=0; e.szModule[i]; i++){
            char c = (char)(e.szModule[i]<128 ? e.szModule[i] : '?');
            mn.push_back((char)tolower(c));
        }
        if(mn==name_lower){ uintptr_t b=(uintptr_t)e.modBaseAddr; CloseHandle(s); return b; }
    } while(Module32NextW(s,&e));
    CloseHandle(s);
    return 0;
}

bool remote_load_library(HANDLE p, const std::wstring& dll_name){
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if(!k32) return false;
    FARPROC fn = GetProcAddress(k32,"LoadLibraryW");
    if(!fn) return false;
    SIZE_T sz = (dll_name.size()+1)*sizeof(wchar_t);
    LPVOID buf = VirtualAllocEx(p,NULL,sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!buf) return false;
    SIZE_T wr;
    if(!WriteProcessMemory(p,buf,dll_name.c_str(),sz,&wr)){ VirtualFreeEx(p,buf,0,MEM_RELEASE); return false; }
    HANDLE t = CreateRemoteThread(p,NULL,0,(LPTHREAD_START_ROUTINE)fn,buf,0,NULL);
    if(!t){ VirtualFreeEx(p,buf,0,MEM_RELEASE); return false; }
    WaitForSingleObject(t,5000);
    DWORD ec = 0; GetExitCodeThread(t,&ec);
    CloseHandle(t);
    VirtualFreeEx(p,buf,0,MEM_RELEASE);
    return ec != 0;
}

const char* resolve_api_set(const char* n){
    if(strstr(n,"api-ms-win-crt-")||strstr(n,"api-ms-win-core-")) return "ucrtbase.dll";
    return n;
}

struct PeData {
    std::vector<uint8_t> raw;
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS64* nt;
    IMAGE_SECTION_HEADER* sections;
    size_t image_size;
};

uintptr_t rva_to_file_offset(DWORD rva, const PeData& pe){
    for(int i=0; i<pe.nt->FileHeader.NumberOfSections; i++){
        auto& s = pe.sections[i];
        if(rva>=s.VirtualAddress && rva<s.VirtualAddress+s.Misc.VirtualSize)
            return rva - s.VirtualAddress + s.PointerToRawData;
    }
    if(rva<pe.nt->OptionalHeader.SizeOfHeaders) return rva;
    return rva;
}

bool load_pe(const std::wstring& path, PeData& pe){
    std::ifstream f(path.c_str(), std::ios::binary|std::ios::ate);
    if(!f) return false;
    size_t size = f.tellg(); f.seekg(0);
    pe.raw.resize(size);
    f.read((char*)pe.raw.data(), size);
    pe.dos = (IMAGE_DOS_HEADER*)pe.raw.data();
    if(pe.dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    pe.nt = (IMAGE_NT_HEADERS64*)(pe.raw.data() + pe.dos->e_lfanew);
    if(pe.nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if(pe.nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;
    pe.sections = IMAGE_FIRST_SECTION(pe.nt);
    pe.image_size = pe.nt->OptionalHeader.SizeOfImage;
    return true;
}

// Build hijack shellcode:
//   1) save all GPRs + rflags to save_area
//   2) switch rsp to private stack
//   3) for each callback: call cb(base, DLL_PROCESS_ATTACH=1, NULL)
//   4) restore all GPRs + rflags + rsp from save_area
//   5) jmp back to original_rip via r11 (volatile per MS x64 ABI, expendable)
std::vector<uint8_t> build_hijack_shellcode(
    const std::vector<uintptr_t>& callbacks,
    uintptr_t dll_base,
    uintptr_t save_area_addr,
    uintptr_t stack_top_addr,
    uintptr_t original_rip)
{
    std::vector<uint8_t> sc;
    auto emit  = [&](std::initializer_list<uint8_t> bs){ for(uint8_t x:bs) sc.push_back(x); };
    auto emit64 = [&](uint64_t v){ for(int i=0;i<8;i++) sc.push_back((uint8_t)(v>>(i*8))); };

    // mov r11, save_area_addr
    emit({0x49, 0xBB}); emit64(save_area_addr);

    // Save GPRs (r11 itself is the scratch reg used to address save_area; not preserved).
    // Layout: rax=00 rcx=08 rdx=10 rbx=18 rsp=20 rbp=28 rsi=30 rdi=38
    //         r8=40  r9=48  r10=50 r12=58 r13=60 r14=68 r15=70 rflags=78
    emit({0x49, 0x89, 0x43, 0x00}); // mov [r11+0x00], rax
    emit({0x49, 0x89, 0x4B, 0x08}); // mov [r11+0x08], rcx
    emit({0x49, 0x89, 0x53, 0x10}); // mov [r11+0x10], rdx
    emit({0x49, 0x89, 0x5B, 0x18}); // mov [r11+0x18], rbx
    emit({0x49, 0x89, 0x63, 0x20}); // mov [r11+0x20], rsp
    emit({0x49, 0x89, 0x6B, 0x28}); // mov [r11+0x28], rbp
    emit({0x49, 0x89, 0x73, 0x30}); // mov [r11+0x30], rsi
    emit({0x49, 0x89, 0x7B, 0x38}); // mov [r11+0x38], rdi
    emit({0x4D, 0x89, 0x43, 0x40}); // mov [r11+0x40], r8
    emit({0x4D, 0x89, 0x4B, 0x48}); // mov [r11+0x48], r9
    emit({0x4D, 0x89, 0x53, 0x50}); // mov [r11+0x50], r10
    emit({0x4D, 0x89, 0x63, 0x58}); // mov [r11+0x58], r12
    emit({0x4D, 0x89, 0x6B, 0x60}); // mov [r11+0x60], r13
    emit({0x4D, 0x89, 0x73, 0x68}); // mov [r11+0x68], r14
    emit({0x4D, 0x89, 0x7B, 0x70}); // mov [r11+0x70], r15
    // rflags via pushfq / pop rax / mov [r11+0x78], rax
    emit({0x9C});                   // pushfq
    emit({0x58});                   // pop rax
    emit({0x49, 0x89, 0x43, 0x78}); // mov [r11+0x78], rax

    // mov rsp, stack_top_addr (switch to our private stack)
    emit({0x48, 0xBC}); emit64(stack_top_addr);

    // For each callback: sub rsp,0x28 / mov rcx,base / mov edx,1 / xor r8d,r8d / mov rax,cb / call rax / add rsp,0x28
    for(uintptr_t cb : callbacks){
        emit({0x48, 0x83, 0xEC, 0x28});                         // sub rsp, 0x28
        emit({0x48, 0xB9}); emit64(dll_base);                   // mov rcx, dll_base
        emit({0xBA, 0x01, 0x00, 0x00, 0x00});                   // mov edx, 1
        emit({0x45, 0x31, 0xC0});                               // xor r8d, r8d
        emit({0x48, 0xB8}); emit64(cb);                         // mov rax, callback
        emit({0xFF, 0xD0});                                     // call rax
        emit({0x48, 0x83, 0xC4, 0x28});                         // add rsp, 0x28
    }

    // RESTORE. Re-load r11 in case a callback clobbered it.
    emit({0x49, 0xBB}); emit64(save_area_addr);

    // Restore rflags first (push rax / popfq while still on private stack)
    emit({0x49, 0x8B, 0x43, 0x78}); // mov rax, [r11+0x78]
    emit({0x50});                   // push rax
    emit({0x9D});                   // popfq

    // Restore GPRs (rsp restored last; r11 not restored)
    emit({0x4D, 0x8B, 0x7B, 0x70}); // mov r15, [r11+0x70]
    emit({0x4D, 0x8B, 0x73, 0x68}); // mov r14, [r11+0x68]
    emit({0x4D, 0x8B, 0x6B, 0x60}); // mov r13, [r11+0x60]
    emit({0x4D, 0x8B, 0x63, 0x58}); // mov r12, [r11+0x58]
    emit({0x4D, 0x8B, 0x53, 0x50}); // mov r10, [r11+0x50]
    emit({0x4D, 0x8B, 0x4B, 0x48}); // mov r9,  [r11+0x48]
    emit({0x4D, 0x8B, 0x43, 0x40}); // mov r8,  [r11+0x40]
    emit({0x49, 0x8B, 0x7B, 0x38}); // mov rdi, [r11+0x38]
    emit({0x49, 0x8B, 0x73, 0x30}); // mov rsi, [r11+0x30]
    emit({0x49, 0x8B, 0x6B, 0x28}); // mov rbp, [r11+0x28]
    emit({0x49, 0x8B, 0x5B, 0x18}); // mov rbx, [r11+0x18]
    emit({0x49, 0x8B, 0x53, 0x10}); // mov rdx, [r11+0x10]
    emit({0x49, 0x8B, 0x4B, 0x08}); // mov rcx, [r11+0x08]
    emit({0x49, 0x8B, 0x43, 0x00}); // mov rax, [r11+0x00]
    emit({0x49, 0x8B, 0x63, 0x20}); // mov rsp, [r11+0x20]   <-- back to victim stack

    // mov r11, original_rip ; jmp r11
    emit({0x49, 0xBB}); emit64(original_rip);
    emit({0x41, 0xFF, 0xE3});

    return sc;
}

bool resolve_imports(HANDLE p, DWORD pid, uintptr_t base, PeData& pe){
    auto& dir = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(dir.Size == 0) return true;
    auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(pe.raw.data() + rva_to_file_offset(dir.VirtualAddress, pe));
    while(desc->Name != 0){
        const char* dn = (const char*)(pe.raw.data() + rva_to_file_offset(desc->Name, pe));
        const char* rn = resolve_api_set(dn);
        std::string rl;
        for(const char* c=rn; *c; c++) rl.push_back((char)tolower(*c));

        uintptr_t rdb = remote_module_base(pid, rl);
        if(!rdb){
            warn("Module not loaded in target, calling LoadLibrary remotely: "+rl);
            std::wstring wname(rl.begin(), rl.end());
            if(remote_load_library(p, wname)){
                rdb = remote_module_base(pid, rl);
            }
            if(!rdb){
                err("Failed to load "+std::string(rn)+" in target process");
                desc++; continue;
            }
        }

        HMODULE hm = LoadLibraryA(rn);
        if(!hm){ err("LoadLibraryA failed for "+std::string(rn)); desc++; continue; }
        info("  "+std::string(dn)+" -> "+rn);

        auto* og = desc->OriginalFirstThunk
            ? (IMAGE_THUNK_DATA64*)(pe.raw.data() + rva_to_file_offset(desc->OriginalFirstThunk, pe))
            : (IMAGE_THUNK_DATA64*)(pe.raw.data() + rva_to_file_offset(desc->FirstThunk, pe));
        uintptr_t lb = (uintptr_t)hm;

        DWORD thunk_idx = 0;
        while(og->u1.AddressOfData != 0){
            uintptr_t lf = 0;
            if(og->u1.Ordinal & IMAGE_ORDINAL_FLAG64){
                lf = (uintptr_t)GetProcAddress(hm, MAKEINTRESOURCEA(og->u1.Ordinal & 0xFFFF));
            } else {
                auto* nb = (IMAGE_IMPORT_BY_NAME*)(pe.raw.data() + rva_to_file_offset((DWORD)og->u1.AddressOfData, pe));
                lf = (uintptr_t)GetProcAddress(hm, nb->Name);
            }
            if(lf){
                uintptr_t rf = rdb + (lf - lb);
                uintptr_t target_addr = base + desc->FirstThunk + (uintptr_t)thunk_idx * sizeof(IMAGE_THUNK_DATA64);
                SIZE_T wr;
                WriteProcessMemory(p, (PVOID)target_addr, &rf, sizeof(rf), &wr);
            }
            og++; thunk_idx++;
        }
        FreeLibrary(hm);
        desc++;
    }
    return true;
}

bool apply_relocs(HANDLE p, uintptr_t base, PeData& pe){
    uintptr_t pref = pe.nt->OptionalHeader.ImageBase;
    if(base == pref) return true;
    intptr_t delta = (intptr_t)(base - pref);
    auto& dir = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if(dir.Size == 0){
        err("DLL has no relocations and remote base differs from preferred");
        return false;
    }
    auto* blk = (IMAGE_BASE_RELOCATION*)(pe.raw.data() + rva_to_file_offset(dir.VirtualAddress, pe));
    uint8_t* en = pe.raw.data() + rva_to_file_offset(dir.VirtualAddress, pe) + dir.Size;
    while((uint8_t*)blk < en && blk->SizeOfBlock > 0){
        DWORD cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* e = (WORD*)(blk + 1);
        for(DWORD i=0; i<cnt; i++){
            if((e[i] >> 12) != IMAGE_REL_BASED_DIR64) continue;
            uintptr_t a = base + blk->VirtualAddress + (e[i] & 0xFFF);
            uintptr_t v = 0; SIZE_T rd;
            ReadProcessMemory(p, (PVOID)a, &v, sizeof(v), &rd);
            v += delta;
            SIZE_T wr;
            WriteProcessMemory(p, (PVOID)a, &v, sizeof(v), &wr);
        }
        blk = (IMAGE_BASE_RELOCATION*)((uint8_t*)blk + blk->SizeOfBlock);
    }
    info("Relocs applied");
    return true;
}

void protect_sections(HANDLE p, uintptr_t base, PeData& pe){
    DWORD old;
    VirtualProtectEx(p, (PVOID)base, pe.nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old);
    for(int i=0; i<pe.nt->FileHeader.NumberOfSections; i++){
        auto& s = pe.sections[i];
        if(s.Misc.VirtualSize == 0) continue;
        bool x = s.Characteristics & IMAGE_SCN_MEM_EXECUTE;
        bool r = s.Characteristics & IMAGE_SCN_MEM_READ;
        bool w = s.Characteristics & IMAGE_SCN_MEM_WRITE;
        DWORD prot = PAGE_NOACCESS;
        if(x && w)        prot = PAGE_EXECUTE_READWRITE;
        else if(x && r)   prot = PAGE_EXECUTE_READ;
        else if(x)        prot = PAGE_EXECUTE;
        else if(w)        prot = PAGE_READWRITE;
        else if(r)        prot = PAGE_READONLY;
        VirtualProtectEx(p, (PVOID)(base + s.VirtualAddress), s.Misc.VirtualSize, prot, &old);
    }
}

std::vector<uintptr_t> collect_tls_callbacks(uintptr_t base, PeData& pe){
    std::vector<uintptr_t> result;
    auto& dir = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if(dir.Size == 0) return result;
    auto* tls = (IMAGE_TLS_DIRECTORY64*)(pe.raw.data() + rva_to_file_offset(dir.VirtualAddress, pe));
    if(tls->AddressOfCallBacks == 0) return result;
    uintptr_t pref = pe.nt->OptionalHeader.ImageBase;
    uintptr_t cb_rva = (uintptr_t)tls->AddressOfCallBacks - pref;
    auto* cb_arr = (uintptr_t*)(pe.raw.data() + rva_to_file_offset((DWORD)cb_rva, pe));
    while(*cb_arr){
        uintptr_t cb_va = *cb_arr;
        uintptr_t cb_rva2 = cb_va - pref;
        result.push_back(base + cb_rva2);
        cb_arr++;
    }
    return result;
}

struct HijackTarget {
    HANDLE handle;
    DWORD  tid;
    uintptr_t original_rip;
};

// Find a thread we can suspend and redirect.
// Pass 0: prefer threads with Rip outside ntdll (i.e. actively running user code,
//         not waiting in a syscall - faster activation of our shellcode).
// Pass 1: take any suspendable thread.
bool find_hijack_target(DWORD pid, HijackTarget& out){
    uintptr_t ntdll_base = remote_module_base(pid, "ntdll.dll");
    for(int pass = 0; pass < 2; pass++){
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if(snap == INVALID_HANDLE_VALUE) return false;
        THREADENTRY32 te{sizeof(te)};
        if(!Thread32First(snap, &te)){ CloseHandle(snap); continue; }
        do {
            if(te.th32OwnerProcessID != pid) continue;
            HANDLE t = OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                FALSE, te.th32ThreadID);
            if(!t) continue;
            DWORD prev_suspend = SuspendThread(t);
            if(prev_suspend == (DWORD)-1){ CloseHandle(t); continue; }
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_FULL;
            if(!GetThreadContext(t, &ctx)){
                ResumeThread(t); CloseHandle(t); continue;
            }
            if(pass == 0 && ntdll_base &&
               ctx.Rip >= ntdll_base && ctx.Rip < ntdll_base + 0x300000){
                ResumeThread(t); CloseHandle(t); continue;
            }
            out.handle = t;
            out.tid = te.th32ThreadID;
            out.original_rip = (uintptr_t)ctx.Rip;
            CloseHandle(snap);
            return true;
        } while(Thread32Next(snap, &te));
        CloseHandle(snap);
    }
    return false;
}

bool manual_map(DWORD pid, const std::wstring& dll_path){
    PeData pe;
    if(!load_pe(dll_path, pe)){ err("Bad PE"); return false; }
    info("DLL: "+std::to_string(pe.image_size)+"B "+std::to_string(pe.nt->FileHeader.NumberOfSections)+" sec");

    HANDLE p = OpenProcess(PROCESS_ALL_ACCESS_FLAGS, FALSE, pid);
    if(!p){ err("OpenProcess"); return false; }
    info("PID "+std::to_string(pid));

    LPVOID mem = VirtualAllocEx(p, NULL, pe.image_size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if(!mem){ err("VirtualAllocEx (image)"); CloseHandle(p); return false; }
    uintptr_t base = (uintptr_t)mem;
    info("@ "+hex_str(base));

    SIZE_T wr;
    WriteProcessMemory(p, mem, pe.raw.data(), pe.nt->OptionalHeader.SizeOfHeaders, &wr);
    for(int i=0; i<pe.nt->FileHeader.NumberOfSections; i++){
        auto& s = pe.sections[i];
        if(s.SizeOfRawData == 0) continue;
        WriteProcessMemory(p, (PVOID)(base + s.VirtualAddress),
                           pe.raw.data() + s.PointerToRawData, s.SizeOfRawData, &wr);
    }

    if(!apply_relocs(p, base, pe)){ CloseHandle(p); return false; }
    if(!resolve_imports(p, pid, base, pe)){ CloseHandle(p); return false; }
    protect_sections(p, base, pe);

    auto callbacks = collect_tls_callbacks(base, pe);
    if(!callbacks.empty()) info("TLS callbacks: "+std::to_string(callbacks.size()));
    uintptr_t entry = pe.nt->OptionalHeader.AddressOfEntryPoint;
    if(entry != 0) callbacks.push_back(base + entry);
    if(callbacks.empty()){ warn("No entry point and no TLS callbacks"); CloseHandle(p); return true; }

    // Allocate save area + private 128KB stack as one RW region.
    // Layout: [save_area 0x100][padding][private stack growing down from top].
    const SIZE_T DATA_SIZE = 0x20000; // 128KB
    LPVOID data_mem = VirtualAllocEx(p, NULL, DATA_SIZE, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if(!data_mem){ err("VirtualAllocEx (data)"); CloseHandle(p); return false; }
    uintptr_t save_area = (uintptr_t)data_mem;
    uintptr_t stack_top = (uintptr_t)data_mem + DATA_SIZE;
    info("Save+stack @ "+hex_str((uintptr_t)data_mem));

    // Find and suspend a hijack target.
    HijackTarget tgt{};
    info("Searching for hijack target...");
    if(!find_hijack_target(pid, tgt)){
        err("No hijackable thread found");
        CloseHandle(p); return false;
    }
    info("Hijacking TID "+std::to_string(tgt.tid)+" orig Rip="+hex_str(tgt.original_rip));

    // Build shellcode with original_rip baked in.
    auto sc = build_hijack_shellcode(callbacks, base, save_area, stack_top, tgt.original_rip);

    // Allocate shellcode page (RW), write, then promote to RX.
    SIZE_T sc_size = (sc.size() + 0xFFF) & ~SIZE_T(0xFFF);
    if(sc_size < 0x1000) sc_size = 0x1000;
    LPVOID sc_mem = VirtualAllocEx(p, NULL, sc_size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if(!sc_mem){
        err("VirtualAllocEx (shellcode)");
        ResumeThread(tgt.handle); CloseHandle(tgt.handle); CloseHandle(p); return false;
    }
    if(!WriteProcessMemory(p, sc_mem, sc.data(), sc.size(), &wr) || wr != sc.size()){
        err("WriteProcessMemory (shellcode)");
        ResumeThread(tgt.handle); CloseHandle(tgt.handle); CloseHandle(p); return false;
    }
    DWORD old;
    if(!VirtualProtectEx(p, sc_mem, sc_size, PAGE_EXECUTE_READ, &old)){
        err("VirtualProtectEx (shellcode RX)");
        ResumeThread(tgt.handle); CloseHandle(tgt.handle); CloseHandle(p); return false;
    }
    info("Shellcode @ "+hex_str((uintptr_t)sc_mem)+" ("+std::to_string(sc.size())+" bytes)");

    // Re-fetch context and redirect Rip.
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if(!GetThreadContext(tgt.handle, &ctx)){
        err("GetThreadContext (refresh)");
        ResumeThread(tgt.handle); CloseHandle(tgt.handle); CloseHandle(p); return false;
    }
    if((uintptr_t)ctx.Rip != tgt.original_rip){
        warn("Thread Rip changed between find and redirect (was "+hex_str(tgt.original_rip)+
             ", now "+hex_str((uintptr_t)ctx.Rip)+"); rebuilding shellcode");
        // Rebuild shellcode with the new original_rip and rewrite. Temporarily RW.
        VirtualProtectEx(p, sc_mem, sc_size, PAGE_READWRITE, &old);
        sc = build_hijack_shellcode(callbacks, base, save_area, stack_top, (uintptr_t)ctx.Rip);
        WriteProcessMemory(p, sc_mem, sc.data(), sc.size(), &wr);
        VirtualProtectEx(p, sc_mem, sc_size, PAGE_EXECUTE_READ, &old);
    }
    ctx.Rip = (DWORD64)(uintptr_t)sc_mem;
    if(!SetThreadContext(tgt.handle, &ctx)){
        err("SetThreadContext");
        ResumeThread(tgt.handle); CloseHandle(tgt.handle); CloseHandle(p); return false;
    }
    info("Rip redirected to shellcode");
    if(ResumeThread(tgt.handle) == (DWORD)-1){
        err("ResumeThread");
        CloseHandle(tgt.handle); CloseHandle(p); return false;
    }
    CloseHandle(tgt.handle);

    info("SUCCESS! DLL @ "+hex_str(base)+" (hijacked TID "+std::to_string(tgt.tid)+")");
    CloseHandle(p);
    return true;
}

bool is_x64_dll(const std::wstring& path){
    std::ifstream f(path.c_str(), std::ios::binary);
    if(!f) return false;
    IMAGE_DOS_HEADER dos;
    f.read((char*)&dos, sizeof(dos));
    if(dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
    f.seekg(dos.e_lfanew);
    DWORD sig; f.read((char*)&sig, sizeof(sig));
    if(sig != IMAGE_NT_SIGNATURE) return false;
    IMAGE_FILE_HEADER fh; f.read((char*)&fh, sizeof(fh));
    WORD magic; f.read((char*)&magic, sizeof(magic));
    return magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

bool is_x64_process(DWORD pid){
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if(!h) return false;
    BOOL w = FALSE;
    IsWow64Process(h, &w);
    CloseHandle(h);
    return !w;
}

int wmain(int argc, wchar_t* argv[]){
    if(argc < 3){
        std::wcout << L"Manual Map Injector (thread hijack)\nUsage: manual_map.exe <dll> --process <name>\n";
        return 1;
    }
    std::wstring dll;
    DWORD pid = 0;
    std::wstring pname;
    for(int i=1; i<argc; ++i){
        std::wstring a = argv[i];
        if(a == L"--pid" && i+1 < argc)         pid = _wtoi(argv[++i]);
        else if(a == L"--process" && i+1 < argc) pname = argv[++i];
        else if(dll.empty())                     dll = argv[i];
    }
    if(dll.empty()){ std::cerr<<"DLL path required"<<std::endl; return 1; }
    if(!pid){
        pid = find_pid(pname);
        if(!pid){ std::cerr<<"Process not found"<<std::endl; return 1; }
    }

    bool dll64 = is_x64_dll(dll);
    bool proc64 = is_x64_process(pid);
    std::wcout << L"\nArch: DLL=" << (dll64?L"64":L"32")
               << L" Proc="      << (proc64?L"64":L"32") << std::endl;
    if(dll64 != proc64){
        std::cerr << "[ERROR] Architecture mismatch - aborting" << std::endl;
        return 1;
    }

    if(!manual_map(pid, dll)){
        std::cerr << "FAILED." << std::endl;
        return 1;
    }
    std::wcout << L"\nDONE." << std::endl;
    return 0;
}
