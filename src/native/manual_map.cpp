// manual_map.cpp - NtCreateThreadEx injector with TLS, remote LoadLibrary, proper memory protection.
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

// Force-load a DLL inside the target process via CreateRemoteThread(LoadLibraryW).
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

// Shellcode: for each callback in order, call callback(base, DLL_PROCESS_ATTACH, NULL).
// TLS callbacks first, then DLL entry point.
std::vector<uint8_t> build_shellcode(const std::vector<uintptr_t>& callbacks, uintptr_t dll_base){
    std::vector<uint8_t> sc;
    auto emit = [&](std::initializer_list<uint8_t> bs){ for(uint8_t x:bs) sc.push_back(x); };
    emit({0x48,0x83,0xEC,0x28}); // sub rsp, 0x28
    for(uintptr_t cb : callbacks){
        emit({0x48,0xB9});                                          // mov rcx, imm64
        for(int i=0;i<8;i++) sc.push_back((uint8_t)(dll_base>>(i*8)));
        emit({0xBA,0x01,0x00,0x00,0x00});                           // mov edx, 1 (DLL_PROCESS_ATTACH)
        emit({0x45,0x31,0xC0});                                     // xor r8d, r8d
        emit({0x48,0xB8});                                          // mov rax, imm64
        for(int i=0;i<8;i++) sc.push_back((uint8_t)(cb>>(i*8)));
        emit({0xFF,0xD0});                                          // call rax
    }
    emit({0x48,0x83,0xC4,0x28}); // add rsp, 0x28
    emit({0xC3});                // ret
    return sc;
}

typedef LONG (NTAPI* NtCreateThreadEx_t)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);

bool inject_thread(HANDLE p, uintptr_t shellcode_addr, uintptr_t base){
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    NtCreateThreadEx_t fn = ntdll ? (NtCreateThreadEx_t)GetProcAddress(ntdll,"NtCreateThreadEx") : nullptr;
    if(fn){
        HANDLE ht = NULL;
        // flag 4 = THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
        LONG st = fn(&ht, THREAD_ALL_ACCESS, NULL, p, (PVOID)shellcode_addr, (PVOID)base, 4, 0, 0, 0, NULL);
        if(st>=0 && ht){
            info("Thread OK (HIDE_FROM_DEBUGGER)");
            CloseHandle(ht);
            return true;
        }
        warn("NtCreateThreadEx failed, falling back to CreateRemoteThread");
    }
    HANDLE t = CreateRemoteThread(p, NULL, 0, (LPTHREAD_START_ROUTINE)shellcode_addr, (PVOID)base, 0, NULL);
    if(!t) return false;
    info("CreateRemoteThread OK");
    CloseHandle(t);
    return true;
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
                desc++; continue; // skip this descriptor; might still work if function unused
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
    // Headers: read-only
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

// Walk IMAGE_DIRECTORY_ENTRY_TLS and return list of remote callback addresses.
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

bool manual_map(DWORD pid, const std::wstring& dll_path){
    PeData pe;
    if(!load_pe(dll_path, pe)){ err("Bad PE"); return false; }
    info("DLL: "+std::to_string(pe.image_size)+"B "+std::to_string(pe.nt->FileHeader.NumberOfSections)+" sec");

    HANDLE p = OpenProcess(PROCESS_ALL_ACCESS_FLAGS, FALSE, pid);
    if(!p){ err("OpenProcess"); return false; }
    info("PID "+std::to_string(pid));

    // Allocate as RW first (no execute bit) - reduces AV/EDR signal vs RWX up-front.
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

    // Gather TLS callbacks, then DLL entry point. Call them in this order with DllMain semantics.
    auto callbacks = collect_tls_callbacks(base, pe);
    if(!callbacks.empty()) info("TLS callbacks: "+std::to_string(callbacks.size()));
    uintptr_t entry = pe.nt->OptionalHeader.AddressOfEntryPoint;
    if(entry != 0) callbacks.push_back(base + entry);
    if(callbacks.empty()){ warn("No entry point and no TLS callbacks"); CloseHandle(p); return true; }

    // Stage shellcode in its own page: RW -> write -> RX (no RWX in memory map at any point).
    auto sc = build_shellcode(callbacks, base);
    LPVOID sc_mem = VirtualAllocEx(p, NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if(!sc_mem){ err("VirtualAllocEx (shellcode)"); CloseHandle(p); return false; }
    WriteProcessMemory(p, sc_mem, sc.data(), sc.size(), &wr);
    DWORD old;
    VirtualProtectEx(p, sc_mem, 0x1000, PAGE_EXECUTE_READ, &old);

    info("NtCreateThreadEx (HIDE_FROM_DEBUGGER)...");
    if(inject_thread(p, (uintptr_t)sc_mem, base)){
        info("SUCCESS! DLL @ "+hex_str(base)+" (shellcode @ "+hex_str((uintptr_t)sc_mem)+")");
        CloseHandle(p);
        return true;
    }
    CloseHandle(p);
    return false;
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
        std::wcout << L"Manual Map Injector\nUsage: manual_map.exe <dll> --process <name>\n";
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
