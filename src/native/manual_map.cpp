// manual_map.cpp - Thread hijack injector (TlsAlloc + private stack + register safe)
// Compile: g++ -std=c++17 -O2 -m64 -municode manual_map.cpp -static -o manual_map.exe

#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>

typedef int32_t i32;

static const DWORD PROCESS_ALL_ACCESS_FLAGS = 0x001F0FFF;

void die(const char* msg) { DWORD c=GetLastError(); std::cerr<<"[FATAL] "<<msg<<" (code="<<c<<")"<<std::endl; exit(1); }
void info(const std::string& msg) { std::cout<<"[+] "<<msg<<std::endl; }
void warn(const std::string& msg) { std::cout<<"[!] "<<msg<<std::endl; }

std::string hex_str(uintptr_t v) { char b[32]; snprintf(b,sizeof(b),"0x%llx",(unsigned long long)v); return std::string(b); }

DWORD find_pid(const std::wstring& name) {
    HANDLE s=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(s==INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W e{sizeof(e)};
    if(!Process32FirstW(s,&e)){CloseHandle(s);return 0;}
    do{if(_wcsicmp(e.szExeFile,name.c_str())==0){CloseHandle(s);return e.th32ProcessID;}}
    while(Process32NextW(s,&e)); CloseHandle(s); return 0;
}

uintptr_t remote_module_base(DWORD pid,const std::string& nl) {
    HANDLE s=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);
    if(s==INVALID_HANDLE_VALUE)return 0;
    MODULEENTRY32W e{sizeof(e)};
    if(!Module32FirstW(s,&e)){CloseHandle(s);return 0;}
    do{
        std::string mn; for(int i=0;e.szModule[i];i++){char c=(char)(e.szModule[i]<128?e.szModule[i]:'?');mn.push_back((char)tolower(c));}
        if(mn==nl){uintptr_t b=(uintptr_t)e.modBaseAddr;CloseHandle(s);return b;}
    }while(Module32NextW(s,&e)); CloseHandle(s); return 0;
}

const char* resolve_api_set(const char* n){
    if(strstr(n,"api-ms-win-crt-")||strstr(n,"api-ms-win-core-"))return"ucrtbase.dll";
    return n;
}

struct PeData{std::vector<uint8_t> raw; IMAGE_DOS_HEADER* dos; IMAGE_NT_HEADERS64* nt; IMAGE_SECTION_HEADER* sections; size_t image_size;};

uintptr_t rva_to_ptr(DWORD rva,const PeData& pe){
    for(int i=0;i<pe.nt->FileHeader.NumberOfSections;i++){
        auto& s=pe.sections[i]; if(rva>=s.VirtualAddress&&rva<s.VirtualAddress+s.Misc.VirtualSize)return rva-s.VirtualAddress+s.PointerToRawData;
    }
    if(rva<pe.nt->OptionalHeader.SizeOfHeaders)return rva;
    return rva;
}

void dump_sections(const PeData& pe){
    info("Sections: "+std::to_string(pe.nt->FileHeader.NumberOfSections));
    for(int i=0;i<pe.nt->FileHeader.NumberOfSections;i++){
        auto& s=pe.sections[i];char n[9]={0};memcpy(n,s.Name,8);
        info("  ["+std::to_string(i)+"] \""+std::string(n)+"\" VA="+hex_str(s.VirtualAddress)+" raw="+std::to_string(s.SizeOfRawData));
    }
}

bool load_pe(const std::wstring& path,PeData& pe){
    std::ifstream f(path.c_str(),std::ios::binary|std::ios::ate);
    if(!f)return false;
    size_t size=f.tellg();f.seekg(0);pe.raw.resize(size);f.read((char*)pe.raw.data(),size);
    pe.dos=(IMAGE_DOS_HEADER*)pe.raw.data();
    if(pe.dos->e_magic!=IMAGE_DOS_SIGNATURE)return false;
    pe.nt=(IMAGE_NT_HEADERS64*)(pe.raw.data()+pe.dos->e_lfanew);
    if(pe.nt->Signature!=IMAGE_NT_SIGNATURE)return false;
    if(pe.nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC)return false;
    pe.sections=IMAGE_FIRST_SECTION(pe.nt);
    pe.image_size=pe.nt->OptionalHeader.SizeOfImage;
    return true;
}

std::vector<DWORD> get_threads(DWORD pid){
    std::vector<DWORD> t;
    HANDLE s=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if(s==INVALID_HANDLE_VALUE)return t;
    THREADENTRY32 e{sizeof(e)};
    if(Thread32First(s,&e)){do{if(e.th32OwnerProcessID==pid)t.push_back(e.th32ThreadID);}while(Thread32Next(s,&e));}
    CloseHandle(s); return t;
}

// ---- Shellcode helpers ----

static void emit_mov_rip_rel(std::vector<uint8_t>& sc, uintptr_t sc_base, uintptr_t target, uint8_t prefix, uint8_t modrm) {
    uintptr_t rip_after = sc_base + sc.size() + 7;
    int32_t disp = (int32_t)(target - rip_after);
    if(prefix) sc.push_back(prefix);
    sc.push_back(0x89); sc.push_back(modrm);
    for(int i=0;i<4;i++) sc.push_back((uint8_t)(disp>>(i*8)));
}

static void emit_ld_rip_rel(std::vector<uint8_t>& sc, uintptr_t sc_base, uintptr_t target, uint8_t prefix, uint8_t modrm) {
    uintptr_t rip_after = sc_base + sc.size() + 7;
    int32_t disp = (int32_t)(target - rip_after);
    if(prefix) sc.push_back(prefix);
    sc.push_back(0x8B); sc.push_back(modrm);
    for(int i=0;i<4;i++) sc.push_back((uint8_t)(disp>>(i*8)));
}

static void emit_eax_to_rip(std::vector<uint8_t>& sc, uintptr_t sc_base, uintptr_t target) {
    uintptr_t rip_after = sc_base + sc.size() + 6;
    int32_t d = (int32_t)(target - rip_after);
    sc.push_back(0x89); sc.push_back(0x05);
    for(int i=0;i<4;i++) sc.push_back((uint8_t)(d>>(i*8)));
}

static void emit_pushfq_pop_rip(std::vector<uint8_t>& sc, uintptr_t sc_base, uintptr_t target) {
    sc.push_back(0x9C);
    uintptr_t rip_after = sc_base + sc.size() + 7;
    int32_t d = (int32_t)(target - rip_after);
    sc.push_back(0x8F); sc.push_back(0x05);
    for(int i=0;i<4;i++) sc.push_back((uint8_t)(d>>(i*8)));
}

static void emit_push_rip_pop_rflags(std::vector<uint8_t>& sc, uintptr_t sc_base, uintptr_t target) {
    uintptr_t rip_after = sc_base + sc.size() + 7;
    int32_t d = (int32_t)(target - rip_after);
    sc.push_back(0xFF); sc.push_back(0x35);
    for(int i=0;i<4;i++) sc.push_back((uint8_t)(d>>(i*8)));
    sc.push_back(0x9D);
}

std::vector<uint8_t> build_hijack_shellcode(uintptr_t data_area) {
    uintptr_t save_rax  = data_area + 0x00;
    uintptr_t save_rcx  = data_area + 0x08;
    uintptr_t save_rdx  = data_area + 0x10;
    uintptr_t save_r8   = data_area + 0x18;
    uintptr_t save_r9   = data_area + 0x20;
    uintptr_t save_r10  = data_area + 0x28;
    uintptr_t save_r11  = data_area + 0x30;
    uintptr_t save_rfl  = data_area + 0x38;
    uintptr_t orig_rip  = data_area + 0x40;
    uintptr_t orig_rsp  = data_area + 0x48;
    uintptr_t addr_idx  = data_area + 0x1000;
    uintptr_t addr_base = data_area + 0x1008;
    uintptr_t addr_entry= data_area + 0x1010;
    uintptr_t addr_tlsa = data_area + 0x1018;
    uintptr_t priv_stack= data_area + 0x3000;
    uintptr_t sc_base   = data_area + 0x100;

    std::vector<uint8_t> sc;

    // Save rax
    sc.push_back(0x48); sc.push_back(0xA3);
    for(int i=0;i<8;i++) sc.push_back((uint8_t)(save_rax>>(i*8)));
    // Save rcx, rdx, r8-r11
    emit_mov_rip_rel(sc, sc_base, save_rcx, 0x48, 0x0D);
    emit_mov_rip_rel(sc, sc_base, save_rdx, 0x48, 0x15);
    emit_mov_rip_rel(sc, sc_base, save_r8,  0x4C, 0x05);
    emit_mov_rip_rel(sc, sc_base, save_r9,  0x4C, 0x0D);
    emit_mov_rip_rel(sc, sc_base, save_r10, 0x4C, 0x15);
    emit_mov_rip_rel(sc, sc_base, save_r11, 0x4C, 0x1D);
    // Save rflags
    emit_pushfq_pop_rip(sc, sc_base, save_rfl);

    // Switch to private stack
    sc.push_back(0x48); sc.push_back(0xBC);
    for(int i=0;i<8;i++) sc.push_back((uint8_t)(priv_stack>>(i*8)));

    // TlsAlloc()
    sc.push_back(0x48); sc.push_back(0x83); sc.push_back(0xEC); sc.push_back(0x28);
    sc.push_back(0x48); sc.push_back(0xA1);
    for(int i=0;i<8;i++) sc.push_back((uint8_t)(addr_tlsa>>(i*8)));
    sc.push_back(0xFF); sc.push_back(0xD0);
    sc.push_back(0x48); sc.push_back(0x83); sc.push_back(0xC4); sc.push_back(0x28);
    // Store TLS index
    emit_eax_to_rip(sc, sc_base, addr_idx);

    // Call DllMainCRTStartup(base, DLL_PROCESS_ATTACH, NULL)
    sc.push_back(0x48); sc.push_back(0x83); sc.push_back(0xEC); sc.push_back(0x28);
    sc.push_back(0x48); sc.push_back(0xA1);
    for(int i=0;i<8;i++) sc.push_back((uint8_t)(addr_base>>(i*8)));
    sc.push_back(0x48); sc.push_back(0x8B); sc.push_back(0xC8);
    sc.push_back(0xBA); sc.push_back(0x01); sc.push_back(0x00); sc.push_back(0x00); sc.push_back(0x00);
    sc.push_back(0x45); sc.push_back(0x31); sc.push_back(0xC0);
    sc.push_back(0x48); sc.push_back(0xA1);
    for(int i=0;i<8;i++) sc.push_back((uint8_t)(addr_entry>>(i*8)));
    sc.push_back(0xFF); sc.push_back(0xD0);
    sc.push_back(0x48); sc.push_back(0x83); sc.push_back(0xC4); sc.push_back(0x28);

    // Restore original stack
    { i32 d=(i32)(orig_rsp-(sc_base+sc.size()+7));
      sc.push_back(0x48); sc.push_back(0x8B); sc.push_back(0x25);
      for(int i=0;i<4;i++) sc.push_back((uint8_t)(d>>(i*8))); }

    // Restore rax
    sc.push_back(0x48); sc.push_back(0xA1);
    for(int i=0;i<8;i++) sc.push_back((uint8_t)(save_rax>>(i*8)));
    // Restore rcx,rdx,r8-r11
    emit_ld_rip_rel(sc, sc_base, save_rcx, 0x48, 0x0D);
    emit_ld_rip_rel(sc, sc_base, save_rdx, 0x48, 0x15);
    emit_ld_rip_rel(sc, sc_base, save_r8,  0x4C, 0x05);
    emit_ld_rip_rel(sc, sc_base, save_r9,  0x4C, 0x0D);
    emit_ld_rip_rel(sc, sc_base, save_r10, 0x4C, 0x15);
    emit_ld_rip_rel(sc, sc_base, save_r11, 0x4C, 0x1D);
    // Restore rflags
    emit_push_rip_pop_rflags(sc, sc_base, save_rfl);

    // Jump to original RIP
    sc.push_back(0xFF); sc.push_back(0x25);
    sc.push_back(0x00); sc.push_back(0x00); sc.push_back(0x00); sc.push_back(0x00);
    for(int i=0;i<8;i++) sc.push_back((uint8_t)(orig_rip>>(i*8)));

    return sc;
}

bool inject_via_hijack(HANDLE p,DWORD pid,uintptr_t base,uintptr_t entry_rva,uintptr_t tls_idx_addr){
    LPVOID mem=VirtualAllocEx(p,nullptr,0x4000,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if(!mem){warn("Hijack alloc failed");return false;}
    uintptr_t da=(uintptr_t)mem;

    auto sc=build_hijack_shellcode(da);

    SIZE_T wr;
    WriteProcessMemory(p,(LPVOID)(da+0x1000),&tls_idx_addr,8,&wr);
    WriteProcessMemory(p,(LPVOID)(da+0x1008),&base,8,&wr);
    uintptr_t ea=base+entry_rva;
    WriteProcessMemory(p,(LPVOID)(da+0x1010),&ea,8,&wr);
    uintptr_t ta=(uintptr_t)TlsAlloc;
    WriteProcessMemory(p,(LPVOID)(da+0x1018),&ta,8,&wr);

    WriteProcessMemory(p,(LPVOID)(da+0x100),sc.data(),sc.size(),&wr);

    std::vector<DWORD> tids=get_threads(pid);
    info(std::to_string(tids.size())+" threads");

    for(int ti=(int)tids.size()-1;ti>=0;ti--){
        DWORD tid=tids[ti];
        HANDLE h=OpenThread(THREAD_ALL_ACCESS,FALSE,tid);
        if(!h)continue;
        if(SuspendThread(h)==(DWORD)-1){CloseHandle(h);continue;}
        CONTEXT ctx={};ctx.ContextFlags=CONTEXT_FULL;
        if(!GetThreadContext(h,&ctx)){ResumeThread(h);CloseHandle(h);continue;}

        WriteProcessMemory(p,(LPVOID)(da+0x40),&ctx.Rip,8,&wr);
        WriteProcessMemory(p,(LPVOID)(da+0x48),&ctx.Rsp,8,&wr);

        info("Hijacking TID="+std::to_string(tid)+" RIP="+hex_str(ctx.Rip));
        ctx.Rip=da+0x100;
        if(SetThreadContext(h,&ctx)){
            ResumeThread(h);CloseHandle(h);
            info("Thread hijacked! DllMain on private stack.");
            return true;
        }
        warn("SetThreadContext failed TID="+std::to_string(tid));
        ResumeThread(h);CloseHandle(h);
    }
    warn("No hijackable thread");
    return false;
}

bool setup_tls(HANDLE p,uintptr_t base,PeData& pe,uintptr_t* out_idx){
    IMAGE_DATA_DIRECTORY& td=pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if(td.Size==0||td.VirtualAddress==0){info("TLS: none");*out_idx=0;return true;}

    uintptr_t tda=base+td.VirtualAddress;
    IMAGE_TLS_DIRECTORY64 tls;SIZE_T rd;
    if(!ReadProcessMemory(p,(LPCVOID)tda,&tls,sizeof(tls),&rd)){warn("TLS: read fail");return false;}

    *out_idx=base+(tls.AddressOfIndex-pe.nt->OptionalHeader.ImageBase);
    info("TLS: index_addr="+hex_str(*out_idx));

    if(tls.StartAddressOfRawData==0){info("TLS: no data");return true;}

    size_t ds=(size_t)(tls.EndAddressOfRawData-tls.StartAddressOfRawData);
    size_t zs=tls.SizeOfZeroFill; size_t tot=ds+zs;
    info("TLS: data="+std::to_string(ds)+" zero="+std::to_string(zs)+" total="+std::to_string(tot));

    LPVOID blk=VirtualAllocEx(p,nullptr,tot,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!blk){warn("TLS: alloc fail");return false;}
    uintptr_t bp=(uintptr_t)blk;

    if(ds>0){
        std::vector<uint8_t> buf(ds);
        uintptr_t src=base+(tls.StartAddressOfRawData-pe.nt->OptionalHeader.ImageBase);
        if(ReadProcessMemory(p,(LPCVOID)src,buf.data(),ds,&rd)){SIZE_T wr;WriteProcessMemory(p,blk,buf.data(),ds,&wr);}
    }
    if(zs>0){std::vector<uint8_t> z(zs,0);SIZE_T wr;WriteProcessMemory(p,(LPVOID)(bp+ds),z.data(),zs,&wr);}

    IMAGE_TLS_DIRECTORY64 pt=tls; pt.StartAddressOfRawData=bp; pt.EndAddressOfRawData=bp+tot; pt.SizeOfZeroFill=0;
    SIZE_T wr;WriteProcessMemory(p,(LPVOID)tda,&pt,sizeof(pt),&wr);
    info("TLS: block @ "+hex_str(bp)+" ("+std::to_string(tot)+" bytes)");
    return true;
}

bool resolve_imports(HANDLE p,DWORD pid,uintptr_t base,PeData& pe){
    auto& dir=pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(dir.Size==0){info("No imports");return true;}
    auto* desc=(IMAGE_IMPORT_DESCRIPTOR*)(pe.raw.data()+rva_to_ptr(dir.VirtualAddress,pe));
    while(desc->Name!=0){
        const char* dn=(const char*)(pe.raw.data()+rva_to_ptr(desc->Name,pe));
        const char* rn=resolve_api_set(dn);
        std::string rl; for(const char*c=rn;*c;c++)rl.push_back((char)tolower(*c));
        uintptr_t rdb=remote_module_base(pid,rl);
        if(!rdb){warn(std::string("Not in target: ")+dn);desc++;continue;}
        HMODULE hm=LoadLibraryA(rn);
        if(!hm){warn(std::string("Can't load: ")+rn);desc++;continue;}
        info("  Import: "+std::string(dn)+" -> "+rn+" @ "+hex_str(rdb));
        auto* tk=(IMAGE_THUNK_DATA64*)(pe.raw.data()+rva_to_ptr(desc->FirstThunk,pe));
        auto* og=desc->OriginalFirstThunk?(IMAGE_THUNK_DATA64*)(pe.raw.data()+rva_to_ptr(desc->OriginalFirstThunk,pe)):tk;
        uintptr_t lb=(uintptr_t)hm;int ur=0;
        while(og->u1.AddressOfData!=0){
            uintptr_t lf=0;
            if(og->u1.Ordinal&IMAGE_ORDINAL_FLAG64)lf=(uintptr_t)GetProcAddress(hm,MAKEINTRESOURCEA(og->u1.Ordinal&0xFFFF));
            else{auto* nb=(IMAGE_IMPORT_BY_NAME*)(pe.raw.data()+rva_to_ptr((DWORD)og->u1.AddressOfData,pe));lf=(uintptr_t)GetProcAddress(hm,nb->Name);}
            uintptr_t rf=lf?(rdb+(lf-lb)):0;if(!lf)ur++;
            SIZE_T wr;
            WriteProcessMemory(p,(LPVOID)(base+(desc->FirstThunk+(uintptr_t)tk-(uintptr_t)(IMAGE_THUNK_DATA64*)(pe.raw.data()+rva_to_ptr(desc->FirstThunk,pe)))),&rf,sizeof(rf),&wr);
            og++;tk++;
        }
        FreeLibrary(hm); if(ur>0)warn(std::to_string(ur)+" unresolved"); desc++;
    }
    return true;
}

bool apply_relocs(HANDLE p,uintptr_t base,PeData& pe){
    uintptr_t pref=pe.nt->OptionalHeader.ImageBase; if(base==pref)return true;
    intptr_t delta=(intptr_t)(base-pref); info("Relocs: delta="+hex_str((uintptr_t)delta));
    auto& dir=pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if(dir.Size==0){warn("No .reloc");return false;}
    auto* blk=(IMAGE_BASE_RELOCATION*)(pe.raw.data()+rva_to_ptr(dir.VirtualAddress,pe));
    uint8_t* en=pe.raw.data()+rva_to_ptr(dir.VirtualAddress,pe)+dir.Size;
    while((uint8_t*)blk<en&&blk->SizeOfBlock>0){
        DWORD cnt=(blk->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);
        WORD* e=(WORD*)(blk+1);
        for(DWORD i=0;i<cnt;i++){
            if((e[i]>>12)!=IMAGE_REL_BASED_DIR64)continue;
            uintptr_t a=base+blk->VirtualAddress+(e[i]&0xFFF);
            uintptr_t v=0;SIZE_T rd;ReadProcessMemory(p,(LPCVOID)a,&v,sizeof(v),&rd);v+=delta;
            SIZE_T wr;WriteProcessMemory(p,(LPVOID)a,&v,sizeof(v),&wr);
        }
        blk=(IMAGE_BASE_RELOCATION*)((uint8_t*)blk+blk->SizeOfBlock);
    }
    info("Relocs applied"); return true;
}

void protect_sections(HANDLE p,uintptr_t base,PeData& pe){
    for(int i=0;i<pe.nt->FileHeader.NumberOfSections;i++){
        auto& s=pe.sections[i];if(s.SizeOfRawData==0)continue;
        DWORD prot=PAGE_READONLY;
        if(s.Characteristics&IMAGE_SCN_MEM_EXECUTE)prot=(s.Characteristics&IMAGE_SCN_MEM_WRITE)?PAGE_EXECUTE_READWRITE:PAGE_EXECUTE_READ;
        else if(s.Characteristics&IMAGE_SCN_MEM_WRITE)prot=PAGE_READWRITE;
        DWORD old;VirtualProtectEx(p,(LPVOID)(base+s.VirtualAddress),s.Misc.VirtualSize,prot,&old);
    }
}

bool manual_map(DWORD pid,const std::wstring& dll_path){
    PeData pe;
    if(!load_pe(dll_path,pe)){std::cerr<<"[ERROR] Bad PE"<<std::endl;return false;}
    info("DLL: "+std::to_string(pe.image_size)+" bytes, "+std::to_string(pe.nt->FileHeader.NumberOfSections)+" sections");
    dump_sections(pe);

    HANDLE p=OpenProcess(PROCESS_ALL_ACCESS_FLAGS,FALSE,pid);
    if(!p){std::cerr<<"[ERROR] OpenProcess failed"<<std::endl;return false;}
    info("Opened PID "+std::to_string(pid));

    LPVOID mem=VirtualAllocEx(p,nullptr,pe.image_size,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if(!mem){die("VirtualAllocEx");CloseHandle(p);return false;}
    uintptr_t base=(uintptr_t)mem; info("Mapped @ "+hex_str(base));

    SIZE_T wr;
    WriteProcessMemory(p,mem,pe.raw.data(),pe.nt->OptionalHeader.SizeOfHeaders,&wr);
    for(int i=0;i<pe.nt->FileHeader.NumberOfSections;i++){
        auto& s=pe.sections[i];if(s.SizeOfRawData==0)continue;
        WriteProcessMemory(p,(LPVOID)(base+s.VirtualAddress),pe.raw.data()+s.PointerToRawData,s.SizeOfRawData,&wr);
    }

    apply_relocs(p,base,pe);
    resolve_imports(p,pid,base,pe);

    uintptr_t tls_idx_addr=0;
    setup_tls(p,base,pe,&tls_idx_addr);
    protect_sections(p,base,pe);

    uintptr_t entry=pe.nt->OptionalHeader.AddressOfEntryPoint;
    if(entry==0){warn("No entry point");CloseHandle(p);return true;}
    info("Entry RVA: "+hex_str(entry));

    info("Thread hijacking (TlsAlloc + private stack + register safe)...");
    if(inject_via_hijack(p,pid,base,entry,tls_idx_addr)){
        info("SUCCESS! DLL @ "+hex_str(base));
        info("DllMain runs on private stack, thread restored after.");
        info("Log: %TEMP%\\luna_extracted\\"+std::to_string(pid)+"\\runtime.log");
        CloseHandle(p);return true;
    }
    CloseHandle(p);
    warn("Thread hijack failed.");
    return false;
}

bool is_x64_dll(const std::wstring& p){
    std::ifstream f(p.c_str(),std::ios::binary);if(!f)return false;
    IMAGE_DOS_HEADER dos;f.read((char*)&dos,sizeof(dos));
    if(dos.e_magic!=IMAGE_DOS_SIGNATURE)return false;
    f.seekg(dos.e_lfanew);DWORD sig;f.read((char*)&sig,sizeof(sig));
    if(sig!=IMAGE_NT_SIGNATURE)return false;
    IMAGE_FILE_HEADER fh;f.read((char*)&fh,sizeof(fh));
    WORD magic;f.read((char*)&magic,sizeof(magic));
    return magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

bool is_x64_process(DWORD pid){
    HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
    if(!h)return false; BOOL w=FALSE;IsWow64Process(h,&w);CloseHandle(h);return !w;
}

int wmain(int argc,wchar_t* argv[]){
    if(argc<3){std::wcout<<L"Manual Map Injector (Hijack + TlsAlloc)\nUsage: manual_map.exe <dll> --process <name>\n";return 1;}
    std::wstring dll;DWORD pid=0;std::wstring pname;
    for(int i=1;i<argc;++i){
        std::wstring a=argv[i];
        if(a==L"--pid"&&i+1<argc)pid=_wtoi(argv[++i]);
        else if(a==L"--process"&&i+1<argc)pname=argv[++i];
        else if(dll.empty())dll=argv[i];
    }
    if(dll.empty()){std::cerr<<"DLL required"<<std::endl;return 1;}
    if(!pid){pid=find_pid(pname);if(!pid){std::cerr<<"Process not found"<<std::endl;return 1;}}
    std::wcout<<L"\n=== Architecture ==="<<std::endl;
    bool d64=is_x64_dll(dll),p64=is_x64_process(pid);
    std::wcout<<L"  DLL: "<<(d64?L"64-bit":L"32-bit")<<L"  Process: "<<(p64?L"64-bit":L"32-bit")<<std::endl;
    if(d64!=p64){std::cerr<<"MISMATCH!"<<std::endl;return 1;}
    std::wcout<<L"\nInjecting PID "<<pid<<L"..."<<std::endl;
    if(!manual_map(pid,dll)){std::cerr<<"FAILED."<<std::endl;return 1;}
    std::wcout<<L"\nDONE. Check %TEMP%\\luna_extracted\\"<<pid<<L"\\runtime.log"<<std::endl;
    return 0;
}
