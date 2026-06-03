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

// ---- Thread enumeration ----
std::vector<DWORD> get_threads(DWORD pid){
    std::vector<DWORD> t;
    HANDLE s=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if(s==INVALID_HANDLE_VALUE)return t;
    THREADENTRY32 e{sizeof(e)};
    if(Thread32First(s,&e)){do{if(e.th32OwnerProcessID==pid)t.push_back(e.th32ThreadID);}while(Thread32Next(s,&e));}
    CloseHandle(s); return t;
}

// ---- THREAD HIJACKING SHELLCODE ----
// Layout (3 pages = 0x3000 allocated at data_area):
//   [0x0000-0x00FF] save area
//   [0x0100-0x0FFF] shellcode
//   [0x1000-0x1FFF] data (addresses stored here for shellcode to load)
//   [0x2000-0x2FFF] private stack (grows down from top)

std::vector<uint8_t> build_hijack_shellcode(uintptr_t data_area){
    uintptr_t save_rax  = data_area + 0x00;
    uintptr_t save_rcx  = data_area + 0x08;
    uintptr_t save_rdx  = data_area + 0x10;
    uintptr_t save_r8   = data_area + 0x18;
    uintptr_t save_r9   = data_area + 0x20;
    uintptr_t save_r10  = data_area + 0x28;
    uintptr_t save_r11  = data_area + 0x30;
    uintptr_t save_rfl  = data_area + 0x38;
    uintptr_t orig_rip  = data_area + 0x40;  // patched per-thread
    uintptr_t orig_rsp  = data_area + 0x48;  // patched per-thread
    uintptr_t addr_idx  = data_area + 0x1000; // AddressOfIndex (patched)
    uintptr_t addr_base = data_area + 0x1008; // dll_base (patched)
    uintptr_t addr_entry= data_area + 0x1010; // entry point (patched)
    uintptr_t addr_tlsa = data_area + 0x1018; // TlsAlloc addr (patched)
    uintptr_t priv_stack_top = data_area + 0x3000;

    // Helper: emit "mov [abs64], reg64" (op=0x89, ModRM)
    auto emit_save_reg = [&](uintptr_t addr, uint8_t modrm) {
        sc.push_back(0x48);
        if(modrm==0x05||modrm==0x0D||modrm==0x15||modrm==0x1D||modrm==0x25||modrm==0x2D||modrm==0x35||modrm==0x3D){
            // RIP-relative form: prefix + op + modrm + 4-byte displacement
            uint32_t o=(uint32_t)addr; sc.push_back(0x89); sc.push_back(modrm);
            for(int i=0;i<4;i++)sc.push_back((uint8_t)(o>>(i*8)));
        }else{
            // absolute mov [abs64], rax: 48 A3 <addr>
            sc.push_back(0xA3);
            for(int i=0;i<8;i++)sc.push_back((uint8_t)(addr>>(i*8)));
        }
    };

    std::vector<uint8_t> sc;

    // == SAVE ALL REGISTERS ==
    // mov [save_rax], rax  (48 A3 ...)
    sc.push_back(0x48); sc.push_back(0xA3);
    for(int i=0;i<8;i++)sc.push_back((uint8_t)(save_rax>>(i*8)));

    // mov [rip+disp], rcx/rdx/r8/r9/r10/r11
    // These use RIP-relative addressing because 32-bit signed offsets fit
    // We'll compute offsets from the save instruction's RIP
    // Actually, simpler: use ABSOLUTE 64-bit addressing via mov r/m64, r64 with SIB
    // But 48 89 0D <disp32> is RIP-relative. The disp32 must reach save area.
    // The shellcode is at data_area+0x100, save area at data_area+0x00.
    // Offset from RIP=shellcode_addr+save_instr_offset to save_area+offset
    // We know: data_area+0x100 is shellcode start. Let's compute precise rip-relative offsets.
    // For simplicity, just build all save instructions first, knowing shellcode_base = data_area + 0x100

    // We need to compute RIP-relative offsets. The "next instruction" RIP after the instruction
    // is used as base for the displacement.
    // Let's just use absolute form via 48 8D modrm [SIB+disp32] pattern... actually that's for LEA.
    // For MOV r64 to [mem], the form is:
    // 48 89 0D <disp32>  = mov [rip+disp32], rcx  (7 bytes)
    // 48 89 15 <disp32>  = mov [rip+disp32], rdx
    // 4C 89 05 <disp32>  = mov [rip+disp32], r8
    // 4C 89 0D <disp32>  = mov [rip+disp32], r9
    // 4C 89 15 <disp32>  = mov [rip+disp32], r10
    // 4C 89 1D <disp32>  = mov [rip+disp32], r11

    // We build the shellcode and track offset to compute RIP-relative displacements
    size_t sc_start = sc.size(); // = 10 (already have save_rax)
    // Actually let me just precompute sizes and compute offsets in a second pass
    // Or better: use the absolute form for all saves, like we did for rax.
    // 48 A3 for rax, but there's no absolute form for rcx/rdx etc with 64-bit immediates as addresses.
    // We need to use a different approach. Let me just use PUSH + POP to save to stack first,
    // then use the private stack area for saving.
    // Actually, the simplest correct approach: push all regs, then mov them from stack to save area.
    // But that's more complex.

    // Let me just use a different technique: compute rip offsets manually for each instruction.
    // shellcode_base = data_area + 0x100
    // After "mov [save_rax], rax" (10 bytes), RIP = shellcode_base + 10
    // Next instruction: mov [rip+disp32], rcx -> disp32 = save_rcx - (shellcode_base + 10 + 7)
    // where 7 = size of the instruction itself.

    uintptr_t sc_base = data_area + 0x100;

    auto add_mov_rip_rel = [&](uintptr_t target, uint8_t op_prefix, uint8_t modrm) {
        // Current size = sc.size(), so RIP after this instruction = sc_base + sc.size() + 7
        uintptr_t rip_after = sc_base + sc.size() + 7;
        int32_t disp = (int32_t)(target - rip_after);
        if(op_prefix) sc.push_back(op_prefix);
        sc.push_back(0x89); sc.push_back(modrm);
        for(int i=0;i<4;i++)sc.push_back((uint8_t)(disp>>(i*8)));
    };

    // rcx: 48 89 0D disp32
    add_mov_rip_rel(save_rcx, 0x48, 0x0D);
    // rdx: 48 89 15 disp32
    add_mov_rip_rel(save_rdx, 0x48, 0x15);
    // r8:  4C 89 05 disp32
    add_mov_rip_rel(save_r8,  0x4C, 0x05);
    // r9:  4C 89 0D disp32
    add_mov_rip_rel(save_r9,  0x4C, 0x0D);
    // r10: 4C 89 15 disp32
    add_mov_rip_rel(save_r10, 0x4C, 0x15);
    // r11: 4C 89 1D disp32
    add_mov_rip_rel(save_r11, 0x4C, 0x1D);

    // pushfq; pop [rip+disp32]
    sc.push_back(0x9C); // pushfq
    uintptr_t rip_after_popfq = sc_base + sc.size() + 7;
    int32_t disp_rfl = (int32_t)(save_rfl - rip_after_popfq);
    sc.push_back(0x8F); sc.push_back(0x05);
    for(int i=0;i<4;i++)sc.push_back((uint8_t)(disp_rfl>>(i*8)));

    // == SWITCH TO PRIVATE STACK ==
    // mov rsp, priv_stack_top (48 BC imm64)
    sc.push_back(0x48); sc.push_back(0xBC);
    for(int i=0;i<8;i++)sc.push_back((uint8_t)(priv_stack_top>>(i*8)));

    // == CALL TlsAlloc ==
    // sub rsp, 0x28
    sc.push_back(0x48); sc.push_back(0x83); sc.push_back(0xEC); sc.push_back(0x28);
    // mov rax, [addr_tlsa]; call rax
    sc.push_back(0x48); sc.push_back(0xA1);
    for(int i=0;i<8;i++)sc.push_back((uint8_t)(addr_tlsa>>(i*8)));
    sc.push_back(0xFF); sc.push_back(0xD0);
    // add rsp, 0x28
    sc.push_back(0x48); sc.push_back(0x83); sc.push_back(0xC4); sc.push_back(0x28);

    // Write eax (TLS index) to [addr_idx] (4-byte DWORD)
    // 89 05 disp32 = mov [rip+disp32], eax
    uintptr_t rip_after_idx = sc_base + sc.size() + 6;
    int32_t disp_idx = (int32_t)(addr_idx - rip_after_idx);
    sc.push_back(0x89); sc.push_back(0x05);
    for(int i=0;i<4;i++)sc.push_back((uint8_t)(disp_idx>>(i*8)));

    // == CALL ENTRY POINT DllMainCRTStartup(dll_base, 1, NULL) ==
    // sub rsp, 0x28
    sc.push_back(0x48); sc.push_back(0x83); sc.push_back(0xEC); sc.push_back(0x28);
    // mov rcx, [addr_base]  (48 8B 0D disp32)
    uintptr_t rip_after_base = sc_base + sc.size() + 7;
    int32_t disp_base = (int32_t)(addr_base - rip_after_base);
    sc.push_back(0x48); sc.push_back(0x8B); sc.push_back(0x0D);
    for(int i=0;i<4;i++)sc.push_back((uint8_t)(disp_base>>(i*8)));

    // mov edx, 1
    sc.push_back(0xBA); sc.push_back(0x01); sc.push_back(0x00); sc.push_back(0x00); sc.push_back(0x00);
    // xor r8d, r8d
    sc.push_back(0x45); sc.push_back(0x31); sc.push_back(0xC0);
    // mov rax, [addr_entry]; call rax
    sc.push_back(0x48); sc.push_back(0xA1);
    for(int i=0;i<8;i++)sc.push_back((uint8_t)(addr_entry>>(i*8)));
    sc.push_back(0xFF); sc.push_back(0xD0);
    // add rsp, 0x28
    sc.push_back(0x48); sc.push_back(0x83); sc.push_back(0xC4); sc.push_back(0x28);

    // == RESTORE ORIGINAL STACK ==
    // mov rsp, [orig_rsp]
    uintptr_t rip_after_rsp = sc_base + sc.size() + 7;
    int32_t disp_rsp = (int32_t)(orig_rsp - rip_after_rsp);
    sc.push_back(0x48); sc.push_back(0x8B); sc.push_back(0x25);
    for(int i=0;i<4;i++)sc.push_back((uint8_t)(disp_rsp>>(i*8)));

    // == RESTORE REGISTERS ==
    // mov rax, [save_rax]
    sc.push_back(0x48); sc.push_back(0xA1);
    for(int i=0;i<8;i++)sc.push_back((uint8_t)(save_rax>>(i*8)));

    // rcx: 48 8B 0D disp32
    rip_after_rsp = sc_base + sc.size() + 7;
    disp_rsp = (int32_t)(save_rcx - rip_after_rsp);
    sc.push_back(0x48); sc.push_back(0x8B); sc.push_back(0x0D);
    for(int i=0;i<4;i++)sc.push_back((uint8_t)(disp_rsp>>(i*8)));

    // rdx: 48 8B 15 disp32
    rip_after_rsp = sc_base + sc.size() + 7;
    disp_rsp = (int32_t)(save_rdx - rip_after_rsp);
    sc.push_back(0x48); sc.push_back(0x8B); sc.push_back(0x15);
    for(int i=0;i<4;i++)sc.push_back((uint8_t)(disp_rsp>>(i*8)));

    // r8: 4C 8B 05 disp32
    rip_after_rsp = sc_base + sc.size() + 7;
    disp_rsp = (int32_t)(save_r8 - rip_after_rsp);
    sc.push_back(0x4C); sc.push_back(0x8B); sc.push_back(0x05);
    for(int i=0;i<4;i++)sc.push_back((uint8_t)(disp_rsp>>(i*8)));

    // r9: 4C 8B 0D disp32
    rip_after_rsp = sc_base + sc.size() + 7;
    disp_rsp = (int32_t)(save_r9 - rip_after_rsp);
    sc.push_back(0x4C); sc.push_back(0x8B); sc.push_back(0x0D);
    for(int i=0;i<4;i++)sc.push_back((uint8_t)(disp_rsp>>(i*8)));

    // r10: 4C 8B 15 disp32
    rip_after_rsp = sc_base + sc.size() + 7;
    disp_rsp = (int32_t)(save_r10 - rip_after_rsp);
    sc.push_back(0x4C); sc.push_back(0x8B); sc.push_back(0x15);
    for(int i=0;i<4;i++)sc.push_back((uint8_t)(disp_rsp>>(i*8)));

    // r11: 4C 8B 1D disp32
    rip_after_rsp = sc_base + sc.size() + 7;
    disp_rsp = (int32_t)(save_r11 - rip_after_rsp);
    sc.push_back(0x4C); sc.push_back(0x8B); sc.push_back(0x1D);
    for(int i=0;i<4;i++)sc.push_back((uint8_t)(disp_rsp>>(i*8)));

    // push [save_rfl]; popfq
    rip_after_rsp = sc_base + sc.size() + 7;
    disp_rsp = (int32_t)(save_rfl - rip_after_rsp);
    sc.push_back(0xFF); sc.push_back(0x35);
    for(int i=0;i<4;i++)sc.push_back((uint8_t)(disp_rsp>>(i*8)));
    sc.push_back(0x9D);

    // == JUMP BACK TO ORIGINAL RIP ==
    // ff 25 00 00 00 00 <orig_rip>
    sc.push_back(0xFF); sc.push_back(0x25);
    sc.push_back(0x00); sc.push_back(0x00); sc.push_back(0x00); sc.push_back(0x00);
    for(int i=0;i<8;i++)sc.push_back((uint8_t)(orig_rip>>(i*8)));

    return sc;
}

bool inject_via_hijack(HANDLE p,DWORD pid,uintptr_t base,uintptr_t entry_rva,uintptr_t tls_idx_addr){
    // Allocate 3 pages
    LPVOID mem=VirtualAllocEx(p,nullptr,0x3000,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if(!mem){warn("Hijack alloc failed");return false;}
    uintptr_t da=(uintptr_t)mem;

    auto sc=build_hijack_shellcode(da);

    // Patch data fields
    SIZE_T wr;
    WriteProcessMemory(p,(LPVOID)(da+0x1000),&tls_idx_addr,8,&wr);  // addr_idx
    WriteProcessMemory(p,(LPVOID)(da+0x1008),&base,8,&wr);          // addr_base
    uintptr_t ea=base+entry_rva;
    WriteProcessMemory(p,(LPVOID)(da+0x1010),&ea,8,&wr);            // addr_entry
    uintptr_t ta=(uintptr_t)TlsAlloc;
    WriteProcessMemory(p,(LPVOID)(da+0x1018),&ta,8,&wr);            // addr_tlsa

    // Write shellcode
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

        // Save orig RIP/RSP
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

// ---- TLS setup ----

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

// ---- Imports ----
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

// ---- Main ----

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
        info("DllMain runs on private stack, original thread restored after.");
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
    if(argc<3){std::wcout<<L"Manual Map Injector (Hijack + TlsAlloc + Private Stack)\nUsage: manual_map.exe <dll> --process <name>\n";return 1;}
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
