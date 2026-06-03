// manual_map.cpp - NtCreateThreadEx injector (fresh thread, bypasses Byfron)
// Compile: g++ -std=c++17 -O2 -m64 -municode manual_map.cpp -static -o manual_map.exe

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>

typedef int32_t i32;

static const DWORD PROCESS_ALL_ACCESS_FLAGS = 0x001F0FFF;

void die(const char* msg){DWORD c=GetLastError();std::cerr<<"[FATAL] "<<msg<<" (code=0x"<<std::hex<<c<<std::dec<<")"<<std::endl;exit(1);}
void info(const std::string& msg){std::cout<<"[+] "<<msg<<std::endl;}
void warn(const std::string& msg){std::cout<<"[!] "<<msg<<std::endl;}

std::string hex_str(uintptr_t v){char b[32];snprintf(b,sizeof(b),"0x%llx",(unsigned long long)v);return std::string(b);}

DWORD find_pid(const std::wstring& name){
    HANDLE s=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(s==INVALID_HANDLE_VALUE)return 0;
    PROCESSENTRY32W e{sizeof(e)};
    if(!Process32FirstW(s,&e)){CloseHandle(s);return 0;}
    do{if(_wcsicmp(e.szExeFile,name.c_str())==0){CloseHandle(s);return e.th32ProcessID;}}
    while(Process32NextW(s,&e));CloseHandle(s);return 0;
}

uintptr_t remote_module_base(DWORD pid,const std::string& nl){
    HANDLE s=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);
    if(s==INVALID_HANDLE_VALUE)return 0;
    MODULEENTRY32W e{sizeof(e)};
    if(!Module32FirstW(s,&e)){CloseHandle(s);return 0;}
    do{
        std::string mn;for(int i=0;e.szModule[i];i++){char c=(char)(e.szModule[i]<128?e.szModule[i]:'?');mn.push_back((char)tolower(c));}
        if(mn==nl){uintptr_t b=(uintptr_t)e.modBaseAddr;CloseHandle(s);return b;}
    }while(Module32NextW(s,&e));CloseHandle(s);return 0;
}

const char* resolve_api_set(const char* n){
    if(strstr(n,"api-ms-win-crt-")||strstr(n,"api-ms-win-core-"))return"ucrtbase.dll";
    return n;
}

struct PeData{std::vector<uint8_t> raw;IMAGE_DOS_HEADER* dos;IMAGE_NT_HEADERS64* nt;IMAGE_SECTION_HEADER* sections;size_t image_size;};

uintptr_t rva_to_ptr(DWORD rva,const PeData& pe){
    for(int i=0;i<pe.nt->FileHeader.NumberOfSections;i++){
        auto& s=pe.sections[i];
        if(rva>=s.VirtualAddress&&rva<s.VirtualAddress+s.Misc.VirtualSize)return rva-s.VirtualAddress+s.PointerToRawData;
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

// ---- SHELLCODE (fresh thread, TlsAlloc + DllMainCRTStartup) ----
// Layout: page[0x00]=tls_idx_addr, page[0x08]=dll_base, page[0x10]=entry_addr
//          page[0x100]=shellcode

std::vector<uint8_t> build_shellcode(uintptr_t page_addr){
    uintptr_t slot_tls   = page_addr + 0x00;
    uintptr_t slot_base  = page_addr + 0x08;
    uintptr_t slot_entry = page_addr + 0x10;
    uintptr_t sc_base    = page_addr + 0x100;

    std::vector<uint8_t> sc;

    // sub rsp, 0x28
    sc.push_back(0x48);sc.push_back(0x83);sc.push_back(0xEC);sc.push_back(0x28);

    // call TlsAlloc()
    uintptr_t ta=(uintptr_t)TlsAlloc;
    sc.push_back(0x48);sc.push_back(0xB8);
    for(int i=0;i<8;i++)sc.push_back((uint8_t)(ta>>(i*8)));
    sc.push_back(0xFF);sc.push_back(0xD0);

    // Write eax to TLS index pointer: mov rcx,[slot_tls]; mov [rcx],eax
    {i32 d=(i32)(slot_tls-(sc_base+sc.size()+7));
     sc.push_back(0x48);sc.push_back(0x8B);sc.push_back(0x0D);
     for(int i=0;i<4;i++)sc.push_back((uint8_t)(d>>(i*8)));}
    sc.push_back(0x89);sc.push_back(0x01);

    // Call DllMainCRTStartup(base, DLL_PROCESS_ATTACH, NULL)
    // mov rcx,[slot_base]
    {i32 d=(i32)(slot_base-(sc_base+sc.size()+7));
     sc.push_back(0x48);sc.push_back(0x8B);sc.push_back(0x0D);
     for(int i=0;i<4;i++)sc.push_back((uint8_t)(d>>(i*8)));}
    // mov edx, 1
    sc.push_back(0xBA);sc.push_back(0x01);sc.push_back(0x00);sc.push_back(0x00);sc.push_back(0x00);
    // xor r8d, r8d
    sc.push_back(0x45);sc.push_back(0x31);sc.push_back(0xC0);
    // mov rax,[slot_entry]; call rax
    {i32 d=(i32)(slot_entry-(sc_base+sc.size()+7));
     sc.push_back(0x48);sc.push_back(0x8B);sc.push_back(0x05);
     for(int i=0;i<4;i++)sc.push_back((uint8_t)(d>>(i*8)));}
    sc.push_back(0xFF);sc.push_back(0xD0);

    // add rsp, 0x28; ret (exit thread cleanly)
    sc.push_back(0x48);sc.push_back(0x83);sc.push_back(0xC4);sc.push_back(0x28);
    sc.push_back(0xC3);

    return sc;
}

// ---- NtCreateThreadEx injection (bypasses Byfron SuspendThread/SetThreadContext detection) ----

#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x4

typedef NTSTATUS (NTAPI* NtCreateThreadEx_t)(
    PHANDLE,HANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);

bool inject_via_ntcreate(HANDLE p,uintptr_t entry_addr,uintptr_t dll_base,uintptr_t tls_idx_addr){
    static NtCreateThreadEx_t ntCreateThreadEx=nullptr;
    if(!ntCreateThreadEx){
        HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
        if(!ntdll){warn("ntdll not loaded");return false;}
        ntCreateThreadEx=(NtCreateThreadEx_t)GetProcAddress(ntdll,"NtCreateThreadEx");
        if(!ntCreateThreadEx){warn("NtCreateThreadEx not found");return false;}
    }

    LPVOID page=VirtualAllocEx(p,nullptr,0x1000,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if(!page){warn("Page alloc failed");return false;}
    uintptr_t pa=(uintptr_t)page;

    SIZE_T wr;
    WriteProcessMemory(p,(LPVOID)(pa+0x00),&tls_idx_addr,8,&wr);
    WriteProcessMemory(p,(LPVOID)(pa+0x08),&dll_base,8,&wr);
    WriteProcessMemory(p,(LPVOID)(pa+0x10),&entry_addr,8,&wr);

    auto sc=build_shellcode(pa);
    WriteProcessMemory(p,(LPVOID)(pa+0x100),sc.data(),sc.size(),&wr);

    HANDLE hThread=nullptr;
    NTSTATUS st;

    for(int attempt=0;attempt<3;attempt++){
        ULONG flags=(attempt==0)?THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER:0;
        st=ntCreateThreadEx(&hThread,THREAD_ALL_ACCESS,nullptr,p,
            (PVOID)(pa+0x100),(PVOID)dll_base,flags,0,0,0,nullptr);
        if(st>=0&&hThread){
            info("Thread created (flags="+std::to_string(flags)+
                 ") TID="+std::to_string(GetThreadId(hThread)));
            CloseHandle(hThread);
            return true;
        }
        warn("NtCreateThreadEx attempt "+std::to_string(attempt+1)+" failed (0x"+hex_str(st)+")");
        Sleep(100);
    }

    warn("NtCreateThreadEx failed, falling back to CreateRemoteThread...");
    HANDLE crt=CreateRemoteThread(p,nullptr,0,(LPTHREAD_START_ROUTINE)(pa+0x100),(LPVOID)dll_base,0,nullptr);
    if(!crt){VirtualFreeEx(p,page,0,MEM_RELEASE);return false;}
    info("CreateRemoteThread TID="+std::to_string(GetThreadId(crt)));
    CloseHandle(crt);
    return true;
}

// ---- TLS setup (read from PE file to avoid double-relocation) ----

bool setup_tls(HANDLE p,uintptr_t base,PeData& pe,uintptr_t* out_idx){
    IMAGE_DATA_DIRECTORY& td=pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if(td.Size==0||td.VirtualAddress==0){info("TLS: none");*out_idx=0;return true;}

    IMAGE_TLS_DIRECTORY64* tls=(IMAGE_TLS_DIRECTORY64*)(pe.raw.data()+rva_to_ptr(td.VirtualAddress,pe));
    if(!tls->StartAddressOfRawData){
        *out_idx=base+(tls->AddressOfIndex-pe.nt->OptionalHeader.ImageBase);
        info("TLS: empty, index_addr="+hex_str(*out_idx));
        return true;}

    size_t ds=(size_t)(tls->EndAddressOfRawData-tls->StartAddressOfRawData);
    size_t zs=tls->SizeOfZeroFill;size_t tot=ds+zs;
    info("TLS: data="+std::to_string(ds)+" zero="+std::to_string(zs)+" total="+std::to_string(tot));

    *out_idx=base+(tls->AddressOfIndex-pe.nt->OptionalHeader.ImageBase);
    info("TLS: index_addr="+hex_str(*out_idx));

    LPVOID blk=VirtualAllocEx(p,nullptr,tot,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!blk){warn("TLS: alloc fail");return false;}
    uintptr_t bp=(uintptr_t)blk;

    if(ds>0){SIZE_T wr;WriteProcessMemory(p,blk,pe.raw.data()+rva_to_ptr((DWORD)tls->StartAddressOfRawData,pe),ds,&wr);}
    if(zs>0){std::vector<uint8_t> z(zs,0);SIZE_T wr;WriteProcessMemory(p,(LPVOID)(bp+ds),z.data(),zs,&wr);}

    uintptr_t tra=base+td.VirtualAddress;
    IMAGE_TLS_DIRECTORY64 pt={};
    pt.StartAddressOfRawData=bp;pt.EndAddressOfRawData=bp+tot;pt.SizeOfZeroFill=0;
    pt.AddressOfIndex=*out_idx;
    pt.AddressOfCallBacks=base+(tls->AddressOfCallBacks-pe.nt->OptionalHeader.ImageBase);
    pt.Characteristics=tls->Characteristics;
    SIZE_T wr;WriteProcessMemory(p,(LPVOID)tra,&pt,sizeof(pt),&wr);

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
        std::string rl;for(const char*c=rn;*c;c++)rl.push_back((char)tolower(*c));
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
        FreeLibrary(hm);if(ur>0)warn(std::to_string(ur)+" unresolved");desc++;
    }
    return true;
}

bool apply_relocs(HANDLE p,uintptr_t base,PeData& pe){
    uintptr_t pref=pe.nt->OptionalHeader.ImageBase;if(base==pref)return true;
    intptr_t delta=(intptr_t)(base-pref);info("Relocs: delta="+hex_str((uintptr_t)delta));
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
    info("Relocs applied");return true;
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
    uintptr_t base=(uintptr_t)mem;info("Mapped @ "+hex_str(base));

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

    info("NtCreateThreadEx (fresh thread, no hijack = no Byfron detection)...");
    if(inject_via_ntcreate(p,base+entry,base,tls_idx_addr)){
        info("SUCCESS! DLL @ "+hex_str(base));
        info("New thread, TlsAlloc called before DllMain, TLS index set.");
        info("Log: %TEMP%\\luna_extracted\\"+std::to_string(pid)+"\\runtime.log");
        CloseHandle(p);return true;
    }
    CloseHandle(p);
    warn("Injection failed.");
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
    if(!h)return false;BOOL w=FALSE;IsWow64Process(h,&w);CloseHandle(h);return !w;
}

int wmain(int argc,wchar_t* argv[]){
    if(argc<3){std::wcout<<L"Manual Map Injector (NtCreateThreadEx)\nUsage: manual_map.exe <dll> --process <name>\n";return 1;}
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
