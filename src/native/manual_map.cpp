// manual_map.cpp - NtCreateThreadEx injector (final)
// For dynamic UCRT DLLs: no manual TLS needed, entry point just works.
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

void die(const char* msg){DWORD c=GetLastError();std::cerr<<"[FATAL] "<<msg<<" (0x"<<std::hex<<c<<std::dec<<")"<<std::endl;exit(1);}
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
    do{std::string mn;for(int i=0;e.szModule[i];i++){char c=(char)(e.szModule[i]<128?e.szModule[i]:'?');mn.push_back((char)tolower(c));}
        if(mn==nl){uintptr_t b=(uintptr_t)e.modBaseAddr;CloseHandle(s);return b;}}
    while(Module32NextW(s,&e));CloseHandle(s);return 0;
}

const char* resolve_api_set(const char* n){
    if(strstr(n,"api-ms-win-crt-")||strstr(n,"api-ms-win-core-"))return"ucrtbase.dll";
    return n;
}

struct PeData{std::vector<uint8_t> raw;IMAGE_DOS_HEADER* dos;IMAGE_NT_HEADERS64* nt;IMAGE_SECTION_HEADER* sections;size_t image_size;};

uintptr_t rva_to_ptr(DWORD rva,const PeData& pe){
    for(int i=0;i<pe.nt->FileHeader.NumberOfSections;i++){
        auto& s=pe.sections[i];
        if(rva>=s.VirtualAddress&&rva<s.VirtualAddress+s.Misc.VirtualSize)return rva-s.VirtualAddress+s.PointerToRawData;}
    if(rva<pe.nt->OptionalHeader.SizeOfHeaders)return rva;return rva;
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
    pe.sections=IMAGE_FIRST_SECTION(pe.nt);pe.image_size=pe.nt->OptionalHeader.SizeOfImage;
    return true;
}

// Shellcode: call entry point in fresh thread. Dynamic UCRT handles TLS.
std::vector<uint8_t> build_shellcode(uintptr_t entry_addr, uintptr_t dll_base){
    std::vector<uint8_t> sc;
    sc.push_back(0x48);sc.push_back(0x83);sc.push_back(0xEC);sc.push_back(0x28);
    sc.push_back(0x48);sc.push_back(0xB9);for(int i=0;i<8;i++)sc.push_back((uint8_t)(dll_base>>(i*8)));
    sc.push_back(0xBA);sc.push_back(0x01);sc.push_back(0x00);sc.push_back(0x00);sc.push_back(0x00);
    sc.push_back(0x45);sc.push_back(0x31);sc.push_back(0xC0);
    sc.push_back(0x48);sc.push_back(0xB8);for(int i=0;i<8;i++)sc.push_back((uint8_t)(entry_addr>>(i*8)));
    sc.push_back(0xFF);sc.push_back(0xD0);
    sc.push_back(0x48);sc.push_back(0x83);sc.push_back(0xC4);sc.push_back(0x28);sc.push_back(0xC3);
    return sc;
}

typedef LONG (NTAPI* NtCreateThreadEx_t)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);

bool inject_via_ntcreate(HANDLE p,uintptr_t ea,uintptr_t base){
    HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
    if(!ntdll){warn("no ntdll");return false;}
    NtCreateThreadEx_t fn=(NtCreateThreadEx_t)GetProcAddress(ntdll,"NtCreateThreadEx");
    if(!fn){warn("no NtCreateThreadEx");return false;}

    auto sc=build_shellcode(ea,base);
    LPVOID pg=VirtualAllocEx(p,NULL,0x1000,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if(!pg){warn("alloc fail");return false;}
    uintptr_t pa=(uintptr_t)pg;SIZE_T wr;
    WriteProcessMemory(p,(PVOID)(pa+0x100),sc.data(),sc.size(),&wr);

    HANDLE ht=NULL;
    LONG st=fn(&ht,THREAD_ALL_ACCESS,NULL,p,(PVOID)(pa+0x100),(PVOID)base,4,0,0,0,NULL);
    if(st>=0&&ht){info("Thread OK (HIDE_FROM_DEBUGGER)");CloseHandle(ht);return true;}
    warn("NtCreateThreadEx fail, fallback...");
    HANDLE crt=CreateRemoteThread(p,NULL,0,(LPTHREAD_START_ROUTINE)(pa+0x100),(PVOID)base,0,NULL);
    if(!crt){VirtualFreeEx(p,pg,0,MEM_RELEASE);return false;}
    info("CreateRemoteThread OK");CloseHandle(crt);return true;
}

bool resolve_imports(HANDLE p,DWORD pid,uintptr_t base,PeData& pe){
    auto& dir=pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(dir.Size==0)return true;
    auto* desc=(IMAGE_IMPORT_DESCRIPTOR*)(pe.raw.data()+rva_to_ptr(dir.VirtualAddress,pe));
    while(desc->Name!=0){
        const char* dn=(const char*)(pe.raw.data()+rva_to_ptr(desc->Name,pe));
        const char* rn=resolve_api_set(dn);
        std::string rl;for(const char*c=rn;*c;c++)rl.push_back((char)tolower(*c));
        uintptr_t rdb=remote_module_base(pid,rl);
        if(!rdb){desc++;continue;}
        HMODULE hm=LoadLibraryA(rn);if(!hm){desc++;continue;}
        info("  "+std::string(dn)+" -> "+rn);
        auto* tk=(IMAGE_THUNK_DATA64*)(pe.raw.data()+rva_to_ptr(desc->FirstThunk,pe));
        auto* og=desc->OriginalFirstThunk?(IMAGE_THUNK_DATA64*)(pe.raw.data()+rva_to_ptr(desc->OriginalFirstThunk,pe)):tk;
        uintptr_t lb=(uintptr_t)hm;int ur=0;
        while(og->u1.AddressOfData!=0){
            uintptr_t lf=0;
            if(og->u1.Ordinal&IMAGE_ORDINAL_FLAG64)lf=(uintptr_t)GetProcAddress(hm,MAKEINTRESOURCEA(og->u1.Ordinal&0xFFFF));
            else{auto* nb=(IMAGE_IMPORT_BY_NAME*)(pe.raw.data()+rva_to_ptr((DWORD)og->u1.AddressOfData,pe));lf=(uintptr_t)GetProcAddress(hm,nb->Name);}
            uintptr_t rf=lf?(rdb+(lf-lb)):0;if(!lf)ur++;SIZE_T wr;
            WriteProcessMemory(p,(PVOID)(base+(desc->FirstThunk+(uintptr_t)tk-(uintptr_t)(IMAGE_THUNK_DATA64*)(pe.raw.data()+rva_to_ptr(desc->FirstThunk,pe)))),&rf,sizeof(rf),&wr);
            og++;tk++;}FreeLibrary(hm);desc++;}
    return true;
}

bool apply_relocs(HANDLE p,uintptr_t base,PeData& pe){
    uintptr_t pref=pe.nt->OptionalHeader.ImageBase;if(base==pref)return true;
    intptr_t delta=(intptr_t)(base-pref);
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
            uintptr_t v=0;SIZE_T rd;ReadProcessMemory(p,(PVOID)a,&v,sizeof(v),&rd);v+=delta;
            SIZE_T wr;WriteProcessMemory(p,(PVOID)a,&v,sizeof(v),&wr);}
        blk=(IMAGE_BASE_RELOCATION*)((uint8_t*)blk+blk->SizeOfBlock);}
    info("Relocs applied");return true;
}

void protect_sections(HANDLE p,uintptr_t base,PeData& pe){
    for(int i=0;i<pe.nt->FileHeader.NumberOfSections;i++){
        auto& s=pe.sections[i];if(s.SizeOfRawData==0)continue;
        DWORD prot=PAGE_READONLY;
        if(s.Characteristics&IMAGE_SCN_MEM_EXECUTE)prot=(s.Characteristics&IMAGE_SCN_MEM_WRITE)?PAGE_EXECUTE_READWRITE:PAGE_EXECUTE_READ;
        else if(s.Characteristics&IMAGE_SCN_MEM_WRITE)prot=PAGE_READWRITE;
        DWORD old;VirtualProtectEx(p,(PVOID)(base+s.VirtualAddress),s.Misc.VirtualSize,prot,&old);}
}

bool manual_map(DWORD pid,const std::wstring& dll_path){
    PeData pe;
    if(!load_pe(dll_path,pe)){std::cerr<<"[ERROR] Bad PE"<<std::endl;return false;}
    info("DLL: "+std::to_string(pe.image_size)+"B "+std::to_string(pe.nt->FileHeader.NumberOfSections)+" sec");

    HANDLE p=OpenProcess(PROCESS_ALL_ACCESS_FLAGS,FALSE,pid);
    if(!p){std::cerr<<"[ERROR] OpenProcess"<<std::endl;return false;}
    info("PID "+std::to_string(pid));

    LPVOID mem=VirtualAllocEx(p,NULL,pe.image_size,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if(!mem){die("VirtualAllocEx");CloseHandle(p);return false;}
    uintptr_t base=(uintptr_t)mem;info("@ "+hex_str(base));

    SIZE_T wr;
    WriteProcessMemory(p,mem,pe.raw.data(),pe.nt->OptionalHeader.SizeOfHeaders,&wr);
    for(int i=0;i<pe.nt->FileHeader.NumberOfSections;i++){
        auto& s=pe.sections[i];if(s.SizeOfRawData==0)continue;
        WriteProcessMemory(p,(PVOID)(base+s.VirtualAddress),pe.raw.data()+s.PointerToRawData,s.SizeOfRawData,&wr);}

    apply_relocs(p,base,pe);
    resolve_imports(p,pid,base,pe);
    protect_sections(p,base,pe);

    uintptr_t entry=pe.nt->OptionalHeader.AddressOfEntryPoint;
    if(entry==0){warn("No entry point");CloseHandle(p);return true;}

    info("NtCreateThreadEx (HIDE_FROM_DEBUGGER)...");
    if(inject_via_ntcreate(p,base+entry,base)){
        info("SUCCESS! DLL @ "+hex_str(base));
        info("Dynamic UCRT = no manual TLS. Log appears instantly.");
        CloseHandle(p);return true;}
    CloseHandle(p);return false;
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
    if(argc<3){std::wcout<<L"NtCreateThreadEx Injector\nUsage: manual_map.exe <dll> --process <name>\n";return 1;}
    std::wstring dll;DWORD pid=0;std::wstring pname;
    for(int i=1;i<argc;++i){std::wstring a=argv[i];
        if(a==L"--pid"&&i+1<argc)pid=_wtoi(argv[++i]);
        else if(a==L"--process"&&i+1<argc)pname=argv[++i];
        else if(dll.empty())dll=argv[i];}
    if(dll.empty()){std::cerr<<"DLL?"<<std::endl;return 1;}
    if(!pid){pid=find_pid(pname);if(!pid){std::cerr<<"Not found"<<std::endl;return 1;}}
    std::wcout<<L"\nArch: DLL="<<(is_x64_dll(dll)?L"64":L"32")<<L" Proc="<<(is_x64_process(pid)?L"64":L"32")<<std::endl;
    if(!manual_map(pid,dll)){std::cerr<<"FAILED."<<std::endl;return 1;}
    std::wcout<<L"\nDONE."<<std::endl;
    return 0;
}
