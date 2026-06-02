#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllimport) BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
__declspec(dllimport) DWORD WINAPI StartRuntimeThreadProc(LPVOID param);
__declspec(dllimport) void ExecuteScript(char* cscript);
__declspec(dllimport) void ProcessQ(void);
__declspec(dllimport) void GoDrawLoop(void);
__declspec(dllimport) void GoIndex(void);
__declspec(dllimport) void GoLunaGateway(void);
__declspec(dllimport) void GoNamecall(void);
__declspec(dllimport) void GoStepHookPayload(void);
__declspec(dllimport) void free_go_handle(void);
__declspec(dllimport) void go_lua_callback(void);

#ifdef __cplusplus
}
#endif
