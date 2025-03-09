#include <Windows.h>

typedef LPVOID(WINAPI* fnVirtualAllocExNuma)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, DWORD nndPreferred);
typedef DWORD(WINAPI* fnFlsAlloc)(PFLS_CALLBACK_FUNCTION lpCallback);
typedef BOOL(WINAPI* fnIsDebuggerPresent)();
typedef BOOL(WINAPI* fnWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);

int CheckSleepForwarding();
int CheckDebuggerPresence();
int CheckApiEmulation1();
int CheckApiEmulation2();