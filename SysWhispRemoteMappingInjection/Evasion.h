#pragma once
#include <Windows.h>

typedef LPVOID(WINAPI* fnVirtualAllocExNuma)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, DWORD nndPreferred);
typedef DWORD(WINAPI* fnFlsAlloc)(PFLS_CALLBACK_FUNCTION lpCallback);
typedef BOOL(WINAPI* fnIsDebuggerPresent)();
typedef DWORD(WINAPI* fnGetEnvironmentVariableA)(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize);
typedef BOOL(WINAPI* fnDebugActiveProcessStop)(DWORD dwProcessId);

DWORD HashStringDjb2A(_In_ PCHAR String);
DWORD64 HashStringDjb2W(PWSTR str);
FARPROC NotGetProcAddress(IN HMODULE hModule, IN DWORD dwApiNameHash);
HMODULE NotGetModuleHandle(DWORD dwModuleNameHash);

int CheckSleepForwarding();
int CheckDebuggerPresence();
int CheckApiEmulation1();
int CheckApiEmulation2();
int CheckExecControl();
int APIHammering(DWORD dwStress);
int InitEvasion();