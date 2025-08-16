#pragma once
#include "syswhispers.h"

//KnownDLL method
#define NTDLL L"\\KnownDlls\\ntdll.dll"

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}

PVOID FetchLocalNtdllBaseAddress();
BOOL MapNtdllFromKnownDLLs(OUT PVOID* ppNtdllBuf);
BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll);
BOOL EvasionUnhook();