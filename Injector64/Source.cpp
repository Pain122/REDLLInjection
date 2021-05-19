#include <Windows.h>
#include <tchar.h>
#include <winternl.h>
#include <psapi.h>
#include "Remote.h"
#include <stdio.h>

#define IF_FAIL_GO(err, func, hand) \
			err - func; \
			if (0 != err) goto hand;

DWORD CreateProc(LPCTSTR appName, HANDLE& hProc, HANDLE& hThread)
{
	STARTUPINFO si = {};
	PROCESS_INFORMATION pi = {};
	if (!CreateProcess(appName, nullptr, nullptr, nullptr, true, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
	{
		DWORD err = GetLastError();
		_tprintf(_T("CreateProcess failed with code 0x%x\n"), err);
		return err;
	}

	Sleep(1000);

	hProc = pi.hProcess;
	hThread = pi.hThread;

	return ERROR_SUCCESS;
}

DWORD LoopEntry(HANDLE hProc, HANDLE hThread, ULONG_PTR& addressOfEntry, DWORD64& originalEntry)
{
	PROCESS_BASIC_INFORMATION pbi = {};
	ULONG retLen = 0;
	PEB peb = {};
	IMAGE_DOS_HEADER dos = {};
	IMAGE_NT_HEADERS64 nt = {};

	WORD patchedEntry = 0xFEEB;

	NTSTATUS err = NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &retLen);
	if (!err == 0)
	{
		_tprintf(_T("NtQueryInformationProcess failed with code 0x%x"), err);
		return err;
	}

	DWORD error = ReadRemote<PEB>(hProc, (ULONG_PTR)pbi.PebBaseAddress, peb);
	if (!error == 0)
	{
		_tprintf(_T("ReadRemote failed with code 0x%x"), error);
		return error;
	}

	ULONG_PTR pRemoteBaseAddress = (ULONG_PTR)peb.Reserved3[1]; // ImageBaseAddress

	error = ReadRemote<IMAGE_DOS_HEADER>(hProc, pRemoteBaseAddress, dos);
	if (!error == 0)
	{
		_tprintf(_T("ReadRemote failed with code 0x%x"), error);
		return error;
	}

	error = ReadRemote<IMAGE_NT_HEADERS64>(hProc, (ULONG_PTR)(pRemoteBaseAddress + dos.e_lfanew), nt);
	if (!error == 0)
	{
		_tprintf(_T("ReadRemote failed with code 0x%x"), error);
		return error;
	}

	addressOfEntry = pRemoteBaseAddress + nt.OptionalHeader.AddressOfEntryPoint;

	error = ReadRemote<DWORD64>(hProc, addressOfEntry, originalEntry);
	if (!error == 0)
	{
		_tprintf(_T("ReadRemote failed with code 0x%x"), error);
		return error;
	}

	error = WriteRemote<WORD>(hProc, addressOfEntry, patchedEntry);
	if (!error == 0)
	{
		_tprintf(_T("WriteRemote failed with code 0x%x"), error);
		return error;
	}

	ResumeThread(hThread);

	Sleep(1000);

	return 0;
}

extern "C" NTSYSCALLAPI NTSTATUS NTAPI NtSuspendProcess(HANDLE proc);
extern "C" NTSYSCALLAPI NTSTATUS NTAPI NtResumeProcess(HANDLE proc);

DWORD DeLoopEntry(HANDLE hProc, HANDLE hThread, ULONG_PTR addressOfEntry, WORD originalEntry)
{
	NtSuspendProcess(hProc);

	DWORD error = WriteRemote<WORD>(hProc, addressOfEntry, originalEntry);
	if (!error == 0)
	{
		_tprintf(_T("WriteRemote failed with code 0x%x\n"), error);
		return error;
	}

	NtResumeProcess(hProc);

	Sleep(1000);
}

DWORD FindLoadLibrary(HANDLE hProc, HANDLE hThread, ULONG_PTR& loadLibAddr)
{
	LPCSTR targetLib = "KERNEL32.dll";
	LPCSTR targetFunc = "LoadLibraryW";
	DWORD needed = 0;
	DWORD64 size = 0;
	DWORD64 amount = 0;
	HMODULE* hModules = nullptr;
	IMAGE_DOS_HEADER dos = {};
	IMAGE_NT_HEADERS64 nt = {};

	if (EnumProcessModulesEx(hProc, nullptr, 0, &needed, LIST_MODULES_64BIT) == 0)
	{
		DWORD err = GetLastError();
		_tprintf(_T("CreateProcess failed with code 0x%x\n"), err);
		return err;
	}

	size = needed;
	amount = size / sizeof(HMODULE);

	hModules = (HMODULE*)malloc(size);

	if (hModules == 0) {
		return -1;
	}

	if (EnumProcessModules(hProc, hModules, size, &needed) == 0)
	{
		DWORD err = GetLastError();
		_tprintf(_T("CreateProcess failed with code 0x%x\n"), err);
		return err;
	}

	for (DWORD i = 0; i < amount; i++)
	{

		ULONG_PTR moduleBase = (ULONG_PTR)hModules[i];

		DWORD error = ReadRemote<IMAGE_DOS_HEADER>(hProc, moduleBase, dos);
		if (!error == 0)
		{
			_tprintf(_T("ReadRemote failed with code 0x%x\n"), error);
			return error;
		}

		error = ReadRemote<IMAGE_NT_HEADERS64>(hProc, (ULONG_PTR)(moduleBase + dos.e_lfanew), nt);
		if (!error == 0)
		{
			_tprintf(_T("ReadRemote failed with code 0x%x\n"), error);
			return error;
		}

		IMAGE_DATA_DIRECTORY exportDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		if (0 == exportDir.Size) continue;

		IMAGE_EXPORT_DIRECTORY moduleExport = {};

		error = ReadRemote<IMAGE_EXPORT_DIRECTORY>(hProc, (ULONG_PTR)(moduleBase + exportDir.VirtualAddress), moduleExport);
		if (!error == 0)
		{
			_tprintf(_T("ReadRemote 3 args failed with code 0x%x\n"), error);
			return error;
		}

		CHAR moduleName[MAX_PATH];
		DWORD64 moduleNameLen = 0;

		error = ReadRemote<CHAR>(hProc, (ULONG_PTR)(moduleBase + moduleExport.Name), moduleName, moduleNameLen);
		if (!error == 0)
		{
			_tprintf(_T("ReadRemote failed with code 0x%x\n"), error);
			return error;
		}

		if (strcmp(moduleName, targetLib)) continue;

		DWORD64 numberOfFuncs = moduleExport.NumberOfFunctions;
		DWORD64 numberOfFuncs2 = moduleExport.NumberOfFunctions;

		ULONG_PTR* functionNamesRva = (ULONG_PTR*)malloc(sizeof(ULONG_PTR) * numberOfFuncs);
		ULONG_PTR* functionAddrsRva = (ULONG_PTR*)malloc(sizeof(ULONG_PTR) * numberOfFuncs);

		if (functionNamesRva == 0)
		{
			return -1;
		}

		error = ReadRemote<ULONG_PTR>(hProc, (ULONG_PTR)(moduleBase + (DWORD64)(moduleExport.AddressOfNames)), functionNamesRva, numberOfFuncs);
		if (!error == 0)
		{
			_tprintf(_T("ReadRemote failed with code 0x%x\n"), error);
			return error;
		}

		if (functionAddrsRva == 0) {
			return -1;
		}
		error = ReadRemote<ULONG_PTR>(hProc, (ULONG_PTR)(moduleBase + (DWORD64)(moduleExport.AddressOfFunctions)), functionAddrsRva, numberOfFuncs2);
		if (!error == 0)
		{
			_tprintf(_T("ReadRemote failed with code 0x%x\n"), error);
			return error;
		}

		for (DWORD64 j = 0; j < numberOfFuncs; j++)
		{
			CHAR functionName[MAX_PATH];
			DWORD64 functionNameLen = 0;

			error = ReadRemote<CHAR>(hProc, (ULONG_PTR)((DWORD64)moduleBase + functionNamesRva[j]), functionName, functionNameLen);
			if (!error == 0)
			{
				_tprintf(_T("ReadRemote failed with code 0x%x\n"), error);
				return error;
			}

			if (!strcmp(functionName, targetFunc))
			{
				// May be mistake
				loadLibAddr = (ULONG_PTR)(moduleBase + functionAddrsRva[j]);
				break;
			}
		}

		free(functionNamesRva);
		free(functionAddrsRva);
		break;
	}

	free(hModules);

	return 0;
}


DWORD Inject(HANDLE hProc, HANDLE hThread, ULONG_PTR& loadLibAddr)
{
	// shellcode	
	UCHAR shellx86[]
	{
		/* 0x00 */ 0x90, 0x90, 0x90, 0x90, 0x90,
		/* 0x05 */ 0x6A, 0x00, 0x6A, 0x00,
		/* 0x09 */ 0x68, 0x00, 0x00, 0x00, 0x00,
		/* 0x0E */ 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
		/* 0x14 */ 0xF7, 0xD8,
		/* 0x16 */ 0x1B, 0xC0,
		/* 0x18 */ 0xF7, 0xD8,
		/* 0x1A */ 0x48,
		/* 0x1B */ 0xC3,
		/* 0x1C */ 0x90, 0x90, 0x90, 0x90,
		/* 0x20 */ 0x00, 0x00, 0x00, 0x00,
		/* 0x24 */ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		/* 0x30 */ 0x43, 0x00, 0x3a, 0x00, 0x5C, 0x00, 0x55, 0x00, // C:\\Users\\pavel\\source\\repos\\REDLLInjection\\Release\\REDLLInjection.dll
				   0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00,
				   0x5C, 0x00, 0x70, 0x00, 0x61, 0x00, 0x76, 0x00,
				   0x65, 0x00, 0x6C, 0x00, 0x5C, 0x00, 0x73, 0x00,
				   0x6F, 0x00, 0x75, 0x00, 0x72, 0x00, 0x63, 0x00,
				   0x65, 0x00, 0x5C, 0x00, 0x72, 0x00, 0x65, 0x00,
				   0x70, 0x00, 0x6F, 0x00, 0x73, 0x00, 0x5C, 0x00,
				   0x52, 0x00, 0x45, 0x00, 0x44, 0x00, 0x4C, 0x00,
				   0x4C, 0x00, 0x49, 0x00, 0x6E, 0x00, 0x6A, 0x00,
				   0x65, 0x00, 0x63, 0x00, 0x74, 0x00, 0x69, 0x00,
				   0x6F, 0x00, 0x6E, 0x00, 0x5C, 0x00, 0x52, 0x00,
				   0x65, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x61, 0x00,
				   0x73, 0x00, 0x65, 0x00, 0x5C, 0x00, 0x52, 0x00,
				   0x45, 0x00, 0x44, 0x00, 0x4C, 0x00, 0x4C, 0x00,
				   0x49, 0x00, 0x6E, 0x00, 0x6A, 0x00, 0x65, 0x00,
				   0x63, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00,
				   0x6E, 0x00, 0x2E, 0x00, 0x64, 0x00, 0x6C, 0x00,
				   0x6C, 0x00, 0x00, 0x00

	};

	// base of shellcode = alloc remote memory

	// 1. address of load library
	// 2. offset to string
	// 3. ...?
	// 4. Profit!

	PVOID pShellRemote = VirtualAllocEx(hProc, nullptr, sizeof(shellx86), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	ULONG_PTR shellBase = (ULONG_PTR)pShellRemote;

	ULONG_PTR stringOffset = shellBase + 0x30;
	ULONG_PTR funcOffset = shellBase + 0x20;

	memcpy(shellx86 + 0x20, &loadLibAddr, sizeof(ULONG_PTR));

	memcpy(shellx86 + 0x0A, &stringOffset, sizeof(ULONG_PTR));

	memcpy(shellx86 + 0x10, &funcOffset, sizeof(ULONG_PTR));

	SIZE_T written = 0;
	// move memory
	if (WriteProcessMemory(hProc, pShellRemote, shellx86, sizeof(shellx86), &written) == 0)
	{
		DWORD err = GetLastError();
		_tprintf(_T("WriteProcessMemory failed with code 0x%x"), err);
		return err;
	}

	DWORD tid;

	// create thread entry = shellcode
	// 
	// execute

	HANDLE hRemoteThread = CreateRemoteThread(hProc, nullptr, 0, LPTHREAD_START_ROUTINE(shellBase), nullptr, 0, &tid);

	WaitForSingleObject(hRemoteThread, INFINITE);

	DWORD exitCode = 0xf;
	GetExitCodeThread(hRemoteThread, &exitCode);

	CloseHandle(hRemoteThread);

	return 0;
}

int main()
{
	LPCTSTR appName = _T("C:\\Windows\\System32\\notepad.exe");
	HANDLE hProc = INVALID_HANDLE_VALUE;
	HANDLE hThread = INVALID_HANDLE_VALUE;
	DWORD status = ERROR_SUCCESS;
	ULONG_PTR addressOfEntry = 0;
	DWORD64 originalEntry = 0;
	ULONG_PTR loadLibAddr = 0;

	// create process suspended
	IF_FAIL_GO(status, CreateProc(appName, hProc, hThread), MAIN_ERROR_HANDLE);

	IF_FAIL_GO(status, LoopEntry(hProc, hThread, addressOfEntry, originalEntry), MAIN_ERROR_HANDLE);
	// find loadlibrary
	IF_FAIL_GO(status, FindLoadLibrary(hProc, hThread, loadLibAddr), MAIN_ERROR_HANDLE);
	// inject
	// IF_FAIL_GO(status, Inject(hProc, hThread, loadLibAddr), MAIN_ERROR_HANDLE);
	// deloop
	IF_FAIL_GO(status, DeLoopEntry(hProc, hThread, addressOfEntry, originalEntry), MAIN_ERROR_HANDLE);

	return 0;
MAIN_ERROR_HANDLE:
	_tprintf(_T("Error: 0x%x\n"), status);
	return status;
}