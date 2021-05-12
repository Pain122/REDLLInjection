#include <Windows.h>
#include <stdio.h>
#include <tchar.h>

#define RVA_TO_VA(ptype, base, offset) (ptype)(((DWORD_PTR)(base)) + (offset))

int main() 
{
	// open exe file

	HANDLE file = CreateFileA("C:\\Users\\pavel\\source\\repos\\REDLLInjection\\PELoader\\simple.exe", 
		GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, 0, NULL);
	DWORD size = GetFileSize(file, NULL);

	HANDLE mapping = CreateFileMappingA(file, NULL, SEC_IMAGE | PAGE_READONLY, 0, 0, NULL);

	LPVOID fileBase = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
	
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)fileBase;
	// print emagic
	WORD magic = pImageDosHeader->e_magic;

	printf("Magic Word: %#X\n", magic);

	// get NT_HEADER
	PIMAGE_NT_HEADERS32 pImageNtHeader = RVA_TO_VA(PIMAGE_NT_HEADERS32, pImageDosHeader, pImageDosHeader->e_lfanew);
	// print signature
	// print machine
	DWORD signature = pImageNtHeader->Signature;
	WORD machine = pImageNtHeader->FileHeader.Machine;

	printf("Signature: %#X\n", signature);
	printf("Machine: %#X\n", machine);
	// get OPTIONAL_HEADER32
	// ImageBase
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNtHeader);
	// AddressOfEntry
	// numberofsections
	DWORD nSections = pImageNtHeader->FileHeader.NumberOfSections;
	DWORD i = 0;
	// foreach import:
	printf("------------Module Names------------\n");
	while (i < nSections)
	{
		//module name
		PTCHAR name = pSection->Name; //Firstly I used BYTE* (Found out it was pointer in the structure)
		_tprintf(_T("Name: %s\n"), name);

		pSection++;
		i++;
	}

	DWORD rvaImport = pImageNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress;
	DWORD sizeImport = pImageNtHeader->OptionalHeader.DataDirectory[1].Size;

	PIMAGE_IMPORT_DESCRIPTOR imageImport = RVA_TO_VA(PIMAGE_IMPORT_DESCRIPTOR, pImageDosHeader, rvaImport);
	PIMAGE_IMPORT_DESCRIPTOR currentDescr = imageImport;
	printf("------------Import Names------------\n");
	while (TRUE)
	{
		// todo: check when it ends

		if (NULL == currentDescr || 0 == currentDescr->FirstThunk)
		{
			break;
		}
		PTCHAR importName = RVA_TO_VA(DWORD, pImageDosHeader, currentDescr->Name);
		_tprintf(_T("Import: %s\n"), importName);
		//	   foreach function:
		//			name, address
		PIMAGE_THUNK_DATA32 pThunk = RVA_TO_VA(PIMAGE_THUNK_DATA32, pImageDosHeader, currentDescr->OriginalFirstThunk);
		PTCHAR dllName = RVA_TO_VA(PTCHAR, pImageDosHeader, currentDescr->Name);

		HMODULE dllModule = LoadLibrary(dllName);
		while (TRUE)
		{
			if (NULL == *(DWORD*)pThunk)
			{
				break;
			}

			PTCHAR funcName = RVA_TO_VA(PTCHAR, RVA_TO_VA(DWORD, pImageDosHeader, pThunk->u1.Function), 2);

			_tprintf(_T("Function: %s\n"), funcName);

			//pThunk->u1.AddressOfData = funcAddr;

			pThunk++;
		}
		currentDescr++;
	}

	return 0;
}