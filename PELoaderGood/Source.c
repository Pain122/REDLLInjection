#include <Windows.h>
#include <stdio.h>
#include <tchar.h>

#define RVA_TO_VA(ptype, base, offset) (ptype)(((DWORD_PTR)(base)) + (offset))

typedef struct _REALLOCATIONS
{
	WORD Offset : 12;
	WORD Type : 4;
} REALLOCATIONS, * PREALLOCATIONS;

int main()
{

	HANDLE file = CreateFileA("C:\\Users\\pavel\\source\\repos\\REDLLInjection\\PELoader\\ex_original.exe",
		GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, 0, NULL);
	DWORD size = GetFileSize(file, NULL);

	HANDLE mapping = CreateFileMappingA(file, NULL, SEC_IMAGE | PAGE_READONLY, 0, 0, NULL);

	LPVOID pImageBase = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
	PIMAGE_NT_HEADERS32 pImageNtHeader = RVA_TO_VA(PIMAGE_NT_HEADERS32, pImageDosHeader, pImageDosHeader->e_lfanew);

	LPVOID peImage = VirtualAlloc(NULL, pImageNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	MoveMemory(peImage, pImageBase, pImageNtHeader->OptionalHeader.SizeOfHeaders); // May be wrong

	// sections

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNtHeader);
	DWORD dwNumSections = pImageNtHeader->FileHeader.NumberOfSections;
	DWORD i = 0;

	DWORD pText = 0;
	char text[5] = ".text";


	while (i < dwNumSections)
	{
		LPVOID pDest = RVA_TO_VA(LPVOID, peImage, pSection->VirtualAddress);
		LPVOID pSrc = RVA_TO_VA(LPVOID, pImageBase, pSection->VirtualAddress);
		DWORD dwSize = pSection->SizeOfRawData;

		if (strcmp(text, pSection->Name, 5))
		{

		}

		if (dwSize != 0)
		{
			MoveMemory(pDest, pSrc, dwSize);
		}
		pSection++;
		i++;
	}

	// imports
	DWORD imageImportDescrVA = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescr = RVA_TO_VA(PIMAGE_IMPORT_DESCRIPTOR, peImage, imageImportDescrVA);
	PIMAGE_IMPORT_DESCRIPTOR currentDescr = pImageImportDescr;

	while (TRUE)
	{
		if (NULL == *(DWORD*)currentDescr)
		{
			break;
		}

		PTCHAR dllName = RVA_TO_VA(PTCHAR, peImage, currentDescr->Name);

		HMODULE dllModule = LoadLibrary(dllName);

		PIMAGE_THUNK_DATA32 pThunk = RVA_TO_VA(PIMAGE_THUNK_DATA32, peImage, currentDescr->FirstThunk);

		while (TRUE)
		{
			if (NULL == *(DWORD*)pThunk)
			{
				break;
			}

			PTCHAR funcName = RVA_TO_VA(PTCHAR, RVA_TO_VA(DWORD, pImageDosHeader, pThunk->u1.Function), 2);
			DWORD funcAddr = GetProcAddress(dllModule, funcName);

			pThunk->u1.AddressOfData = funcAddr;


			pThunk++;
		}


		currentDescr++;
	}

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNtHeader);
	// AddressOfEntry
	// numberofsections
	DWORD nSections = pImageNtHeader->FileHeader.NumberOfSections;

	while (i < dwNumSections)
	{
		LPVOID pDest = RVA_TO_VA(LPVOID, peImage, pSection->VirtualAddress);
		LPVOID pSrc = RVA_TO_VA(LPVOID, pImageBase, pSection->VirtualAddress);
		DWORD dwSize = pSection->SizeOfRawData;

		PDWORD iter = RVA_TO_VA(PDWORD, peImage, pSection->VirtualAddress);
		
	}

	//start

	DWORD peEntry = RVA_TO_VA(DWORD, peImage, pImageNtHeader->OptionalHeader.AddressOfEntryPoint);

	__asm
	{
		mov eax, [peEntry]
		jmp eax
	}

	return 1;
}