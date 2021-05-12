#include "ntifs.h" // \WinDDK\7600.16385.1\inc\ddk
#include "ntdef.h"

//------------------------------------
// Following function definitions can be found in native development kit
// but I am too lazy to include `em so I declare it here
//------------------------------------

NTSYSAPI
NTSTATUS
NTAPI
NtTerminateProcess(
  IN HANDLE               ProcessHandle OPTIONAL,
  IN NTSTATUS             ExitStatus
);

NTSYSAPI 
NTSTATUS
NTAPI
NtDisplayString(
	IN PUNICODE_STRING String
);

NTSTATUS 
NtWaitForSingleObject(
  IN HANDLE         Handle,
  IN BOOLEAN        Alertable,
  IN PLARGE_INTEGER Timeout
);

NTSYSAPI 
NTSTATUS
NTAPI
NtCreateEvent(
    OUT PHANDLE             EventHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
    IN EVENT_TYPE           EventType,
    IN BOOLEAN              InitialState
);



// https://docs.microsoft.com/en-us/windows/win32/api/ntddkbd/ns-ntddkbd-keyboard_input_data
typedef struct _KEYBOARD_INPUT_DATA {
  USHORT UnitId;
  USHORT MakeCode;
  USHORT Flags;
  USHORT Reserved;
  ULONG  ExtraInformation;
} KEYBOARD_INPUT_DATA, *PKEYBOARD_INPUT_DATA;

//----------------------------------------------------------
// Our code goes here
//----------------------------------------------------------

// usage: WriteLn(L"Hello Native World!\n");
void WriteLn(LPWSTR Message)
{
    UNICODE_STRING string;
    RtlInitUnicodeString(&string, Message);
    NtDisplayString(&string);
}

void NtProcessStartup(void* StartupArgument)
{
	// it is important to declare all variables at the beginning
	HANDLE hKeyBoard, hEvent;
	UNICODE_STRING skull, keyboard;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK Iosb;
	LARGE_INTEGER ByteOffset;
	KEYBOARD_INPUT_DATA kbData;
	
	PVOID memory = NULL;
	PVOID buffer = NULL;
	ULONG bufferSize = 42;

	//use it if debugger connected to break
	//DbgBreakPoint();

	WriteLn(L"Hello Native World!\n");

	// inialize variables
	RtlInitUnicodeString(&keyboard, L"\\Device\\KeyboardClass0");
	InitializeObjectAttributes(&ObjectAttributes, &keyboard, OBJ_CASE_INSENSITIVE, NULL, NULL);

	// open keyboard device
	NtCreateFile(&hKeyBoard,
				SYNCHRONIZE | GENERIC_READ | FILE_READ_ATTRIBUTES,
				&ObjectAttributes,
				&Iosb,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				0,
				FILE_OPEN,FILE_DIRECTORY_FILE,
				NULL, 0);

	// create event to wait on
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, &ObjectAttributes, 1, 0);
	
	WriteLn(L"Keyboard ready\n");
	
	// create heap in order to allocate memory later
	memory = RtlCreateHeap(
	  HEAP_GROWABLE, 
	  NULL, 
	  1000, 
	  0, NULL, NULL
	);
	
	WriteLn(L"Heap ready\n");

	// allocate buffer of size bufferSize
	buffer = RtlAllocateHeap(
	  memory, 
	  HEAP_ZERO_MEMORY, 
	  bufferSize
	);
	
	WriteLn(L"Buffer allocated\n");

	// free buffer (actually not needed because we destroy heap in next step)
	RtlFreeHeap(memory, 0, buffer);

	RtlDestroyHeap(memory);
	
	WriteLn(L"Heap destroyed\n");
	
	WriteLn(L"Press ESC to continue...\n");

	while (TRUE)
	{
		NtReadFile(hKeyBoard, hEvent, NULL, NULL, &Iosb, &kbData, sizeof(KEYBOARD_INPUT_DATA), &ByteOffset, NULL);
		NtWaitForSingleObject(hEvent, TRUE, NULL);

		if (kbData.MakeCode == 0x01)    // if ESC pressed
		{
				break;
		}
	}

	NtTerminateProcess(NtCurrentProcess(), 0);
}