#pragma once

#include <Windows.h>

template<class T>
DWORD ReadRemote(
	_In_ HANDLE hProc,
	_In_ ULONG_PTR offset,
	_Out_ T& value
)
{
	SIZE_T numBytesRead = 0;
	if (!ReadProcessMemory(hProc, (LPCVOID)offset, &value, sizeof(T), &numBytesRead))
	{
		DWORD err = GetLastError();
		_tprintf(_T("ReadProcessMemory failed with code 0x%x"), err);
		return err;
	}
	return 0;
}

template<class T>
DWORD ReadRemote(
	_In_ HANDLE hProc,
	_In_ ULONG_PTR offset,
	_Out_ T* value,
	DWORD& amount
)
{
	ULONG_PTR p = offset;
	DWORD counter = 0;
	T zero = {};

	for (;;)
	{
		T current;
		DWORD error = ReadRemote<T>(hProc, p, current);
		if (!error == 0)
		{
			_tprintf(_T("ReadRemote failed with code 0x%x"), error);
			return error;
		}
		value[counter] = current;
		counter++;

		if (0 != amount && counter == amount) break;

		p += sizeof(T);
		if (0 == amount && 0 == memcmp(&current, &zero, sizeof(T))) break;
	}

	counter--;
	amount - counter;

	return 0;
}

template<class T>
DWORD WriteRemote(
	_In_ HANDLE hProc,
	_In_ ULONG_PTR offset,
	_In_  const T& value
)
{
	SIZE_T numBytesWritten = 0;
	if (!WriteProcessMemory(hProc, (LPVOID)offset, &value, sizeof(T), &numBytesWritten))
	{
		DWORD err = GetLastError();
		_tprintf(_T("WriteProcessMemory failed with code 0x%x"), err);
		return err;
	}
	return 0;
}