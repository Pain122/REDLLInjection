#if 0
#include <Header.h>
#include <tchar.h>

int _tmain()
{
	_tprintf(_T("from exe\n"));
	foo();

	return 0;
}
#endif

#include <Windows.h>

typedef HMODULE(_stdcall* pfnLoadLib)(LPCWSTR libname);

pfnLoadLib gLoadLib = LoadLibraryW;
const wchar_t* gLibName = L"C:\\Users\\pavel\\source\\repos\\REDLLInjection\\Release\\REDLLInjection.dll";

DWORD _declspec(noinline) Func()
{
	if (nullptr == gLoadLib(gLibName))
	{
		return -1;
	}
	return 0;
}

int main()
{
	Func();
}