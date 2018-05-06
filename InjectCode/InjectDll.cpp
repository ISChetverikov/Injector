#include <windows.h>
#include <TlHelp32.h>
#include <iostream>

using namespace std;

BOOL ReplaceIATEntryInModule(PCSTR pszCalleeModName, PROC pfnCurrent, PROC pfnNew, HMODULE hmodCaller);
BOOL WriteToRemoteConsole(LPWSTR);

DWORD InjectorPID;
HANDLE hMutex;

//////////////////////////////////////////////
typedef HANDLE(__stdcall *procCreateFileW)(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
	);

HANDLE WINAPI MyCreateFileW(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
	);

procCreateFileW OriginCreateFileW;
//////////////////////////////////////////////



extern "C" __declspec(dllexport) void __stdcall injectFunction(DWORD* injectorPID)
{
	InjectorPID = *injectorPID;
	hMutex = CreateMutexW(NULL, FALSE, TEXT("Mutex for remote console"));
	//HMODULE hModuleExe = 0;
	//GetModuleHandleEx(NULL, NULL, &hModuleExe);
	
	WaitForSingleObject(hMutex, INFINITE);
	LPWSTR phrase = TEXT("Внедрение перехватчика на функцию CreateFileW во все загруженные модули.\n\n");
	WriteToRemoteConsole(phrase);
	ReleaseMutex(hMutex);

	//Получение хэндлов всех загруженных в процесс модулей
	HANDLE hModuleSnap;
	MODULEENTRY32 ModuleEntry;
	ModuleEntry.dwSize = sizeof(MODULEENTRY32);

	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hModuleSnap);
		return;
	}

	while (Module32Next(hModuleSnap, &ModuleEntry))
	{
		WaitForSingleObject(hMutex, INFINITE);
		LPWSTR phrase1 = TEXT("Редактирование таблицы импорта модуля %s.............");
		LPWSTR buf1 = new WCHAR[wcslen(phrase1) + wcslen(ModuleEntry.szModule)];
		wsprintf(buf1, phrase1, ModuleEntry.szModule);
		WriteToRemoteConsole(buf1);
		delete[] buf1;

		OriginCreateFileW = (procCreateFileW)GetProcAddress(GetModuleHandle(L"Kernel32"), "CreateFileW");
		BOOL isSuccess = ReplaceIATEntryInModule("kernel32.dll", (FARPROC)OriginCreateFileW, (FARPROC)MyCreateFileW, ModuleEntry.hModule);

		LPWSTR phrase2 = (!isSuccess) ? TEXT("Неудача\n") : TEXT("Успех\n");
		LPWSTR buf2 = new WCHAR[wcslen(phrase2)];
		wsprintf(buf2, phrase2);
		WriteToRemoteConsole(buf2);
		delete[] buf2;
		ReleaseMutex(hMutex);
	}

	return;
}


HANDLE WINAPI MyCreateFileW(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
	)
{
	WaitForSingleObject(hMutex, INFINITE);

	HMODULE hCallerModule = 0;
	GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPWSTR>(_ReturnAddress()), &hCallerModule);
	LPWSTR callerLibraryName = new WCHAR[MAX_PATH];
	GetModuleFileName(hCallerModule, callerLibraryName, MAX_PATH);
	CloseHandle(hCallerModule);

	LPCWSTR phrase = TEXT("===========================================================\nПерехвачен вызов функции CreateFileW из модуля\n\t %s\nФайл:\n\t %s\n===========================================================\n");
	LPWSTR buf = new WCHAR[wcslen(phrase) + wcslen(lpFileName) + wcslen(callerLibraryName)];
	wsprintf(buf, phrase, callerLibraryName, lpFileName);
	WriteToRemoteConsole(buf);

	delete[]callerLibraryName;
	delete[]buf;
		
	ReleaseMutex(hMutex);
	return OriginCreateFileW(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
		);
}

BOOL WriteToRemoteConsole(LPWSTR text)
{
	

	BOOL result = FALSE;

	FreeConsole();
	if (AttachConsole(InjectorPID))
	{
		HANDLE hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);

		result = WriteConsoleW(hConsoleOutput, text, (DWORD)wcslen(text), 0, 0);

		CloseHandle(hConsoleOutput);
		FreeConsole();
	}

	return result;
}

BOOL ReplaceIATEntryInModule(PCSTR pszCalleeModName, FARPROC pfnCurrent, FARPROC pfnNew, HMODULE hmodCaller)
{

	ULONG ulSize;
	typedef PIMAGE_IMPORT_DESCRIPTOR(__stdcall *MYPROC)(void*, bool, unsigned short, unsigned long *);
	MYPROC ImageDirectoryEntryToData;

	HMODULE hDbgHelpDll = LoadLibrary(L"Dbghelp.dll");
	if (hDbgHelpDll)
	{
		
		ImageDirectoryEntryToData = (MYPROC)GetProcAddress(hDbgHelpDll, "ImageDirectoryEntryToData");

		PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hmodCaller, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);

		if (pImportDesc == NULL) return FALSE;

		for (; pImportDesc->Name; pImportDesc++)
		{
			PSTR pszModName = (PSTR)((PBYTE)hmodCaller + pImportDesc->Name);

			if (lstrcmpiA(pszModName, pszCalleeModName) == 0) break;
		}

		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((PBYTE)hmodCaller + pImportDesc->FirstThunk);
		
		for (; pThunk->u1.Function; pThunk++)
		{
			if ((PROC)pThunk->u1.Function == pfnCurrent)
			{
				
				DWORD old;
				
				VirtualProtect(&pThunk->u1.Function, 4, PAGE_READWRITE, &old);
				pThunk->u1.Function = (DWORD64)pfnNew;
				VirtualProtect(&pThunk->u1.Function, 4, old, &old);

				return TRUE;
			}
		}

	}

	return FALSE;
}



