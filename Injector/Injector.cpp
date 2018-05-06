#include <iostream>
#include <tchar.h>
#include <windows.h>
#include <TlHelp32.h>
#include <locale.h>

using namespace std;

//////////////////////////////////////////
// Поиск PID процесса по имени
//////////////////////////////////////////
DWORD GetProcessID(LPCWSTR procName)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hProcessSnap);
		return FALSE;
	}
	
	do
	{
		if (!Process32Next(hProcessSnap, &pe32))
		{
			CloseHandle(hProcessSnap);
			return FALSE;
		}
		
	} while (lstrcmpi(pe32.szExeFile, procName));

	CloseHandle(hProcessSnap);
	return pe32.th32ProcessID;
}

//////////////////////////////////////////
// Проверка загрузки библиотеки в адресное 
// пространство процесса
//////////////////////////////////////////
BOOL IsLibraryLoad(DWORD processID, LPCTSTR libraryName)
{
	HANDLE hModuleSnap;
	MODULEENTRY32 ModuleEntry;
	ModuleEntry.dwSize = sizeof(MODULEENTRY32);

	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hModuleSnap);
		return FALSE;
	}

	do
	{
		if (!Module32Next(hModuleSnap, &ModuleEntry)) // перечисляем процессы
		{
			CloseHandle(hModuleSnap);
			return FALSE;
		}

	} while (lstrcmpi(ModuleEntry.szModule, libraryName)); // ищем нужный процесс
	
	CloseHandle(hModuleSnap);
	return TRUE;
}

int _tmain(int argc, wchar_t *argv[])
{
	setlocale(LC_ALL, "Russian");

	if (argc != 2)
	{
		printf_s("Usage: Injector.exe NameOfProcessToInjection\n");
		return FALSE;
	}
	LPWSTR targetProcessName = argv[1];
		
	LPCTSTR INJECTED_DLL_NAME = _T("InjectCode.dll");
	LPCSTR INJECTED_FUNCTION_NAME = "injectFunction";

	DWORD targetPID;
	HANDLE hTargetProcess;
	HMODULE hInjectedDll;

	FARPROC InjectCodeStartAddress;
	SIZE_T fullDllNameSize;
	LPTSTR fullDllName;

	LPVOID lpRemoteFullDllName;
	SIZE_T NumberOfBytesWritten;

	FARPROC LoadLibraryWAddr;

	HANDLE hThread;
	DWORD TID;


	targetPID = GetProcessID(targetProcessName);
	if (!targetPID)
	{
		printf_s("Не удалось найти процесс %S.\n\n", targetProcessName);
		return FALSE;
	}
	printf_s("Процесс %S найден. PID:%d.\n\n", targetProcessName, targetPID);


	hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, targetPID);
	if (!hTargetProcess)
	{
		printf_s("Не удалось открыть процесс с PID %d\n\n", targetPID);
		return FALSE;
	}
	printf_s("Целевой процесс открыт.\n\n");

	// Загружаем в текущий процесс библиотеку для того, чтобы узнать
	// полное имя библиотеки и адрес функции, код которой необходимо выполнить
	hInjectedDll = LoadLibrary(INJECTED_DLL_NAME);
	if (!hInjectedDll)
	{
		printf_s("Не удалось загрузить библиотеку %S.\n\n", INJECTED_DLL_NAME);
		return FALSE;
	}
	printf_s("Библиотека  %S загружена в текущий процесс.\n\n", INJECTED_DLL_NAME);

	fullDllName = new WCHAR[MAX_PATH];
	GetModuleFileName(hInjectedDll, fullDllName, MAX_PATH);
	if (!fullDllName)
	{
		printf_s("Не удалось найти полный путь до библиотеки: %S.\n", INJECTED_DLL_NAME);
		return FALSE;
	}
	fullDllNameSize = wcslen(fullDllName) * 2;

	InjectCodeStartAddress = GetProcAddress(hInjectedDll, INJECTED_FUNCTION_NAME);
	/////////////////////////////////////////////////////////////////////

	// Записываем полное имя библиотеки в память целевого процесса
	lpRemoteFullDllName = VirtualAllocEx(hTargetProcess, NULL, fullDllNameSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!lpRemoteFullDllName)
	{
		printf_s("Не удалось выделить память в целевом процессе!\n");
		return FALSE;
	}
	
	if (!WriteProcessMemory(hTargetProcess, lpRemoteFullDllName, fullDllName, fullDllNameSize, &NumberOfBytesWritten))
	{
		printf_s("Не удалось записать в выделенную память в целевом процессе!\n");
		return FALSE;
	}
	////////////////////////////////////////////////////////////////////

	// Загрузка библиотеки в адресное пространство целевого процесса и проверка загпузки
	LoadLibraryWAddr = GetProcAddress(GetModuleHandle(_T("Kernel32.dll")), "LoadLibraryW");
	if (!LoadLibraryWAddr)
	{
		printf_s("Не удалось найти LoadLibraryW в Kernel32.dll!\n");
		return FALSE;
	}

	hThread = CreateRemoteThread(hTargetProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryWAddr, lpRemoteFullDllName, NULL, &TID);
	WaitForSingleObject(hThread, INFINITE);

	if (!IsLibraryLoad(targetPID, INJECTED_DLL_NAME))
	{
		printf_s("Библиотека %S не была загружена в целевой процесс!\n\n", INJECTED_DLL_NAME);
		return FALSE;
	}
	printf_s("Библиотека %S загружена в целевой процесс!\n\n", INJECTED_DLL_NAME);
	////////////////////////////////////////////////////////////////////

	
	
	//Запись идентификатора текущего процесса в инжектируемое приложение
	LPVOID lpPID = VirtualAllocEx(hTargetProcess, NULL, sizeof(DWORD), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!lpPID)
	{
		printf_s("Не удалось выделить память в целевом процессе!\n");
		return FALSE;
	}

	LPDWORD buf = new DWORD;
	*buf = GetCurrentProcessId();
	if (!WriteProcessMemory(hTargetProcess, lpPID, buf, sizeof(DWORD), &NumberOfBytesWritten))
	{
		printf_s("Не удалось записать в выделенную память в целевом процессе!\n");
		return FALSE;
	}

	// Вызов инжектируемого кода
	hThread = CreateRemoteThread(hTargetProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)InjectCodeStartAddress, (LPVOID)lpPID, NULL, &TID);
	WaitForSingleObject(hThread, INFINITE);

	//Ожидание закрытия приложения
	while (GetProcessID(targetProcessName))
	{
		Sleep(1000);
	}
	
	printf_s("\nПриложение %S было закрыто.\n", targetProcessName);
	CloseHandle(hThread);
	CloseHandle(hTargetProcess);

	return 0;
}