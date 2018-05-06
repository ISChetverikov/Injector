#include <iostream>
#include <tchar.h>
#include <windows.h>
#include <TlHelp32.h>
#include <locale.h>

using namespace std;

//////////////////////////////////////////
// ����� PID �������� �� �����
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
// �������� �������� ���������� � �������� 
// ������������ ��������
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
		if (!Module32Next(hModuleSnap, &ModuleEntry)) // ����������� ��������
		{
			CloseHandle(hModuleSnap);
			return FALSE;
		}

	} while (lstrcmpi(ModuleEntry.szModule, libraryName)); // ���� ������ �������
	
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
		printf_s("�� ������� ����� ������� %S.\n\n", targetProcessName);
		return FALSE;
	}
	printf_s("������� %S ������. PID:%d.\n\n", targetProcessName, targetPID);


	hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, targetPID);
	if (!hTargetProcess)
	{
		printf_s("�� ������� ������� ������� � PID %d\n\n", targetPID);
		return FALSE;
	}
	printf_s("������� ������� ������.\n\n");

	// ��������� � ������� ������� ���������� ��� ����, ����� ������
	// ������ ��� ���������� � ����� �������, ��� ������� ���������� ���������
	hInjectedDll = LoadLibrary(INJECTED_DLL_NAME);
	if (!hInjectedDll)
	{
		printf_s("�� ������� ��������� ���������� %S.\n\n", INJECTED_DLL_NAME);
		return FALSE;
	}
	printf_s("����������  %S ��������� � ������� �������.\n\n", INJECTED_DLL_NAME);

	fullDllName = new WCHAR[MAX_PATH];
	GetModuleFileName(hInjectedDll, fullDllName, MAX_PATH);
	if (!fullDllName)
	{
		printf_s("�� ������� ����� ������ ���� �� ����������: %S.\n", INJECTED_DLL_NAME);
		return FALSE;
	}
	fullDllNameSize = wcslen(fullDllName) * 2;

	InjectCodeStartAddress = GetProcAddress(hInjectedDll, INJECTED_FUNCTION_NAME);
	/////////////////////////////////////////////////////////////////////

	// ���������� ������ ��� ���������� � ������ �������� ��������
	lpRemoteFullDllName = VirtualAllocEx(hTargetProcess, NULL, fullDllNameSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!lpRemoteFullDllName)
	{
		printf_s("�� ������� �������� ������ � ������� ��������!\n");
		return FALSE;
	}
	
	if (!WriteProcessMemory(hTargetProcess, lpRemoteFullDllName, fullDllName, fullDllNameSize, &NumberOfBytesWritten))
	{
		printf_s("�� ������� �������� � ���������� ������ � ������� ��������!\n");
		return FALSE;
	}
	////////////////////////////////////////////////////////////////////

	// �������� ���������� � �������� ������������ �������� �������� � �������� ��������
	LoadLibraryWAddr = GetProcAddress(GetModuleHandle(_T("Kernel32.dll")), "LoadLibraryW");
	if (!LoadLibraryWAddr)
	{
		printf_s("�� ������� ����� LoadLibraryW � Kernel32.dll!\n");
		return FALSE;
	}

	hThread = CreateRemoteThread(hTargetProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryWAddr, lpRemoteFullDllName, NULL, &TID);
	WaitForSingleObject(hThread, INFINITE);

	if (!IsLibraryLoad(targetPID, INJECTED_DLL_NAME))
	{
		printf_s("���������� %S �� ���� ��������� � ������� �������!\n\n", INJECTED_DLL_NAME);
		return FALSE;
	}
	printf_s("���������� %S ��������� � ������� �������!\n\n", INJECTED_DLL_NAME);
	////////////////////////////////////////////////////////////////////

	
	
	//������ �������������� �������� �������� � ������������� ����������
	LPVOID lpPID = VirtualAllocEx(hTargetProcess, NULL, sizeof(DWORD), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!lpPID)
	{
		printf_s("�� ������� �������� ������ � ������� ��������!\n");
		return FALSE;
	}

	LPDWORD buf = new DWORD;
	*buf = GetCurrentProcessId();
	if (!WriteProcessMemory(hTargetProcess, lpPID, buf, sizeof(DWORD), &NumberOfBytesWritten))
	{
		printf_s("�� ������� �������� � ���������� ������ � ������� ��������!\n");
		return FALSE;
	}

	// ����� �������������� ����
	hThread = CreateRemoteThread(hTargetProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)InjectCodeStartAddress, (LPVOID)lpPID, NULL, &TID);
	WaitForSingleObject(hThread, INFINITE);

	//�������� �������� ����������
	while (GetProcessID(targetProcessName))
	{
		Sleep(1000);
	}
	
	printf_s("\n���������� %S ���� �������.\n", targetProcessName);
	CloseHandle(hThread);
	CloseHandle(hTargetProcess);

	return 0;
}