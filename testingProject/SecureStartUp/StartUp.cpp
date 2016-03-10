#include <vector>
#include <string>
#include <windows.h>
#include <Tlhelp32.h>
#include <Shlobj.h>
#include <memory>
#define MAX_PATH 260

HANDLE startup(LPCTSTR lpApplicationName)
{
	// additional information
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	// set the size of the structures
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// start the program up
	CreateProcess(lpApplicationName,   // the path
		NULL,        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		CREATE_SUSPENDED,// create in suspended mode
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		;
		// Close process and thread handles.
		CloseHandle(pi.hProcess);
		//return handle of the main thread
		return pi.hThread;
}

int main()
{
	
	LPCTSTR path = L"C:\\Program Files (x86)\\Notepad++\\notepad++.exe";
	//start notepad++ in resume mode
	HANDLE hThread = startup(path);
	//
	std::vector<std::wstring> processNames;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	BOOL bProcess = Process32First(hTool32, &pe32);
	if (bProcess == TRUE)
	{
		while ((Process32Next(hTool32, &pe32)) == TRUE)
		{
			processNames.push_back(pe32.szExeFile);
			//find if the pe32 is off notepad++ 
			if (std::wcsstr(pe32.szExeFile, L"notepad++.exe"))
			{
				WCHAR* DirPath = new WCHAR[MAX_PATH];
				DirPath[0] = NULL;
				DirPath[1] = NULL;
				WCHAR* FullPath = new WCHAR[MAX_PATH];
				FullPath[0] = NULL;
				FullPath[1] = NULL;
				GetCurrentDirectory(MAX_PATH, DirPath);
				wcscat(FullPath, DirPath);
				wcscat(FullPath, L"\\ScureEditor.dll");
				//get handle to the notepade++ process
				HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
					PROCESS_VM_WRITE, FALSE, pe32.th32ProcessID);
				//get pointer the LoadLibraryW func 
				LPVOID LoadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"),
					"LoadLibraryW");
				int len = wcslen(FullPath);
				LPVOID LLParam = (LPVOID)VirtualAllocEx(hProcess, NULL, len,
					MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
				//write the path to process len*2 due to the ize of WCHAR (2 bytes)
				WriteProcessMemory(hProcess, LLParam, FullPath, len*2, NULL);
				//the start address off the new thread is LoadLibraryA, with our string passed as the parameter
				CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryAddr,
					LLParam, NULL, NULL);
				CloseHandle(hProcess);
				delete[] DirPath;
				delete[] FullPath;
				//resume notepad++ main thread
				ResumeThread(hThread);
				CloseHandle(hThread);
				break;
			}	
		}
	}
	CloseHandle(hTool32);
}