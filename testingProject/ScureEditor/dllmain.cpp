// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

#define SIZE 6
#define BUFSIZE 512
#define MAX_PATH 260
#define KEY_SIZE 2048
#define EXPONENT 65537
#define MAX_PASSWORD_SIZE 100
#define HEADER_SIZE 522
#define BITS_KEY_SIZE 192
#define CTR_BLOCK_SIZE 16

typedef BOOL(WINAPI* pReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);		// ReadFile prototype
BOOL WINAPI MyReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);				// Our detour

typedef BOOL(WINAPI* pWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);	// WriteFile prototype
BOOL WINAPI MyWriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);				// Our detour

typedef HANDLE(WINAPI* pCreateFile)(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);	// CreateFile prototype
HANDLE WINAPI MyCreateFile(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);				// Our detour

//function decleration
void BeginRedirectWF(LPVOID);
void BeginRedirectRF(LPVOID);
void BeginRedirectCF(LPVOID);
DWORD GetProcessIdByName(const wchar_t*);
bool StartHooking(std::vector<std::wstring>, DWORD);
void GetFilesInDirectory(std::vector<wchar_t*> &out, const std::wstring &directory);
void ListOfFileToIgnor(wchar_t* FilePath);
BOOL FileInIgnorFileList(const wchar_t* FileName);
BOOL IsConfig(HANDLE);
BOOL IsBackup(HANDLE);
LONG GetFilePointer(HANDLE hFile);
int gener_key();
bool fileExists(const std::string& );
int loadPublic();
int loadPrivate();
int encryptPrivateKeyFile();
void getPasswordFromUser();
std::string getAppDataPath();
//
std::recursive_mutex mutex;
//std::mutex mutex;
std::vector<std::wstring> ProgramToHook;
std::vector<wchar_t*> m_ListOfFileToIgnor;
std::map<std::wstring, unsigned char*> filesHeader;
unsigned char hashPassword[32];
//
mbedtls_rsa_context rsa_pr;
mbedtls_rsa_context rsa_pb;
//
pReadFile pOrigRFAddress = NULL;		//pointer to Original ReadFile function Address
pWriteFile pOrigWFAddress = NULL;		//pointer to Original WriteFile function Address
pCreateFile pOrigCFAddress = NULL;		//pointer to Original CreateFileW function Address

BYTE oldBytesRF[SIZE] = { 0 };			// backup for ReadFile
BYTE oldBytesWF[SIZE] = { 0 };			// backup for WriteFile
BYTE oldBytesCF[SIZE] = { 0 };			// backup for CreateFileW

BYTE JMPRF[SIZE] = { 0 };				// 6 byte JMP instruction From IAT to ReadFile Function
BYTE JMPWF[SIZE] = { 0 };				// 6 byte JMP instruction From IAT to WriteFile Function
BYTE JMPCF[SIZE] = { 0 };				// 6 byte JMP instruction From IAT to CreateFileW Function

DWORD oldProtectRF, myProtectRF = PAGE_EXECUTE_READWRITE;
DWORD oldProtectWF, myProtectWF = PAGE_EXECUTE_READWRITE;
DWORD oldProtectCF, myProtectCF = PAGE_EXECUTE_READWRITE;

INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved)
{
	std::srand(std::time(NULL));
	INT_PTR res = 0;
	wchar_t* FileName = NULL;
	wchar_t* path = NULL;
	//config cnf;
	switch (Reason)
	{
	case DLL_PROCESS_ATTACH:
		ProgramToHook.push_back(L"notepad++.exe");
		if (!StartHooking(ProgramToHook, GetCurrentProcessId()))
		{
			return 0;
		}
		//get password from user and save tha hash in the global vriable hashPassword
		getPasswordFromUser();
		//load RSA private and public key
		if (!fileExists(getAppDataPath() + "rsa_priv.txt") || !fileExists(getAppDataPath() + "rsa_pub.txt"))
		{
			//if the key dosn't exist create new key pair
			gener_key();
		}
		else
		{
			encryptPrivateKeyFile();
		}
		//load private and public key
		if (loadPrivate() || loadPublic())
		{
			MessageBoxW(NULL, L"Wrong Password!!!", NULL, MB_OK);
			exit(1);
		}
		//encrypt the private key file
		encryptPrivateKeyFile();

		//load list of file to ignor all the file in the program folder 
		FileName = new wchar_t[MAX_PATH + 1];
		res = GetModuleFileName(NULL, FileName, MAX_PATH);
		if (!res)
			return 0;
		ListOfFileToIgnor(FileName);
		delete FileName;
		path = new WCHAR[MAX_PATH];
		if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, path)))
		{
			wcscat_s(path, 26 * sizeof(WCHAR), L"\\AppData\\Roaming\\Notepad++");
			GetFilesInDirectory(m_ListOfFileToIgnor, path);
		}
		delete path;
		//get the original function adress in the IAT table for API hooking
		pOrigWFAddress = (pWriteFile)
			GetProcAddress(GetModuleHandle(L"kernel32.dll"), "WriteFile"); // get address of original Write File
		pOrigRFAddress = (pReadFile)
			GetProcAddress(GetModuleHandle(L"kernel32.dll"), "ReadFile"); // get address of original Read File
		pOrigCFAddress = (pCreateFile)
			GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateFileW"); // get address of original Create File

		//API hooking
		if (pOrigWFAddress != NULL)
			BeginRedirectWF(MyWriteFile);	    	// start detouring
		if (pOrigRFAddress != NULL)
			BeginRedirectRF(MyReadFile);	    	// start detouring
		if (pOrigCFAddress != NULL)
			BeginRedirectCF(MyCreateFile);	    	// start detouring
		break;
	case DLL_PROCESS_DETACH:
		//safe exit
		if (pOrigWFAddress != NULL)
			memcpy(pOrigWFAddress, oldBytesWF, SIZE);  	    	              // restore
		if (pOrigRFAddress != NULL)
			memcpy(pOrigRFAddress, oldBytesRF, SIZE);                  	      // restore
		if (pOrigCFAddress != NULL)
			memcpy(pOrigCFAddress, oldBytesCF, SIZE);                  	      // restore
		//free memory of global var
		try
		{
			while (!m_ListOfFileToIgnor.empty()) {
				delete m_ListOfFileToIgnor.back();
				m_ListOfFileToIgnor.pop_back();
			}
			m_ListOfFileToIgnor.clear();
			std::map<std::wstring, unsigned char*>::iterator dbIT;
			for (dbIT = filesHeader.begin(); dbIT != filesHeader.end(); ++dbIT)
			{
				delete dbIT->second;
			}
			filesHeader.clear();
		}
		catch (...)
		{
			//free malloc failed !!!
		}

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	//case DLL_THREAD_ATTACH:
	//case DLL_THREAD_DETACH:
		//break;
	}
	return TRUE;
}

void BeginRedirectRF(LPVOID newFunction)
{
	BYTE tempJMP[SIZE] = { 0xE9, 0x90, 0x90, 0x90, 0x90, 0xC3 };       // 0xE9 = JMP 0x90 = NOP oxC3 = RET
	memcpy(JMPRF, tempJMP, SIZE);                                      // store jmp instruction to JMP
	DWORD JMPSize = ((DWORD)newFunction - (DWORD)pOrigRFAddress - 5); // calculate jump distance
	VirtualProtect((LPVOID)pOrigRFAddress, SIZE,                      // assign read write protection
		PAGE_EXECUTE_READWRITE, &oldProtectRF);
	memcpy(oldBytesRF, pOrigRFAddress, SIZE);                          // make backup
	memcpy(&JMPRF[1], &JMPSize, 4);										// fill the nop's with the jump distance (JMP,distance(4bytes),RET)
	memcpy(pOrigRFAddress, JMPRF, SIZE);                               // set jump instruction at the beginning of the original function
	VirtualProtect((LPVOID)pOrigRFAddress, SIZE, oldProtectRF, NULL);  // reset protection
}

void BeginRedirectWF(LPVOID newFunction)
{
	BYTE tempJMP[SIZE] = { 0xE9, 0x90, 0x90, 0x90, 0x90, 0xC3 };       // 0xE9 = JMP 0x90 = NOP oxC3 = RET
	memcpy(JMPWF, tempJMP, SIZE);                                      // store jmp instruction to JMP
	DWORD JMPSize = ((DWORD)newFunction - (DWORD)pOrigWFAddress - 5); // calculate jump distance
	VirtualProtect((LPVOID)pOrigWFAddress, SIZE,                      // assign read write protection
		PAGE_EXECUTE_READWRITE, &oldProtectWF);
	memcpy(oldBytesWF, pOrigWFAddress, SIZE);                          // make backup
	memcpy(&JMPWF[1], &JMPSize, 4);										// fill the nop's with the jump distance (JMP,distance(4bytes),RET)
	memcpy(pOrigWFAddress, JMPWF, SIZE);                               // set jump instruction at the beginning of the original function
	VirtualProtect((LPVOID)pOrigWFAddress, SIZE, oldProtectWF, NULL);  // reset protection
}

void BeginRedirectCF(LPVOID newFunction)
{
	BYTE tempJMP[SIZE] = { 0xE9, 0x90, 0x90, 0x90, 0x90, 0xC3 };       // 0xE9 = JMP 0x90 = NOP oxC3 = RET
	memcpy(JMPCF, tempJMP, SIZE);                                      // store jmp instruction to JMP
	DWORD JMPSize = ((DWORD)newFunction - (DWORD)pOrigCFAddress - 5); // calculate jump distance
	VirtualProtect((LPVOID)pOrigCFAddress, SIZE,                      // assign read write protection
		PAGE_EXECUTE_READWRITE, &oldProtectCF);
	memcpy(oldBytesCF, pOrigCFAddress, SIZE);                          // make backup
	memcpy(&JMPCF[1], &JMPSize, 4);										// fill the nop's with the jump distance (JMP,distance(4bytes),RET)
	memcpy(pOrigCFAddress, JMPCF, SIZE);                               // set jump instruction at the beginning of the original function
	VirtualProtect((LPVOID)pOrigCFAddress, SIZE, oldProtectCF, NULL);  // reset protection
}


BOOL WINAPI MyReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
	LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
	std::lock_guard<std::recursive_mutex> _lock(mutex);
	//
	if ((int)hFile == HFILE_ERROR)//check if the file handle in valid 
		return false;
	//
	TCHAR Path[BUFSIZE];
	BOOL decrypt = FALSE;
	bool res = false;
	bool isConfig = false;
	bool isBackup = false;
	DWORD BytesRead = 0;
	DWORD countWord = 0;
	std::wstring fileName = L"";
	size_t nc_off = 0;
	//get file name
	GetFinalPathNameByHandle(hFile, Path, BUFSIZE, (VOLUME_NAME_NONE | FILE_NAME_OPENED));
	std::wstring path(Path);
	//chack if file encrypted
	int pos = path.find_last_of(L"\\");
	if (pos != std::wstring::npos)
		path = path.substr(pos + 1);
	//if that encrypted file the header will be in the filesHeader object
	if (filesHeader.find(path) != filesHeader.end())
	{
		decrypt = TRUE;
		LONG FilePointerLocation = GetFilePointer(hFile);
		if (!FilePointerLocation)//if this is the first buffer set the pointer to header size
		{
			SetFilePointer(hFile, HEADER_SIZE, NULL, FILE_BEGIN);
		}
	}
	//
	VirtualProtect((LPVOID)pOrigRFAddress, SIZE, myProtectRF, NULL);     // assign read write protection
	memcpy(pOrigRFAddress, oldBytesRF, SIZE);                            // restore backup
	//
	//read buffer from file
	res = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, &BytesRead, lpOverlapped);
	//
	if (!res)
		MessageBox(NULL, L"Error in Read File", NULL, 1);
	//Hooking
	memcpy(pOrigRFAddress, JMPRF, SIZE);                                 // set the jump instruction again
	VirtualProtect((LPVOID)pOrigRFAddress, SIZE, oldProtectRF, NULL);    // reset protection
	//check if it is BytesRead=0 or is config file or is in backup folder or the file is in ignor file list
	isConfig = IsConfig(hFile);
	isBackup = IsBackup(hFile);
	if (!BytesRead || isConfig || isBackup || FileInIgnorFileList(Path))
	{
		*lpNumberOfBytesRead = BytesRead;
		return res;
	}

	if (decrypt)
	{
		//AES CTR MODE
		unsigned char nonce_counter[CTR_BLOCK_SIZE] = { 0 }, stream_block[CTR_BLOCK_SIZE] = { 0 }, input[CTR_BLOCK_SIZE] = { 0 }, output[4096] = { 0 };
		unsigned char readHeader[HEADER_SIZE];
		memcpy(readHeader, filesHeader.find(path)->second, HEADER_SIZE);
		unsigned char key[24] = { 0 };
		const char *pers = "rsa_decrypt";
		//get key from heder and encrypt it
		mbedtls_rsa_context _rsa_pr(rsa_pr);
		mbedtls_entropy_context entropy;
		mbedtls_ctr_drbg_context ctr_drbg;
		mbedtls_ctr_drbg_init(&ctr_drbg);
		mbedtls_entropy_init(&entropy);
		mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
		mbedtls_rsa_pkcs1_decrypt(&_rsa_pr, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &_rsa_pr.len, readHeader + 2, key, 24);
		//copy nonce from header
		memcpy(nonce_counter, readHeader + 514, 8);
		//get file location 
		LONG64 counter = 0x00;
		LONG filePointerLocetion = GetFilePointer(hFile);
		filePointerLocetion -= HEADER_SIZE;

		//set counter after fix the locetion pointer
		counter = (filePointerLocetion - BytesRead) / CTR_BLOCK_SIZE;
		int tempBytesRead = BytesRead / CTR_BLOCK_SIZE;
		tempBytesRead *= CTR_BLOCK_SIZE;
		//
		mbedtls_aes_context context;
		mbedtls_aes_init(&context);
		mbedtls_aes_setkey_enc(&context, key, BITS_KEY_SIZE);
		unsigned char* buffer = (unsigned char*)lpBuffer;
		//reverse the counter byte
		unsigned char bytes[8];
		for (size_t i = 0; i < 8; i++)
		{
			bytes[i] = (counter >> (64 - ((i + 1) * 8))) & 0xFF;
		}
		//copy the reverse byte to the counter part
		memcpy((nonce_counter + 8), bytes, 8);
		//encrypt the file buffer (16 byte) by buffer
		for (int i = 0; i < tempBytesRead; i += CTR_BLOCK_SIZE)
		{
			memcpy(input, buffer, CTR_BLOCK_SIZE);
			mbedtls_aes_crypt_ctr(&context, CTR_BLOCK_SIZE, &nc_off, nonce_counter, stream_block, input, buffer);
			buffer += CTR_BLOCK_SIZE;
		}
		//decrypt the rest of the last buffer
		int leftToRead = BytesRead - tempBytesRead;
		if (leftToRead > 0)
		{
			memcpy(input, buffer, leftToRead);
			mbedtls_aes_crypt_ctr(&context, leftToRead, &nc_off, nonce_counter, stream_block, input, buffer);
			buffer += leftToRead;
		}
		filePointerLocetion = GetFilePointer(hFile);
		LARGE_INTEGER temp;
		GetFileSizeEx(hFile, &temp);
		//set null in the end of buffer if that the last buffer
		if (filePointerLocetion == temp.QuadPart)
		{
			*buffer = NULL;
			*(buffer + 1) = NULL;
		}
	}

	*lpNumberOfBytesRead = BytesRead;
	return res;
}

BOOL WINAPI MyWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
	LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
	std::lock_guard<std::recursive_mutex> lock(mutex);
	//std::lock_guard<std::mutex> _lock(mutex);
	
	if ((int)hFile == HFILE_ERROR)//check if the file handle in valid 
	{
		return false;
	}
	//
	bool isConfig = false;
	bool isBackup = false;
	TCHAR Path[BUFSIZE];
	size_t nc_off = 0;

	//
	VirtualProtect((LPVOID)pOrigWFAddress, SIZE, myProtectWF, NULL);     // assign read write protection
	memcpy(pOrigWFAddress, oldBytesWF, SIZE);                            // restore backup
	//
	GetFinalPathNameByHandle(hFile, Path, BUFSIZE, (VOLUME_NAME_NONE | FILE_NAME_OPENED));
	std::wstring path(Path);
	isBackup = IsBackup(hFile);
	isConfig = IsConfig(hFile);
	//
	if (!isConfig && !isBackup && !FileInIgnorFileList(Path))/*check if the key not exist*/
	{
		LONG fileLocetion = GetFilePointer(hFile);

		unsigned char* header = new unsigned char[HEADER_SIZE];
		if (!fileLocetion)// if this is the first buffer check if the file is allready build
		{
			char identetyTag[2] = { 0x21, 0x43 };
			char fromFile[2] = { 0 };
			if (strncmp(identetyTag, (char*)lpBuffer, 2))
			{
				/*BuildHeder SIZE = 2(header) + 512(KeyEncryption) + 8(nonce)*/
				/*set header*/
				header[0] = 0x12;
				header[1] = 0x34;
				/*set encrypted key*/
				unsigned char key[24];
				unsigned char buf[512];
				for (size_t i = 0; i < 24; i++)
				{
					key[i] = std::rand() % 255;
				}
				const char *pers = "rsa_encrypt";
				mbedtls_rsa_context _rsa_pb(rsa_pb);
				mbedtls_entropy_context entropy;
				mbedtls_ctr_drbg_context ctr_drbg;
				mbedtls_ctr_drbg_init(&ctr_drbg);
				mbedtls_entropy_init(&entropy);
				mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
				mbedtls_rsa_pkcs1_encrypt(&_rsa_pb, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, 24, key, buf);
				memcpy(header + 2, buf, 512);
				/*set nonce*/
				unsigned char newNonce[8];
				for (size_t i = 0; i < 8; i++)
				{
					newNonce[i] = std::rand() % 255;
				}
				//copy the nonce
				memcpy((header + 514), &newNonce, 8);
			}
			DWORD BytesWritten = 0;
			/*Append Data To Text*/
			path = path.substr(path.find_last_of(L"\\") + 1);
			filesHeader.insert(std::pair<std::wstring, unsigned char*>(path, header));
		}
		/*read key and nonce from headers Map and encrypt*/
		int pos = path.find_last_of(L"\\");
		if (pos != std::wstring::npos)
			path = path.substr(pos + 1);
		unsigned char nonce_counter[CTR_BLOCK_SIZE] = { 0 }, stream_block[CTR_BLOCK_SIZE] = { 0 }, input[CTR_BLOCK_SIZE] = { 0 }, output[4096] = { 0 };
		unsigned char readHeader[HEADER_SIZE];
		memcpy(readHeader, filesHeader.find(path)->second, HEADER_SIZE);
		unsigned char key[24] = { 0 };
		const char *pers = "rsa_decrypt";
		mbedtls_rsa_context _rsa_pr(rsa_pr);
		mbedtls_entropy_context entropy;
		mbedtls_ctr_drbg_context ctr_drbg;
		mbedtls_ctr_drbg_init(&ctr_drbg);
		mbedtls_entropy_init(&entropy);
		mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
		mbedtls_rsa_pkcs1_decrypt(&_rsa_pr, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &_rsa_pr.len, readHeader + 2, key, 24);
		//copy nonce from header
		memcpy(nonce_counter, readHeader + 514, 8);

		//write Header to buffer if that first buffer to write
		fileLocetion = GetFilePointer(hFile);
		if (!fileLocetion)
		{
			DWORD bytsWrite = 0;
			WriteFile(hFile, readHeader, HEADER_SIZE, &bytsWrite, NULL);
		}
		else
		{
			fileLocetion -= HEADER_SIZE;
		}
		LONG64 counter = fileLocetion / CTR_BLOCK_SIZE;
		//reverse the counter byte
		unsigned char bytes[8];
		for (size_t i = 0; i < 8; i++)
		{
			bytes[i] = (counter >> (64 - ((i + 1) * 8))) & 0xFF;
		}
		//copy the reverse byte to the counter part
		memcpy((nonce_counter + 8), bytes, 8);
		//
		int tempBytesWrite = nNumberOfBytesToWrite - (nNumberOfBytesToWrite % CTR_BLOCK_SIZE);

		mbedtls_aes_context context;
		mbedtls_aes_init(&context);
		mbedtls_aes_setkey_enc(&context, key, BITS_KEY_SIZE);
		unsigned char* buffer = (unsigned char*)lpBuffer;
		//
		for (int i = 0; i < tempBytesWrite; i += CTR_BLOCK_SIZE)
		{
			memcpy(input, buffer, CTR_BLOCK_SIZE);
			mbedtls_aes_crypt_ctr(&context, CTR_BLOCK_SIZE, &nc_off, nonce_counter, stream_block, input, buffer);
			buffer += CTR_BLOCK_SIZE;
		}
		int leftToRead = nNumberOfBytesToWrite - tempBytesWrite;
		if (leftToRead > 0)
		{
			memcpy(input, buffer, leftToRead);
			mbedtls_aes_crypt_ctr(&context, leftToRead, &nc_off, nonce_counter, stream_block, input, buffer);
			buffer += leftToRead;
		}
	}
	int wordCount = 0;
	BOOL res = FALSE;
	DWORD BytesWritten = 0;
	res = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, &BytesWritten, lpOverlapped);
	if (!res)
		MessageBox(NULL, L"Error in Write File", NULL, 1);
	wordCount += BytesWritten;
	*lpNumberOfBytesWritten = BytesWritten;
	//
	memcpy(pOrigWFAddress, JMPWF, SIZE);                                 // set the jump instruction again
	VirtualProtect((LPVOID)pOrigWFAddress, SIZE, oldProtectWF, NULL);    // reset protection
	return res;
}

HANDLE WINAPI MyCreateFile(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	std::lock_guard<std::recursive_mutex> _lock(mutex);
	//std::lock_guard<std::mutex> _lock(mutex);
	

	VirtualProtect((LPVOID)pOrigCFAddress, SIZE, myProtectCF, NULL);     // assign read write protection
	memcpy(pOrigCFAddress, oldBytesCF, SIZE);                            // restore backup

	HANDLE hFile = CreateFile(lpFileName, (GENERIC_READ | GENERIC_WRITE), dwShareMode, lpSecurityAttributes,
		dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

	if ((int)hFile == HFILE_ERROR)//check if the file handle in valid 
	{
		memcpy(pOrigCFAddress, JMPCF, SIZE);                                 // set the jump instruction again
		VirtualProtect((LPVOID)pOrigCFAddress, SIZE, oldProtectCF, NULL);    // reset protection
		return hFile;
	}


	DWORD FileSize = 0;
	FileSize = GetFileSize(hFile, NULL);
	unsigned char* header = new unsigned char[HEADER_SIZE];
	unsigned char Flag[2] = { 0x12, 0x34 };
	std::wstring fileName(lpFileName);
	int pos = fileName.find_last_of('\\') + 1;
	if (pos > 0)
		fileName = fileName.substr(pos);
	if (FileSize > HEADER_SIZE && !IsConfig(hFile) && !FileInIgnorFileList(fileName.c_str()))
	{
		DWORD BytsRead = 0;
		ReadFile(hFile, (LPVOID)header, HEADER_SIZE, &BytsRead, NULL);
		if (!strncmp((char*)header, (char*)Flag, 2))
		{
			TCHAR Path[BUFSIZE];
			GetFinalPathNameByHandle(hFile, Path, BUFSIZE, (VOLUME_NAME_NONE | FILE_NAME_OPENED));
			std::wstring path(Path);
			path = path.substr(path.find_last_of(L"\\") + 1);
			filesHeader.insert(std::pair<std::wstring, unsigned char*>(path, header));
		}
		else
		{
			SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
		}
	}

	memcpy(pOrigCFAddress, JMPCF, SIZE);                                 // set the jump instruction again
	VirtualProtect((LPVOID)pOrigCFAddress, SIZE, oldProtectCF, NULL);    // reset protection

	return hFile;
}

//chack if the Attach Process is in the List of Program To Hook list
bool StartHooking(std::vector<std::wstring> ProgramToHook, DWORD CurrentProcessId)
{
	for each (std::wstring var in ProgramToHook)
	{
		if (GetProcessIdByName(var.c_str()) == CurrentProcessId)
			return true;
	}
	return false;
}
//get process ID by its Name (example: "notepad.exe") -- Idea from stackoverflow
DWORD GetProcessIdByName(const wchar_t *processName)
{
	DWORD exists = 0;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry))
		while (Process32Next(snapshot, &entry))
			if (!_wcsicmp(entry.szExeFile, processName))
				return entry.th32ProcessID;

	CloseHandle(snapshot);
	return exists;
}
//Returns a list of files in a directory (except the ones that begin with a dot) 
void GetFilesInDirectory(std::vector<wchar_t*> &out, const std::wstring &directory)
{
	HANDLE dir;
	WIN32_FIND_DATA file_data;

	if ((dir = FindFirstFile((directory + L"\\*").c_str(), &file_data)) == INVALID_HANDLE_VALUE)
		return; /* No files found */

	do {
		const std::wstring file_name = file_data.cFileName;
		const std::wstring full_file_name = directory + L"\\" + file_name;
		const bool is_directory = (file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

		if (file_name[0] == '.')
			continue;

		if (is_directory)
		{
			GetFilesInDirectory(out, full_file_name);
			continue;
		}
		wchar_t* temp = new wchar_t[full_file_name.length() + 1];
		memcpy(temp, full_file_name.c_str(), full_file_name.length() * 2);
		temp[full_file_name.length()] = '\0';
		out.push_back(temp);
	} while (FindNextFile(dir, &file_data));

	FindClose(dir);
} // GetFilesInDirectory
//loud m_ListOfFileToIgnor with file to ignor
void ListOfFileToIgnor(wchar_t* FilePath)
{
	std::wstring tempFileName(FilePath);
	tempFileName = tempFileName.substr(0, tempFileName.find_last_of('\\'));
	GetFilesInDirectory(m_ListOfFileToIgnor, tempFileName);
}
//check if the file is in the ignor file list
BOOL FileInIgnorFileList(const wchar_t* FileName)
{
	for (size_t i = 0; i < m_ListOfFileToIgnor.size(); i++)
	{
		if (std::wcsstr(m_ListOfFileToIgnor[i], FileName))
		{
			return true;
		}
	}
	return false;
}
//check if the file is config file
BOOL IsConfig(HANDLE hFile)
{
	TCHAR Path[BUFSIZE];
	GetFinalPathNameByHandle(hFile, Path, BUFSIZE, (VOLUME_NAME_NONE | FILE_NAME_OPENED));
	if (wcsstr(Path, L"\\Notepad++\\config") != NULL)
		return true;
	return false;
}
//check if the fike is backup file
BOOL IsBackup(HANDLE hFile)
{
	TCHAR Path[BUFSIZE];
	GetFinalPathNameByHandle(hFile, Path, BUFSIZE, (VOLUME_NAME_NONE | FILE_NAME_OPENED));
	if (wcsstr(Path, L"\\AppData\\Roaming\\Notepad++\\backup\\") != NULL)
		return true;
	return false;
}
//get file pointer location
LONG GetFilePointer(HANDLE hFile)
{
	return SetFilePointer(hFile, 0, 0, FILE_CURRENT);
}
//
std::string getAppDataPath()
{
	char env[100];
	memcpy_s(env, 99, getenv("APPDATA"), 99);
	std::string envVar(env);
	int pos = envVar.find_first_of(';');
	if (pos)
		//You should not be here
		envVar = envVar.substr(0, pos - 1);
	return envVar + "\\Notepad++\\";
}
//from mbedtls
int gener_key()
{
	int ret;
	mbedtls_rsa_context rsa;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	FILE *fpub = NULL;
	FILE *fpriv = NULL;
	const char *pers = "rsa_genkey";

	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_printf("\n  . Seeding the random number generator...");
	fflush(stdout);

	mbedtls_entropy_init(&entropy);
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		(const unsigned char *)pers,
		strlen(pers))) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
		goto exit;
	}

	mbedtls_printf(" ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE);
	fflush(stdout);

	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

	if ((ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
		EXPONENT)) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret);
		goto exit;
	}

	mbedtls_printf(" ok\n  . Exporting the public  key in rsa_pub.txt....");
	fflush(stdout);

	if ((fpub = fopen((getAppDataPath() + "rsa_pub.txt").c_str(), "wb+")) == NULL)
	{
		mbedtls_printf(" failed\n  ! could not open rsa_pub.txt for writing\n\n");
		ret = 1;
		goto exit;
	}

	if ((ret = mbedtls_mpi_write_file("N = ", &rsa.N, 16, fpub)) != 0 ||
		(ret = mbedtls_mpi_write_file("E = ", &rsa.E, 16, fpub)) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret);
		goto exit;
	}
	fclose(fpub);
	mbedtls_printf(" ok\n  . Exporting the private key in rsa_priv.txt...");
	fflush(stdout);

	if ((fpriv = fopen((getAppDataPath() + "rsa_priv.txt").c_str(), "wb+")) == NULL)
	{
		mbedtls_printf(" failed\n  ! could not open rsa_priv.txt for writing\n");
		ret = 1;
		goto exit;
	}

	if ((ret = mbedtls_mpi_write_file("N = ", &rsa.N, 16, fpriv)) != 0 ||
		(ret = mbedtls_mpi_write_file("E = ", &rsa.E, 16, fpriv)) != 0 ||
		(ret = mbedtls_mpi_write_file("D = ", &rsa.D, 16, fpriv)) != 0 ||
		(ret = mbedtls_mpi_write_file("P = ", &rsa.P, 16, fpriv)) != 0 ||
		(ret = mbedtls_mpi_write_file("Q = ", &rsa.Q, 16, fpriv)) != 0 ||
		(ret = mbedtls_mpi_write_file("DP = ", &rsa.DP, 16, fpriv)) != 0 ||
		(ret = mbedtls_mpi_write_file("DQ = ", &rsa.DQ, 16, fpriv)) != 0 ||
		(ret = mbedtls_mpi_write_file("QP = ", &rsa.QP, 16, fpriv)) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret);
		goto exit;
	}
	fclose(fpriv);
	/*
	mbedtls_printf( " ok\n  . Generating the certificate..." );

	x509write_init_raw( &cert );
	x509write_add_pubkey( &cert, &rsa );
	x509write_add_subject( &cert, "CN='localhost'" );
	x509write_add_validity( &cert, "2007-09-06 17:00:32",
	"2010-09-06 17:00:32" );
	x509write_create_selfsign( &cert, &rsa );
	x509write_crtfile( &cert, "cert.der", X509_OUTPUT_DER );
	x509write_crtfile( &cert, "cert.pem", X509_OUTPUT_PEM );
	x509write_free_raw( &cert );
	*/
	mbedtls_printf(" ok\n\n");

exit:

	if (fpub != NULL)
		fclose(fpub);

	if (fpriv != NULL)
		fclose(fpriv);

	mbedtls_rsa_free(&rsa);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

#if defined(_WIN32)
	mbedtls_printf("  Press Enter to exit this program.\n");
	fflush(stdout); getchar();
#endif

	return(ret);
}
//check if file exist
bool fileExists(const std::string& name)
{
	std::ifstream f(name.c_str());
	if (f.good()) {
		f.close();
		return true;
	}
	else {
		f.close();
		return false;
	}
}
//from mbedtls - load rsa public key from file
int loadPublic()
{
	FILE *f;
	int ret = 0;
	if ((f = fopen((getAppDataPath() + "rsa_pub.txt").c_str(), "rb")) == NULL)
	{
		ret = 1;
		return ret;
	}

	mbedtls_rsa_init(&rsa_pb, MBEDTLS_RSA_PKCS_V15, 0);

	if ((ret = mbedtls_mpi_read_file(&rsa_pb.N, 16, f)) != 0 ||
		(ret = mbedtls_mpi_read_file(&rsa_pb.E, 16, f)) != 0)
	{
		ret = 1;
		return ret;
	}

	rsa_pb.len = (mbedtls_mpi_bitlen(&rsa_pb.N) + 7) >> 3;
	fclose(f);
	return ret;
}
//from mbedtls - load rsa private key from file
int loadPrivate()
{
	FILE *f;
	int ret = 0;
	if ((f = fopen((getAppDataPath() + "rsa_priv.txt").c_str(), "rb")) == NULL)
	{
		ret = 1;
		return ret;
	}

	mbedtls_rsa_init(&rsa_pr, MBEDTLS_RSA_PKCS_V15, 0);
	if ((ret = mbedtls_mpi_read_file(&rsa_pr.N, 16, f)) != 0 ||
		(ret = mbedtls_mpi_read_file(&rsa_pr.E, 16, f)) != 0 ||
		(ret = mbedtls_mpi_read_file(&rsa_pr.D, 16, f)) != 0 ||
		(ret = mbedtls_mpi_read_file(&rsa_pr.P, 16, f)) != 0 ||
		(ret = mbedtls_mpi_read_file(&rsa_pr.Q, 16, f)) != 0 ||
		(ret = mbedtls_mpi_read_file(&rsa_pr.DP, 16, f)) != 0 ||
		(ret = mbedtls_mpi_read_file(&rsa_pr.DQ, 16, f)) != 0 ||
		(ret = mbedtls_mpi_read_file(&rsa_pr.QP, 16, f)) != 0)
	{
		ret = 1;
		return ret;
	}

	rsa_pr.len = (mbedtls_mpi_bitlen(&rsa_pr.N) + 7) >> 3;

	fclose(f);
	return ret;
}
//encrypt the Private Key File
int encryptPrivateKeyFile()
{
	//encrypt/decrypt the file
	int ret = 1;
	int size;
	char *contents = NULL;
	std::ifstream RFile((getAppDataPath() + "rsa_priv.txt").c_str(), std::ios::in | std::ios::binary);
	if (RFile.is_open())
	{
		RFile.seekg(0, std::ios::end);
		size = RFile.tellg();
		contents = new char[size];
		RFile.seekg(0, std::ios::beg);
		RFile.read(contents, size);
		RFile.close();
	}
	mbedtls_aes_context context;
	mbedtls_aes_init(&context);
	mbedtls_aes_setkey_enc(&context, hashPassword, 256);
	int tempBytesWrite = size - (size % CTR_BLOCK_SIZE);
	//nonce = 0 AND counter = 0;
	unsigned char nonce_counter[CTR_BLOCK_SIZE] = { 0 }, stream_block[CTR_BLOCK_SIZE] = { 0 }, input[CTR_BLOCK_SIZE] = { 0 };
	unsigned char* buffer = (unsigned char*)contents;
	size_t nc_off = 0;
	for (int i = 0; i < tempBytesWrite; i += CTR_BLOCK_SIZE)
	{
		memcpy(input, buffer, CTR_BLOCK_SIZE);
		mbedtls_aes_crypt_ctr(&context, CTR_BLOCK_SIZE, &nc_off, nonce_counter, stream_block, input, buffer);
		buffer += CTR_BLOCK_SIZE;
	}
	int leftToRead = size - tempBytesWrite;
	if (leftToRead > 0)
	{
		memcpy(input, buffer, leftToRead);
		mbedtls_aes_crypt_ctr(&context, leftToRead, &nc_off, nonce_counter, stream_block, input, buffer);
		buffer += leftToRead;
	}
	std::ofstream WFile((getAppDataPath() + "rsa_priv.txt").c_str(), std::ios::in | std::ios::binary);
	if (WFile.is_open())
	{
		WFile.seekp(0, std::ios::beg);
		WFile.write(contents, size);
		WFile.close();
	}
	contents[size - 1] = NULL;
	delete contents;
	return 0;
}
//get password from user(with console window)
void getPasswordFromUser()
{
	char buf[MAX_PASSWORD_SIZE] = { 0 };
	//create console object;
	CConsole* newConsole;
	newConsole = new CConsole();
	do
	{
		std::cout << "Insert Password:\n";
		gets_s(buf, MAX_PASSWORD_SIZE);
	} while (!buf[0]);//no password inserted
	try
	{
		if (newConsole)
			delete newConsole;
	} catch (...)
	{/*don't know how to fix it!*/}
	//hash the password
	mbedtls_sha256((unsigned char*)buf, MAX_PASSWORD_SIZE, hashPassword, 0);
}