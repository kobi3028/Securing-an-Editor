// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <FCNTL.H>
#include <io.h>
#include <iostream>
#include <ctime>
#include <string>
#include <sstream>
#include <vector>
#include <mutex>
#include <map>
#include <fstream>
#include <streambuf>
#include <sys/stat.h>
#include <tlhelp32.h>
#include <random>
#include <ShlObj.h>
#include <CommCtrl.h>
#include <WinUser.h>
#include "Console.h"
#include "mbedtls\config.h"
#include "mbedtls\platform.h"
#include "mbedtls\aes.h"
#include "mbedtls\rsa.h"
#include "mbedtls\sha256.h"
#include "mbedtls\entropy.h"
#include "mbedtls\ctr_drbg.h"
#include "mbedtls\bignum.h"
#include "rapidjson/document.h"
#include "rapidjson/filereadstream.h"   // FileReadStream
#include "rapidjson/encodedstream.h"    // EncodedInputStream
#include "config.h"
//Link with the Advapi32.lib file.
#pragma comment (lib, "advapi32")
#pragma comment (lib, "comctl32.lib") 


// TODO: reference additional headers your program requires here
