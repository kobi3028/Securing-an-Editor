========================================================================
    DYNAMIC LINK LIBRARY : ProofOfConceptForSecureTheEditor Project Overview
========================================================================

Before Start:

1. Need set the AppInit_DLLs with the Dll full path (Priority to path without spaces)

For 32 bit DLL on 32 bit OS the path is:
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs]
 
For 64 bit DLL on 64 bit OS the path is: :
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs]

For 32 bit DLL on 64 bit system:
[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs]

2. Need set the LoadAppInit_DLLs to 1 (true)

For 32 bit DLL on 32 bit OS the path is:
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs]
 
For 64 bit DLL on 64 bit OS the path is: :
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs]

For 32 bit DLL on 64 bit system:
[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs]

now you can start Work with notepad.exe!!