#include "run.h"

void run(char* output)
{
#pragma region function-resolution
/// Resolve the address of KERNEL32.DLL via djb2 hash.
    LPVOID kernel32dll = NULL;
    kernel32dll = GetModuleByHash(KERNEL32DLL_HASH1);
    if (NULL == kernel32dll)
    {
        /// Resolve the address of kernel32.dll via djb2 hash.
        kernel32dll = GetModuleByHash(KERNEL32DLL_HASH2);
        if (NULL == kernel32dll)
        {
            /// Resolve the address of Kernel32.dll via djb2 hash.
            kernel32dll = GetModuleByHash(KERNEL32DLL_HASH3);
            if (NULL == kernel32dll) {
                return;
            }
        }
    }

    LOADLIBRARYA LoadLibraryAFunc;
    UINT64 msvcrtdll;
    STRLEN strlenFunc;
    CHAR loadlibrarya_c[] = "LoadLibraryA";
    LoadLibraryAFunc = _GetProcAddress((HANDLE)kernel32dll, loadlibrarya_c);
    CHAR msvcrt_c[] = "msvcrt.dll";
    msvcrtdll = (UINT64)((LOADLIBRARYA)LoadLibraryAFunc)(msvcrt_c);
    CHAR strlen_c[] = "strlen";
    strlenFunc = _GetProcAddress((HANDLE)msvcrtdll, strlen_c);
    
    UINT64 advapi32dll;
	DUPLICATETOKENEX DuplicateTokenExFunc;
	CHAR Advapi32_c[] = "advapi32.dll";
	advapi32dll = (UINT64)((LOADLIBRARYA)LoadLibraryAFunc)(Advapi32_c);
	CHAR duplicatetokenex_c[] = "DuplicateTokenEx";
	DuplicateTokenExFunc = _GetProcAddress((HANDLE)advapi32dll,duplicatetokenex_c);

    
    
    //Write Your code here
    //You send text back by using print or println by changing the VALUE_TO_PRINT 
    //to the string you want: "print(&output, strlenFunc, VALUE_TO_PRINT);
    //All Strings must be declared with the CHAR [] varname = ""; format.

    return;
}
