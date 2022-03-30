#include <windows.h>
#include "function-resolution.h"


typedef struct THREADENTRY32 {
	DWORD dwSize;
	DWORD cntUsage;
	DWORD th32ThreadID;
	DWORD th32OwnerProcessID;
	LONG  tpBasePri;
	LONG  tpDeltaPri;
	DWORD dwFlags;
}THREADENTRY32, *LPTHREADENTRY32;



typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef size_t (*STRLEN)(const char *str);


typedef HANDLE(WINAPI* OPENPROCESS)(DWORD,BOOL,DWORD);
typedef HANDLE(WINAPI* GETCURRENTPROCESS)();
typedef BOOL(WINAPI* OPENPROCESSTOKEN)(HANDLE,DWORD,PHANDLE);
typedef BOOL(WINAPI* LOOKUPPRIVILEGEVALUEA)(LPCTSTR,LPCTSTR,PLUID);
typedef BOOL(WINAPI* ADJUSTTOKENPRIVILEGES)(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
typedef BOOL(WINAPI* DUPLICATETOKEN)(HANDLE,SECURITY_IMPERSONATION_LEVEL,PHANDLE);
typedef BOOL(WINAPI* SETTHREADTOKEN)(PHANDLE,HANDLE);
typedef BOOL(WINAPI* THREAD32FIRST)(HANDLE, LPTHREADENTRY32);
typedef HANDLE(WINAPI* CREATETOOLHELP32SNAPSHOT)(DWORD, DWORD);
typedef HANDLE(WINAPI* THREAD32NEXT)(HANDLE, LPTHREADENTRY32);
typedef int (*PRINTF)(const char* format, ...);
typedef BOOL(WINAPI* CLOSEHANDLE)(HANDLE);
typedef DWORD(WINAPI* GETCURRENTPROCESSID)();
typedef HANDLE(WINAPI* OPENTHREAD)(DWORD, BOOL, DWORD);
typedef VOID(WINAPI* SLEEP)(DWORD);

typedef BOOL(WINAPI* GETUSERNAMEA)(LPTSTR, LPDWORD);

// djb2 hashes for dynamic function resolution.
#define KERNEL32DLL_HASH1   0xa709e74f /// Hash of KERNEL32.DLL
#define KERNEL32DLL_HASH2   0xa96f406f /// Hash of kernel32.dll
#define KERNEL32DLL_HASH3   0x8b03944f /// Hash of Kernel32.dll

void println(char** output, STRLEN strlenFunc, CHAR text[]) {
	
	for (int i = 0; i < strlenFunc(text); i++) {
		**output = text[i];
		*output = *output + 1;
	}
	**output = 0x0a;
	*output = *output + 1;
}

void print(char** output, STRLEN strlenFunc, CHAR text[]) {
	for (int i = 0; i < strlenFunc(text); i++) {
		**output = text[i];
		*output = *output + 1;
	}
}

