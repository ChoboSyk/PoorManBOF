#include <windows.h>
#include "function-resolution.h"

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef size_t (*STRLEN)(const char *str);


typedef HANDLE(WINAPI* OPENPROCESS)(DWORD,BOOL,DWORD);
typedef HANDLE(WINAPI* GETCURRENTPROCESS)();
typedef BOOL(WINAPI* OPENPROCESSTOKEN)(HANDLE,DWORD,PHANDLE);
typedef BOOL(WINAPI* LOOKUPPRIVILEGEVALUEA)(LPCTSTR,LPCTSTR,PLUID);
typedef BOOL(WINAPI* ADJUSTTOKENPRIVILEGES)(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
typedef BOOL(WINAPI* DUPLICATETOKENEX)(HANDLE,DWORD,LPSECURITY_ATTRIBUTES,SECURITY_IMPERSONATION_LEVEL,TOKEN_TYPE,PHANDLE);
typedef BOOL(WINAPI* CREATEPROCESSWITHTOKENW)(HANDLE,DWORD,LPCWSTR,LPWSTR,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);


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

void printz(char** output, CHAR text[]) {

	for (int i = 0; i < 10000; i++) {
		if (i > 2) {
			if (text[i] == 0 && text[i - 1] == 0 && text[i - 2] == 0 && text[i - 3] == 0) {
				break;
			}
		}
		if(text[i] != 0){
			**output = text[i];
			*output = *output + 1;
		}

	}
}

