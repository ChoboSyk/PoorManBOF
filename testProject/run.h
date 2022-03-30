#include <windows.h>
#include "function-resolution.h"

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef size_t (*STRLEN)(const char *str);


typedef VOID(WINAPI* SLEEP)(DWORD);

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

