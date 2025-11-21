#pragma once
#include "common.h"

typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR lpLibFileName);

HMODULE GetModuleHandleImpl(DWORD hashInput);
LPVOID getAPIAddr(HMODULE module, DWORD myHash);
FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char* sProcName, LoadLibraryA_t pLoadLibraryA);