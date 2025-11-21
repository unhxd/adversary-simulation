#include "common.h"

// The `#pragma intrinsic(memset)` and #pragma function(memset)macros are Microsoft - specific compiler instructions.
// They force the compiler to generate code for the memset function using a built-in intrinsic function.
#pragma intrinsic(memset)
#pragma function(memset)

void* __cdecl memset(void* Destination, int Value, size_t Size) {
	// logic similar to memset's one
	unsigned char* p = (unsigned char*)Destination;
	while (Size > 0) {
		*p = (unsigned char)Value;
		p++;
		Size--;
	}
	return Destination;
}

PVOID CopyMemoryEx(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

PPEB GetPeb(VOID)
{
#if defined(_WIN64)
	return (PPEB)__readgsqword(0x60);
#elif define(_WIN32)
	return (PPEB)__readfsdword(0x30);
#endif
}

HANDLE GetProcessHeapFromTeb(VOID)
{
	return GetPeb()->ProcessHeap;
}

INT StringCompareA(_In_ LPCSTR String1, _In_ LPCSTR String2)
{
	for (; *String1 == *String2; String1++, String2++)
	{
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCSTR)String1 < *(LPCSTR)String2) ? -1 : +1);
}

INT StringCompareW(_In_ LPCWSTR String1, _In_ LPCWSTR String2)
{
	for (; *String1 == *String2; String1++, String2++)
	{
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCWSTR)String1 < *(LPCWSTR)String2) ? -1 : +1);
}

PCHAR StringCopyA(_Inout_ PCHAR String1, _In_ LPCSTR String2)
{
	PCHAR p = String1;

	while ((*p++ = *String2++) != 0);

	return String1;
}

PWCHAR StringCopyW(_Inout_ PWCHAR String1, _In_ LPCWSTR String2)
{
	PWCHAR p = String1;

	while ((*p++ = *String2++) != 0);

	return String1;
}

SIZE_T StringLengthA(_In_ LPCSTR String)
{
	LPCSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

SIZE_T StringLengthW(_In_ LPCWSTR String)
{
	LPCWSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

PWCHAR StringConcatW(_Inout_ PWCHAR String, _In_ LPCWSTR String2)
{
	StringCopyW(&String[StringLengthW(String)], String2);

	return String;
}

PCHAR StringConcatA(_Inout_ PCHAR String, _In_ LPCSTR String2)
{
	StringCopyA(&String[StringLengthA(String)], String2);

	return String;
}

PCHAR StringLocateCharA(_Inout_ PCHAR String, _In_ INT Character)
{
	do
	{
		if (*String == Character)
			return (PCHAR)String;

	} while (*String++);

	return NULL;
}

PWCHAR StringLocateCharW(_Inout_ PWCHAR String, _In_ INT Character)
{
	do
	{
		if (*String == Character)
			return (PWCHAR)String;

	} while (*String++);

	return NULL;
}

