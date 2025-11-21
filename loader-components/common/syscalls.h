#pragma once
#include <Windows.h>

WORD GetSSN(LPVOID addr);
INT_PTR GetsyscallInstr(LPVOID addr);

#define NtCurrentProcess()	   ((HANDLE)-1)

#define MOVE_MEMORY(Destination, Source, Length) do {     \
    char* dest = (char*)(Destination);                     \
    const char* src = (const char*)(Source);               \
    size_t len = (Length);                                 \
    for(size_t i = 0; i < len; i++) {                      \
        dest[i] = src[i];                                  \
    }                                                       \
} while (0)


#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

EXTERN_C VOID GetSyscall(WORD systemCall);
EXTERN_C VOID GetSyscallAddr(INT_PTR syscallAdr);


EXTERN_C NTSTATUS sysZwAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

EXTERN_C NTSTATUS sysNtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);

EXTERN_C NTSTATUS sysNtCreateThreadEx(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer
);

EXTERN_C NTSTATUS sysNtWaitForSingleObject(
    IN HANDLE         Handle,
    IN BOOLEAN        Alertable,
    IN PLARGE_INTEGER Timeout
);