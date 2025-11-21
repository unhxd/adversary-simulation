#include "common.h"

DWORD CalculateHash(char* inputData) {
    DWORD hashValue = 0x99;

    for (int index = 0; index < strlen(inputData); index++) {
        hashValue += inputData[index] + (hashValue << 1);
    }

    return hashValue;
}

DWORD CalculateModuleHash(LDR_MODULE* moduleLinkList) {
    char moduleName[64];
    size_t index = 0;

    while (moduleLinkList->BaseDllName.Buffer[index] && index < sizeof(moduleName) - 1) {
        moduleName[index] = (char)moduleLinkList->BaseDllName.Buffer[index];
        index++;
    }
    moduleName[index] = 0;
    return CalculateHash((char*)CharLowerA(moduleName));
}

HMODULE GetModuleHandleImpl(DWORD hashInput) {
    HMODULE ModuleBaseAddr;
    INT_PTR PEB = __readgsqword(0x60);
    INT_PTR Ldr = 0x18;
    INT_PTR FlinkOffset = 0x10;

    INT_PTR PEB_LDR_DATA = *(INT_PTR*)(PEB + Ldr);
    INT_PTR FistFlink = *(INT_PTR*)(PEB_LDR_DATA + FlinkOffset); // InLoadOrderModuleList
    LDR_MODULE* LDR_DATA_TABLE_ENTRY = (LDR_MODULE*)FistFlink;
    do {
        LDR_DATA_TABLE_ENTRY = (LDR_MODULE*)LDR_DATA_TABLE_ENTRY->InLoadOrderModuleList.Flink;
        if (LDR_DATA_TABLE_ENTRY->BaseAddress != NULL) {

            if (CalculateModuleHash(LDR_DATA_TABLE_ENTRY) == hashInput) {
                break;
            }
        }
    } while (FistFlink != (INT_PTR)LDR_DATA_TABLE_ENTRY);

    ModuleBaseAddr = (HMODULE)LDR_DATA_TABLE_ENTRY->BaseAddress;
    return ModuleBaseAddr;
}

LPVOID getAPIAddr(HMODULE module, DWORD myHash) {

    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((LPBYTE)module + DOSheader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY EXdir = (PIMAGE_EXPORT_DIRECTORY)(
        (LPBYTE)module + NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD fAddr = (PDWORD)((LPBYTE)module + EXdir->AddressOfFunctions);
    PDWORD fNames = (PDWORD)((LPBYTE)module + EXdir->AddressOfNames);
    PWORD  fOrdinals = (PWORD)((LPBYTE)module + EXdir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < EXdir->AddressOfFunctions; i++) {
        LPSTR pFuncName = (LPSTR)((LPBYTE)module + fNames[i]);
        DWORD hash = CalculateHash(pFuncName);
        if (hash == myHash) {
            //printf("functionName : %s\n", pFuncName);
            return (LPVOID)((LPBYTE)module + fAddr[fOrdinals[i]]);
        }
    }
    return NULL;
}

LPVOID getAPIAddrWoH(HMODULE module, char* sProcName) {

    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((LPBYTE)module + DOSheader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY EXdir = (PIMAGE_EXPORT_DIRECTORY)(
        (LPBYTE)module + NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD fAddr = (PDWORD)((LPBYTE)module + EXdir->AddressOfFunctions);
    PDWORD fNames = (PDWORD)((LPBYTE)module + EXdir->AddressOfNames);
    PWORD  fOrdinals = (PWORD)((LPBYTE)module + EXdir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < EXdir->AddressOfFunctions; i++) {
        LPSTR pFuncName = (LPSTR)((LPBYTE)module + fNames[i]);
        //DWORD hash = CalculateHash(pFuncName);
        int result = StringCompareA(sProcName, pFuncName);
        if (result == 0) {
            //printf("functionName : %s\n", pFuncName);
            return (LPVOID)((LPBYTE)module + fAddr[fOrdinals[i]]);
        }
    }
    return NULL;
}

FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char* sProcName, LoadLibraryA_t pLoadLibraryA) {

    char* pBaseAddr = (char*)hMod;

    // get pointers to main headers/structures
    IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
    IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY* pExportDataDir = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pExportDataDir->VirtualAddress);

    // resolve addresses to Export Address Table, table of function names and "table of ordinals"
    DWORD* pEAT = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);
    DWORD* pFuncNameTbl = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfNames);
    WORD* pHintsTbl = (WORD*)(pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

    // function address we're looking for
    void* pProcAddr = NULL;

    // resolve function by ordinal
    if (((DWORD_PTR)sProcName >> 16) == 0) {
        WORD ordinal = (WORD)sProcName & 0xFFFF;  // convert to WORD
        DWORD Base = pExportDirAddr->Base;         // first ordinal number

        // check if ordinal is not out of scope
        if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
            return NULL;

        // get the function virtual address = RVA + BaseAddr
        pProcAddr = (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[ordinal - Base]);
    }
    // resolve function by name
    else {
        // parse through table of function names
        for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
            char* sTmpFuncName = (char*)pBaseAddr + (DWORD_PTR)pFuncNameTbl[i];

            if (StringCompareA(sProcName, sTmpFuncName) == 0) {
                // Check if it's a forwarder
                DWORD forwarderRVA = pEAT[pHintsTbl[i]];
                if (forwarderRVA >= pExportDataDir->VirtualAddress &&
                    forwarderRVA < pExportDataDir->VirtualAddress + pExportDataDir->Size) {
                    // It's a forwarder, resolve it
                    char* forwarder = (char*)(pBaseAddr + forwarderRVA);
                    char* dot = StringLocateCharA(forwarder, '.');
                    if (dot != NULL) {
                        // Extract the substring before the dot
                        size_t length = dot - forwarder;
                        char dllName[256];  // Adjust the size as needed
                        StringCopyA(dllName, forwarder); //length
                        dllName[length] = '\0';  // Null-terminate the DLL name
                        // Concatenate ".dll" to the extracted substring
                        StringConcatA(dllName, ".dll"); // sizeof(dllName) - length - 1

                        HMODULE hForwardedModule = pLoadLibraryA(dllName);
                        if (hForwardedModule != NULL) {
                            // Resolve the function from the forwarded DLL
                            pProcAddr = getAPIAddrWoH(hForwardedModule, dot + 1);

                        }
                    }
                }
                else {
                    // Not a forwarder, get the function virtual address = RVA + BaseAddr
                    pProcAddr = (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[pHintsTbl[i]]);
                }
                break;
            }
        }
    }

    return (FARPROC)pProcAddr;
}