#pragma once
#include "common.h"

struct DATA {

    LPVOID data;
    size_t len;

};

DATA getFilelessData(char* host, char* port, char* resource, HMODULE hModule, LoadLibraryA_t pLoadLibraryA);

typedef struct addrinfo
{
    int                 ai_flags;       // AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST
    int                 ai_family;      // PF_xxx
    int                 ai_socktype;    // SOCK_xxx
    int                 ai_protocol;    // 0 or IPPROTO_xxx for IPv4 and IPv6
    size_t              ai_addrlen;     // Length of ai_addr
    char* ai_canonname;   // Canonical name for nodename
    _Field_size_bytes_(ai_addrlen) struct sockaddr* ai_addr;        // Binary address
    struct addrinfo* ai_next;        // Next structure in linked list
}
ADDRINFOA, * PADDRINFOA;

#define SD_SEND         0x01

