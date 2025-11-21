#pragma once
#include "common.h"


typedef struct {
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} Crypt, * PCrypt;

typedef VOID(WINAPI* SystemFunction032_t)(PCrypt Img, PCrypt Key);


void xor_aa(BYTE* input, size_t length);
void xor_stack(void* stack_top, void* stack_base);
void XORNull(char* data, size_t data_len, char* key, size_t key_len);