#include "common.h"

void xor_aa(BYTE* input, size_t length) {

    for (int i = 0; i < length; i++) {
        input[i] = input[i] ^ 0xaa;
    }

}

void xor_stack(void* stack_top, void* stack_base) {
    unsigned char* top = (unsigned char*)stack_top;
    unsigned char* base = (unsigned char*)stack_base;

    for (unsigned char* p = top; p < base; ++p) {
        *p ^= 0xAA;
    }
}

void XORNull(char* data, size_t data_len, char* key, size_t key_len)
{
    int j;
    j = 0;
    for (int i = 0; i < data_len; i++)
    {
        if (j == key_len - 1)
            j = 0;
        if (data[i] == 0x00) {
            data[i] = 0x00;
        }
        else
        {
            data[i] = data[i] ^ key[j];
        }
        j++;
    }

}