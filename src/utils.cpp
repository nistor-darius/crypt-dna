#include "../include/utils.hpp"
#include <iostream>

void printHex(unsigned char *data, size_t data_len)
{
    for(size_t i = 0; i < data_len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}
