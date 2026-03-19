#pragma once
#include <cstdlib>
#include <cstddef>

#define DNA_BLOCK_SIZE      16
#define _KEY_LENGTH         16
#define _SALT_LENGTH        16
#define _IV_LENGTH          16
#define _PBKDF2_ITER        100000

#define STATUS_SUCCESS      1
#define ERR_BASE            100
#define ERR_CRYPT           (ERR_BASE + 3)


void printHex(unsigned char* data, size_t data_len);