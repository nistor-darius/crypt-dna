#pragma once
#include <cstdlib>
#include <cstddef>

// cryptographic sizes in bytes
#define _KEY_LENGTH         16
#define _SALT_LENGTH        16
#define _IV_LENGTH          16
#define _PBKDF2_ITER        100000

// success code
#define STATUS_SUCCESS      1

// print data in hexadecimal
void printHex(unsigned char* data, size_t data_len);