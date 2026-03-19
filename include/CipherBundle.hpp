#pragma once

namespace crypto
{
    struct CipherBundle
    {
        unsigned char* iv;
        unsigned char* salt;
        unsigned char* ciphertext;
        int ciphertext_len;
    };
}