#pragma once
#include <vector>

namespace crypto
{
    /*
    *   Structure that holds the encryption data
    */
    struct CipherBundle
    {
        std::vector<unsigned char> iv;
        std::vector<unsigned char> salt;
        std::vector<unsigned char> ciphertext;
    };
}