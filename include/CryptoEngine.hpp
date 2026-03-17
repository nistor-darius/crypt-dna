#pragma once
#include <cstdlib>
#include <cstddef>

namespace crypto {
    class CryptoEngine
    {
    public:
        int encryptData(unsigned char** plaintext, size_t& data_len, unsigned char* iv, unsigned char** key, unsigned char** ciphertext);
        
        int encodeData(unsigned char* data, size_t& data_len ,unsigned char** encodedData);

    private:
        int addPadding(unsigned char** data, size_t& data_len, size_t block_size);
        unsigned char mapValue(unsigned char two_bit_value, int scheme_choice);
    };
}