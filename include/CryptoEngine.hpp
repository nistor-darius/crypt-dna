#pragma once
#include <cstdlib>
#include <cstddef>

namespace crypto {
    class CryptoEngine
    {
    public:
        int encryptData(unsigned char** plaintext, int& data_len, unsigned char* iv, unsigned char** key, unsigned char** ciphertext, int& ciphertext_len);
        
        int encodeData(unsigned char* data, int& data_len ,unsigned char** encodedData);

        int generateKey(unsigned char* passphrase, int passphrase_len, unsigned char** key, int key_len);
    private:
        unsigned char mapValue(unsigned char two_bit_value, int scheme_choice);
    };
}