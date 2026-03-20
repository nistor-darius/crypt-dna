#pragma once
#include <cstdlib>
#include <cstddef>

namespace crypto {
    class CryptoEngine
    {
    public:
        int encryptData(unsigned char* plaintext, int& data_len, const char* password, unsigned char** ciphertext, int& ciphertext_len);
        
        int generateKey(const char* passphrase, int passphrase_len, unsigned char** key, int key_len, unsigned char** salt);
    private:
        unsigned char _mapValue(unsigned char two_bit_value, int scheme_choice);

        int _performEncryptionAES(unsigned char** plaintext, int& data_len, unsigned char* iv, unsigned char** key, unsigned char** ciphertext, int& ciphertext_len);

        int _encodeData(unsigned char* data, int& data_len ,unsigned char** encodedData);
    };
}