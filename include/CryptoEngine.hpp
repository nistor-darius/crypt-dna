#pragma once
#include <cstdlib>
#include <cstddef>
#include <vector>
#include <string>

namespace crypto {
    /*
    Main encryption engine
    */
    class CryptoEngine
    {
    public:
        int encryptData(std::vector<unsigned char>& plaintext, const std::string& password, std::vector<unsigned char>& ciphertext);
        
        int generateKey(const std::string& password, std::vector<unsigned char>& key, int key_len, std::vector<unsigned char>& salt);
    private:
        unsigned char _mapValue(unsigned char two_bit_value, int scheme_choice);

        int _performEncryptionAES(const std::vector<unsigned char>& plaintext, std::vector<unsigned char>& iv, const std::vector<unsigned char>&  key, std::vector<unsigned char>& ciphertext);

        int _encodeData(const std::vector<unsigned char>& data, std::vector<unsigned char>& encodedData);
    };
}