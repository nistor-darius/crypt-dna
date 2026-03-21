#pragma once
#include <cstdlib>
#include <cstddef>
#include <vector>
#include <string>
#include <unordered_map>
#include "../include/CipherBundle.hpp"

namespace crypto {
    /*
    Main encryption engine
    */
    class CryptoEngine
    {
    public:
        CryptoEngine();
        int encryptData(std::vector<unsigned char>& plaintext, const std::string& password, CipherBundle &cryptoInfo);
        int decryptData(std::vector<unsigned char>& plaintext, const std::string& password, CipherBundle &cryptoInfo);
    private:
        unsigned char _mapValue(unsigned char two_bit_value, int scheme_choice);

        unsigned char _reverseMapValue(unsigned char nucleotide, int scheme_choice);

        int _performEncryptionAES(const std::vector<unsigned char>& plaintext, std::vector<unsigned char>& iv, const std::vector<unsigned char>&  key, std::vector<unsigned char>& ciphertext);

        int _performDecryptionAES(const std::vector<unsigned char>& ciphertex, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& key, std::vector<unsigned char>& plaintext);

        int _encodeData(const std::vector<unsigned char>& data, std::vector<unsigned char>& encodedData);

        int _generateKey(const std::string& password, std::vector<unsigned char>& key, int key_len, const std::vector<unsigned char>& salt);

        int _generateSalt(std::vector<unsigned char>& salt, int salt_len);

        int _generateIV(std::vector<unsigned char>& iv, int iv_len);

        int _decodeData(const std::vector<unsigned char>& data, std::vector<unsigned char>& decodedData);

        std::unordered_map<unsigned char, unsigned char> m_reverseMap;
        std::unordered_map<unsigned char, unsigned char> m_directMap;
    };
}