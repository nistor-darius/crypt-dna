#include <exception>
#include <iostream>
#include <cstring>
#include <new>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "../include/CryptoEngine.hpp"
#include "../include/utils.hpp"

crypto::CryptoEngine::CryptoEngine()
{
    m_reverseMap['A'] = 0b00;
    m_reverseMap['T'] = 0b11;
    m_reverseMap['C'] = 0b01;
    m_reverseMap['G'] = 0b10;

    m_directMap[0b00] = 'A';
    m_directMap[0b11] = 'T';
    m_directMap[0b01] = 'C';
    m_directMap[0b10] = 'G';
}

int crypto::CryptoEngine::encryptData(std::vector<unsigned char> &plaintext, const std::string &password, CipherBundle &cryptoInfo)
{
    std::vector<unsigned char> key;

    _generateSalt(cryptoInfo.salt, _SALT_LENGTH);

    _generateKey(password, key, _KEY_LENGTH, cryptoInfo.salt);

    _generateIV(cryptoInfo.iv, _IV_LENGTH);
    
    _performEncryptionAES(plaintext, cryptoInfo.iv, key, cryptoInfo.ciphertext);
    key.clear();

    std::vector<unsigned char> encodedData;

    _encodeData(cryptoInfo.ciphertext, encodedData);

    cryptoInfo.ciphertext.clear();
    cryptoInfo.ciphertext = encodedData;

    return STATUS_SUCCESS;
}

int crypto::CryptoEngine::decryptData(std::vector<unsigned char> &plaintext, const std::string &password, CipherBundle &cryptoInfo)
{
    std::vector<unsigned char> key;
    _generateKey(password, key, _KEY_LENGTH, cryptoInfo.salt);

    std::vector<unsigned char> decodedData;
    _decodeData(cryptoInfo.ciphertext, decodedData);

    _performDecryptionAES(decodedData, cryptoInfo.iv, key, plaintext);

    return STATUS_SUCCESS;
}
int crypto::CryptoEngine::_generateKey(const std::string &password, std::vector<unsigned char> &key, int key_len, const std::vector<unsigned char> &salt)
{ 
    key.resize(key_len);

    if (STATUS_SUCCESS != PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(), salt.data(), _SALT_LENGTH, _PBKDF2_ITER, key_len, key.data()))
        throw std::runtime_error("Failed to generate key!");

    return STATUS_SUCCESS;
}

int crypto::CryptoEngine::_generateSalt(std::vector<unsigned char> &salt, int salt_len)
{
    salt.resize(salt_len);

    if (STATUS_SUCCESS != RAND_bytes(salt.data(), salt_len))
        throw std::runtime_error("Unable to generate random salt.");
    
    return STATUS_SUCCESS;
}

int crypto::CryptoEngine::_generateIV(std::vector<unsigned char> &iv, int iv_len)
{
    iv.resize(iv_len);

    if (STATUS_SUCCESS != RAND_bytes(iv.data(), iv_len))
        throw std::runtime_error("Unable to generate random iv.");

    return STATUS_SUCCESS;
}

int crypto::CryptoEngine::_decodeData(const std::vector<unsigned char> &data, std::vector<unsigned char> &decodedData)
{
    decodedData.resize(data.size() / 4);

    std::cout << "Initial data: " << data.size() << "\nDecoded data size: " << decodedData.size() << std::endl;

    for(size_t i = 0, j = 0; i < data.size() - 1; i += 4, j++)
    {
        decodedData[j] = (_reverseMapValue(data[i], 1) << 6) | 
        (_reverseMapValue(data[i + 1], 1) << 4) | 
        (_reverseMapValue(data[i + 2], 1) << 2) | 
        (_reverseMapValue(data[i + 3], 1) << 0);
    }

    return STATUS_SUCCESS;
}

unsigned char crypto::CryptoEngine::_mapValue(unsigned char two_bit_value, int scheme_choice)
{
    return m_directMap[two_bit_value];
}

unsigned char crypto::CryptoEngine::_reverseMapValue(unsigned char nucleotide, int scheme_choice)
{
    return m_reverseMap[nucleotide];
}

int crypto::CryptoEngine::_performEncryptionAES(const std::vector<unsigned char> &plaintext, std::vector<unsigned char> &iv, const std::vector<unsigned char> &key, std::vector<unsigned char> &ciphertext)
{
    int status = STATUS_SUCCESS;
    int ciphertext_len_update;
    int ciphertext_len = plaintext.size();
    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    status = EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key.data(), iv.data());
    if(status != STATUS_SUCCESS)
        throw std::runtime_error("Encryption error.");

    status = EVP_EncryptUpdate(ctx, ciphertext.data(), &ciphertext_len, plaintext.data(), plaintext.size());
    if(status != STATUS_SUCCESS)
        throw std::runtime_error("Encryption error.");

    status = EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &ciphertext_len_update);
    if(status != STATUS_SUCCESS)
        throw std::runtime_error("Encryption error.");

    ciphertext_len += ciphertext_len_update; // sanity check, for CTR mode padding is not needed
    ciphertext.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);

    return STATUS_SUCCESS;
}

int crypto::CryptoEngine::_performDecryptionAES(const std::vector<unsigned char> &ciphertex, const std::vector<unsigned char> &iv, const std::vector<unsigned char> &key, std::vector<unsigned char> &plaintext)
{
    int status = STATUS_SUCCESS;
    int plaintext_len_update;
    int plaintext_len = ciphertex.size();
    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    status = EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key.data(), iv.data());
    if(status != STATUS_SUCCESS)
        throw std::runtime_error("Decryption error.");

    status = EVP_DecryptUpdate(ctx, plaintext.data(), &plaintext_len, ciphertex.data(), ciphertex.size());
    if(status != STATUS_SUCCESS)
        throw std::runtime_error("Decryption error.");

    status = EVP_DecryptFinal(ctx, plaintext.data() + plaintext_len, &plaintext_len_update);
    if(status != STATUS_SUCCESS)
        throw std::runtime_error("Decryption error.");

    plaintext_len += plaintext_len_update; // sanity check, for CTR mode padding is not needed
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);

    return STATUS_SUCCESS;
}

int crypto::CryptoEngine::_encodeData(const std::vector<unsigned char> &data, std::vector<unsigned char> &encodedData)
{
    encodedData.resize(data.size() * 4 + 1);
    for(size_t i = 0,  j = 0; i < data.size(); i++, j += 4)
    {
        encodedData[j] = _mapValue((data[i] & 0xC0) >> 6, 1);
        encodedData[j + 1] = _mapValue((data[i] & 0x30) >> 4, 1);
        encodedData[j + 2] = _mapValue((data[i] & 0x0C) >> 2, 1);
        encodedData[j + 3] = _mapValue((data[i] & 0x03) >> 0, 1);
    }
    return STATUS_SUCCESS;
}