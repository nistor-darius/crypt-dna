#include <exception>
#include <iostream>
#include <cstring>
#include <new>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "../include/CryptoEngine.hpp"
#include "../include/utils.hpp"
#include "../include/CipherBundle.hpp"


int crypto::CryptoEngine::encryptData(std::vector<unsigned char> &plaintext, const std::string &password, std::vector<unsigned char> &ciphertext)
{
    CipherBundle cryptoInfo;

    std::vector<unsigned char> key;
    generateKey(password, key, _KEY_LENGTH, cryptoInfo.salt);

    cryptoInfo.iv.resize(_IV_LENGTH);

    RAND_bytes(cryptoInfo.iv.data(), _IV_LENGTH);
    
    _performEncryptionAES(plaintext, cryptoInfo.iv, key, cryptoInfo.ciphertext);
    key.clear();

    std::vector<unsigned char> encodedData;

    _encodeData(cryptoInfo.ciphertext, encodedData);

    printf("Intermediary encoded data: %s\n", encodedData.data());

    return STATUS_SUCCESS;
}

int crypto::CryptoEngine::generateKey(const std::string &password, std::vector<unsigned char> &key, int key_len, std::vector<unsigned char> &salt)
{
    salt.resize(_SALT_LENGTH);

    if(STATUS_SUCCESS != RAND_bytes(salt.data(), _SALT_LENGTH))
        throw new std::runtime_error("Couldn't generate random salt.");
    
    key.resize(key_len);

    if (STATUS_SUCCESS != PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(), salt.data(), _SALT_LENGTH, _PBKDF2_ITER, key_len, key.data()))
        throw new std::runtime_error("Failed to generate key!");

    return STATUS_SUCCESS;
}

unsigned char crypto::CryptoEngine::_mapValue(unsigned char two_bit_value, int scheme_choice)
{
    if(two_bit_value == 0x00)
        return 'A';
    else if (two_bit_value == 0x01)
        return 'C';
    else if (two_bit_value == 0x02)
        return 'T';
    return 'G';
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
        return ERR_CRYPT;

    status = EVP_EncryptUpdate(ctx, ciphertext.data(), &ciphertext_len, plaintext.data(), plaintext.size());
    if(status != STATUS_SUCCESS)
        return ERR_CRYPT;

    status = EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &ciphertext_len_update);
    if(status != STATUS_SUCCESS)
        return ERR_CRYPT;

    ciphertext_len += ciphertext_len_update;
    ciphertext.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);

    return STATUS_SUCCESS;
}

int crypto::CryptoEngine::_encodeData(const std::vector<unsigned char> &data, std::vector<unsigned char> &encodedData)
{
    encodedData.resize(data.size() * 4 + 1);
    for(int i = 0,  j = 0; i < data.size(); i++, j += 4)
    {
        encodedData[j] = _mapValue((data[i] & 0xC0) >> 6, 1);
        encodedData[j + 1] = _mapValue((data[i] & 0x30) >> 4, 1);
        encodedData[j + 2] = _mapValue((data[i] & 0x0C) >> 2, 1);
        encodedData[j + 3] = _mapValue((data[i] & 0x03) >> 0, 1);
    }
    encodedData[encodedData.size() - 1] = '\0';
    return STATUS_SUCCESS;
}
