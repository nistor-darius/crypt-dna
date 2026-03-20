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

int crypto::CryptoEngine::encryptData(unsigned char* plaintext, int &plaintext_len, const char* password, unsigned char **ciphertext, int& ciphertext_len)
{
    CipherBundle cryptoInfo;

    cryptoInfo.salt = new unsigned char[_SALT_LENGTH];
    if(cryptoInfo.salt == NULL)
        throw new std::bad_alloc();

    RAND_bytes(cryptoInfo.salt, _SALT_LENGTH);

    unsigned char* key = NULL;
    generateKey(password, strlen(password), &key, _KEY_LENGTH, &cryptoInfo.salt);

    cryptoInfo.iv = new unsigned char[_IV_LENGTH];
    if(cryptoInfo.iv == NULL)
        throw new std::bad_alloc();


    RAND_bytes(cryptoInfo.iv, _IV_LENGTH);
    
    _performEncryptionAES(&plaintext, plaintext_len, cryptoInfo.iv, &key, &cryptoInfo.ciphertext, cryptoInfo.ciphertext_len);

    unsigned char* encodedData = new unsigned char[ciphertext_len * 4 + 1];

    if(encodedData == NULL)
        throw new std::bad_alloc();

    _encodeData(cryptoInfo.ciphertext, cryptoInfo.ciphertext_len, &encodedData);
    
    ciphertext_len = _SALT_LENGTH + _IV_LENGTH + cryptoInfo.ciphertext_len;
    *ciphertext = new unsigned char[ciphertext_len];
    if(*ciphertext == NULL)
        throw new std::bad_alloc();

    memcpy(*ciphertext, cryptoInfo.salt, _SALT_LENGTH);
    memcpy((*ciphertext) + _SALT_LENGTH, cryptoInfo.iv, _IV_LENGTH);
    memcpy((*ciphertext) + _SALT_LENGTH + _IV_LENGTH, encodedData, cryptoInfo.ciphertext_len);

    printf("Intermediary encoded data: %s\n", encodedData);

    delete[] cryptoInfo.salt;
    delete[] cryptoInfo.iv;
    delete[] encodedData;
    delete[] cryptoInfo.ciphertext;

    return STATUS_SUCCESS;
}

int crypto::CryptoEngine::_encodeData(unsigned char *data, int& data_len, unsigned char **encodedData)
{
    *encodedData = new unsigned char[data_len * 4 + 1];
    for(int i = 0,  j = 0; i < data_len; i++, j += 4)
    {
        (*encodedData)[j] = _mapValue((data[i] & 0xC0) >> 6, 1);
        (*encodedData)[j + 1] = _mapValue((data[i] & 0x30) >> 4, 1);
        (*encodedData)[j + 2] = _mapValue((data[i] & 0x0C) >> 2, 1);
        (*encodedData)[j + 3] = _mapValue((data[i] & 0x03) >> 0, 1);
    }
    data_len *= 4;
    (*encodedData)[data_len] = '\0';
    return STATUS_SUCCESS;
}

int crypto::CryptoEngine::generateKey(const char *passphrase, int passphrase_len, unsigned char **key, int key_len, unsigned char** salt)
{
    *salt = new unsigned char[_SALT_LENGTH];
    if(*salt == NULL)
        throw new std::bad_alloc();

    if(RAND_bytes(*salt, sizeof(salt)) != STATUS_SUCCESS)
        throw new std::runtime_error("Couldn't generate random bytes.");

    *key = new unsigned char[_KEY_LENGTH];
    if(*key == NULL)
        throw new std::bad_alloc();

    if (PKCS5_PBKDF2_HMAC_SHA1(passphrase, passphrase_len, *salt, _SALT_LENGTH, _PBKDF2_ITER, key_len, *key) != STATUS_SUCCESS)
        throw new std::runtime_error("Failed to generate key!");

    return STATUS_SUCCESS;
}

int crypto::CryptoEngine::_performEncryptionAES(unsigned char **plaintext, int &data_len, unsigned char *iv, unsigned char **key, unsigned char **ciphertext, int &ciphertext_len)
{
    int status = STATUS_SUCCESS;
    int ciphertext_len_update;
    ciphertext_len = data_len + AES_BLOCK_SIZE;
    *ciphertext = new unsigned char[ciphertext_len];
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    status = EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, *key, iv);
    if(status != STATUS_SUCCESS)
        return ERR_CRYPT;

    status = EVP_EncryptUpdate(ctx, *ciphertext, &ciphertext_len, *plaintext, data_len);
    if(status != STATUS_SUCCESS)
        return ERR_CRYPT;

    status = EVP_EncryptFinal_ex(ctx, *ciphertext + ciphertext_len, &ciphertext_len_update);
    if(status != STATUS_SUCCESS)
        return ERR_CRYPT;

    ciphertext_len += ciphertext_len_update;

    EVP_CIPHER_CTX_free(ctx);

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