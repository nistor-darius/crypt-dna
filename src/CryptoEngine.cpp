#include "../include/CryptoEngine.hpp"
#include "../include/utils.hpp"
#include <exception>
#include <iostream>
#include <cstring>
#include <new>
#include <openssl/evp.h>
#include <openssl/aes.h>

int crypto::CryptoEngine::encryptData(unsigned char **plaintext, int &plaintext_len, unsigned char *iv, unsigned char **key, unsigned char **ciphertext, int& ciphertext_len)
{
    int status = STATUS_SUCCESS;
    int ciphertext_len_update;
    ciphertext_len = plaintext_len + AES_BLOCK_SIZE;
    *ciphertext = new unsigned char[ciphertext_len];
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    status = EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, *key, iv);
    if(status != STATUS_SUCCESS)
        return ERR_CRYPT;

    status = EVP_EncryptUpdate(ctx, *ciphertext, &ciphertext_len, *plaintext, plaintext_len);
    if(status != STATUS_SUCCESS)
        return ERR_CRYPT;

    status = EVP_EncryptFinal_ex(ctx, *ciphertext + ciphertext_len, &ciphertext_len_update);
    if(status != STATUS_SUCCESS)
        return ERR_CRYPT;

    ciphertext_len += ciphertext_len_update;

    EVP_CIPHER_CTX_free(ctx);

    unsigned char* encodedData = new unsigned char[ciphertext_len];
    encodeData(*ciphertext, ciphertext_len, &encodedData);

    printf("%s", encodedData);

    return STATUS_SUCCESS;
}

int crypto::CryptoEngine::encodeData(unsigned char *data, int& data_len, unsigned char **encodedData)
{
    *encodedData = new unsigned char[data_len * 4 + 1];
    for(size_t i = 0,  j = 0; i < data_len; i++, j += 4)
    {
        (*encodedData)[j] = mapValue((data[i] & 0xC0) >> 6, 1);
        (*encodedData)[j + 1] = mapValue((data[i] & 0x30) >> 4, 1);
        (*encodedData)[j + 2] = mapValue((data[i] & 0x0C) >> 2, 1);
        (*encodedData)[j + 3] = mapValue((data[i] & 0x03) >> 0, 1);
    }
    data_len *= 4;
    (*encodedData)[data_len] = '\0';
    return STATUS_SUCCESS;
}

int crypto::CryptoEngine::generateKey(unsigned char *passphrase, int passphrase_len, unsigned char **key, int key_len)
{
    return 0;
}
unsigned char crypto::CryptoEngine::mapValue(unsigned char two_bit_value, int scheme_choice)
{
    if(two_bit_value == 0x00)
        return 'A';
    else if (two_bit_value == 0x01)
        return 'C';
    else if (two_bit_value == 0x02)
        return 'T';
    return 'G';
}