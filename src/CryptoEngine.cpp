#include <exception>
#include <iostream>
#include <cstring>
#include <new>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include "../include/CryptoEngine.hpp"
#include "../include/utils.hpp"

crypto::CryptoEngine::CryptoEngine()
{
    m_reverseMap.resize(8);
    m_directMap.resize(8);
    // RULE 1
    m_reverseMap[0]['A'] = 0b00;
    m_reverseMap[0]['C'] = 0b01;
    m_reverseMap[0]['G'] = 0b10;
    m_reverseMap[0]['T'] = 0b11;

    m_directMap[0][0b00] = 'A';
    m_directMap[0][0b01] = 'C';
    m_directMap[0][0b10] = 'G';
    m_directMap[0][0b11] = 'T';

    // RULE 2
    m_reverseMap[1]['A'] = 0b00;
    m_reverseMap[1]['G'] = 0b01;
    m_reverseMap[1]['C'] = 0b10;
    m_reverseMap[1]['T'] = 0b11;

    m_directMap[1][0b00] = 'A';
    m_directMap[1][0b01] = 'G';
    m_directMap[1][0b10] = 'C';
    m_directMap[1][0b11] = 'T';

    // RULE 3

    m_reverseMap[2]['C'] = 0b00;
    m_reverseMap[2]['A'] = 0b01;
    m_reverseMap[2]['T'] = 0b10;
    m_reverseMap[2]['G'] = 0b11;

    m_directMap[2][0b00] = 'C';
    m_directMap[2][0b01] = 'A';
    m_directMap[2][0b10] = 'T';
    m_directMap[2][0b11] = 'G';

    // RULE 4

    m_reverseMap[3]['G'] = 0b00;
    m_reverseMap[3]['A'] = 0b01;
    m_reverseMap[3]['T'] = 0b10;
    m_reverseMap[3]['C'] = 0b11;

    m_directMap[3][0b00] = 'G';
    m_directMap[3][0b01] = 'A';
    m_directMap[3][0b10] = 'T';
    m_directMap[3][0b11] = 'C';

    // RULE 5

    m_reverseMap[4]['C'] = 0b00;
    m_reverseMap[4]['T'] = 0b01;
    m_reverseMap[4]['A'] = 0b10;
    m_reverseMap[4]['G'] = 0b11;

    m_directMap[4][0b00] = 'C';
    m_directMap[4][0b01] = 'T';
    m_directMap[4][0b10] = 'A';
    m_directMap[4][0b11] = 'G';

    // RULE 6

    m_reverseMap[5]['G'] = 0b00;
    m_reverseMap[5]['T'] = 0b01;
    m_reverseMap[5]['A'] = 0b10;
    m_reverseMap[5]['C'] = 0b11;

    m_directMap[5][0b00] = 'G';
    m_directMap[5][0b01] = 'T';
    m_directMap[5][0b10] = 'A';
    m_directMap[5][0b11] = 'C';

    // RULE 7

    m_reverseMap[6]['T'] = 0b00;
    m_reverseMap[6]['C'] = 0b01;
    m_reverseMap[6]['G'] = 0b10;
    m_reverseMap[6]['A'] = 0b11;

    m_directMap[6][0b00] = 'T';
    m_directMap[6][0b01] = 'C';
    m_directMap[6][0b10] = 'G';
    m_directMap[6][0b11] = 'A';

    // RULE 8

    m_reverseMap[7]['T'] = 0b00;
    m_reverseMap[7]['G'] = 0b01;
    m_reverseMap[7]['C'] = 0b10;
    m_reverseMap[7]['A'] = 0b11;

    m_directMap[7][0b00] = 'T';
    m_directMap[7][0b01] = 'G';
    m_directMap[7][0b10] = 'C';
    m_directMap[7][0b11] = 'A';
    
}

int crypto::CryptoEngine::encryptData(std::vector<unsigned char> &plaintext, const std::string &password, CipherBundle &cryptoInfo)
{
    std::vector<unsigned char> key;
    std::vector<unsigned char> aes_key;
    std::vector<unsigned char> dynamic_key;

    _generateSalt(cryptoInfo.salt, _SALT_LENGTH);

    _generateKey(password, key, _KEY_LENGTH, cryptoInfo.salt);

    _generateIV(cryptoInfo.iv, _IV_LENGTH);
    
    aes_key.assign(key.begin(), key.begin() + 16);

    _performEncryptionAES(plaintext, cryptoInfo.iv, aes_key, cryptoInfo.ciphertext);
    aes_key.clear();

    std::vector<unsigned char> encodedData;

    dynamic_key.assign(key.begin() + 16, key.end());

    _encodeData(cryptoInfo.ciphertext, encodedData, dynamic_key, cryptoInfo.iv);
    key.clear();

    cryptoInfo.ciphertext.clear();
    cryptoInfo.ciphertext = encodedData;

    return STATUS_SUCCESS;
}

int crypto::CryptoEngine::decryptData(std::vector<unsigned char> &plaintext, const std::string &password, CipherBundle &cryptoInfo)
{
    std::vector<unsigned char> key;
    std::vector<unsigned char> aes_key;
    std::vector<unsigned char> dynamic_key;
    _generateKey(password, key, _KEY_LENGTH, cryptoInfo.salt);

    
    dynamic_key.assign(key.begin() + 16, key.end());
    std::vector<unsigned char> decodedData;
    _decodeData(cryptoInfo.ciphertext, decodedData, dynamic_key,cryptoInfo.iv);
    dynamic_key.clear();

    aes_key.assign(key.begin(), key.begin() + 16);
    _performDecryptionAES(decodedData, cryptoInfo.iv, aes_key, plaintext);
    aes_key.clear();
    key.clear();

    return STATUS_SUCCESS;
}
int crypto::CryptoEngine::_generateKey(const std::string &password, std::vector<unsigned char> &key, int key_len, const std::vector<unsigned char> &salt)
{ 
    key.resize(key_len);

    if (STATUS_SUCCESS != PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(), salt.data(), _SALT_LENGTH, _PBKDF2_ITER, key_len, key.data()))
        throw std::runtime_error("Failed to generate key!");

    return STATUS_SUCCESS;
}

int crypto::CryptoEngine::_getRandomScheme(int *current_values, unsigned char *buffer)
{
    current_values[0] = ( ( buffer[0] & 0x07 ) | ( buffer[0] | 0x08) ) & 0x07;
    current_values[1] = ( ( ( buffer[0] & 0x70 ) | ( buffer[0] | 0x80) ) >> 4 ) & 0x07;
    current_values[2] = ( ( buffer[1] & 0x07 ) | ( buffer[1] | 0x08) ) & 0x07;
    current_values[3] = ( ( ( buffer[1] & 0x70 ) | ( buffer[1] | 0x80) ) >> 4 ) & 0x07;

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

int crypto::CryptoEngine::_generateAES_DPRB(std::vector<unsigned char> &random_buffer, std::vector<unsigned char> &key, int output_len)
{
    std::vector<unsigned char> zeros_input(output_len, 0);
    std::vector<unsigned char> iv_input(_IV_LENGTH, 0);
    _performEncryptionAES(zeros_input, iv_input, key, random_buffer);   

    return STATUS_SUCCESS;
}

unsigned char crypto::CryptoEngine::_mapValue(unsigned char two_bit_value, int scheme_choice)
{
    return m_directMap[scheme_choice].find(two_bit_value)->second;
}

unsigned char crypto::CryptoEngine::_reverseMapValue(unsigned char nucleotide, int scheme_choice)
{
    return m_reverseMap[scheme_choice].find(nucleotide)->second;
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

int crypto::CryptoEngine::_encodeData(const std::vector<unsigned char> &data, std::vector<unsigned char> &encodedData, std::vector<unsigned char>& dynamicKey, std::vector<unsigned char>& iv)
{
    int status = STATUS_SUCCESS;
    encodedData.resize(data.size() * 4 + 1);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    status = EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, dynamicKey.data(), iv.data());
    if (status != STATUS_SUCCESS)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Couldn't init the PRBG stream!");   
    }

    int current_values[4] = {0, 0, 0, 0};
    std::vector<unsigned char> random_buffer;
    random_buffer.resize(AES_BLOCK_SIZE);
    std::vector<unsigned char> zero_data(AES_BLOCK_SIZE, 0);
    unsigned char slice_random_buffer[2];
    int out_len = 0;

    int keyposition = 0;
    for(size_t i = 0,  j = 0; i < data.size(); i++, j += 4)
    {        
        if (keyposition == 16)
        {
            status = EVP_EncryptUpdate(ctx, random_buffer.data(), &out_len, zero_data.data(), AES_BLOCK_SIZE);
            if (status != STATUS_SUCCESS)
            {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Internal PRBG error!");
            }
            keyposition = 0;
        }
        memcpy(slice_random_buffer, random_buffer.data() + keyposition, 2);
        keyposition += 2;
        _getRandomScheme(current_values, slice_random_buffer);
        encodedData[j]      = _mapValue((data[i] & 0xC0) >> 6, current_values[0]);
        encodedData[j + 1]  = _mapValue((data[i] & 0x30) >> 4, current_values[1]);
        encodedData[j + 2]  = _mapValue((data[i] & 0x0C) >> 2, current_values[2]);
        encodedData[j + 3]  = _mapValue((data[i] & 0x03) >> 0, current_values[3]);
    }

    EVP_CIPHER_CTX_free(ctx);

    return STATUS_SUCCESS;
}

int crypto::CryptoEngine::_decodeData(const std::vector<unsigned char> &data, std::vector<unsigned char> &decodedData, std::vector<unsigned char>& dynamicKey, std::vector<unsigned char>& iv)
{
    int status = STATUS_SUCCESS;
    decodedData.resize(data.size() / 4);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    status = EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, dynamicKey.data(), iv.data());
    if (status != STATUS_SUCCESS)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Couldn't init the PRBG stream!");   
    }

    int current_values[4] = {0, 0, 0, 0};
    std::vector<unsigned char> random_buffer;
    random_buffer.resize(AES_BLOCK_SIZE);
    std::vector<unsigned char> zero_data(AES_BLOCK_SIZE, 0);
    unsigned char slice_random_buffer[2];
    int out_len = 0;

    int keyposition = 0;

    for(size_t i = 0, j = 0; i < data.size() - 1; i += 4, j++)
    {
        if (keyposition == 16)
        {
            status = EVP_EncryptUpdate(ctx, random_buffer.data(), &out_len, zero_data.data(), AES_BLOCK_SIZE);
            if (status != STATUS_SUCCESS)
            {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Internal PRBG error!");
            }
            keyposition = 0;
        }

        memcpy(slice_random_buffer, random_buffer.data() + keyposition, 2);
        keyposition += 2;
        _getRandomScheme(current_values, slice_random_buffer);

        decodedData[j] = (_reverseMapValue(data[i], current_values[0]) << 6) | 
            (_reverseMapValue(data[i + 1], current_values[1]) << 4) | 
            (_reverseMapValue(data[i + 2], current_values[2]) << 2) | 
            (_reverseMapValue(data[i + 3], current_values[3]) << 0);
    }

    EVP_CIPHER_CTX_free(ctx);

    return STATUS_SUCCESS;
}