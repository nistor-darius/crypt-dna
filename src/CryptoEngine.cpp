#include "../include/CryptoEngine.hpp"
#include "../include/utils.hpp"
#include <exception>
#include <iostream>
#include <cstring>
#include <new>

int crypto::CryptoEngine::encryptData(unsigned char **plaintext, size_t &data_len, unsigned char *iv, unsigned char **key, unsigned char **ciphertext)
{
    size_t offset = 0;
    printf("Data_len before padding: %d\n", data_len);
    addPadding(plaintext, data_len, DNA_BLOCK_SIZE);
    printf("Data_len after padding: %d\n", data_len);
    printHex(*plaintext, data_len);
    unsigned char* encodedData;
    encodeData(*plaintext, data_len, &encodedData);

    

    printf("%s\n", encodedData);
    delete[] encodedData;

    return 0;
}

int crypto::CryptoEngine::encodeData(unsigned char *data, size_t& data_len, unsigned char **encodedData)
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
    return 0;
}

int crypto::CryptoEngine::addPadding(unsigned char** data, size_t &data_len, size_t block_size)
{
    size_t pad_num = block_size - (data_len % block_size);

    if(pad_num == 0)
    {
        data_len += block_size;
        unsigned char* temp = new unsigned char[data_len];
        if(temp == nullptr)
            throw new std::bad_alloc();

        memcpy(temp, *data, data_len - block_size);

        delete[] *data;
        *data = temp;

        for(size_t i = 1 ; i < block_size; i++)
        {
            (*data)[data_len - i] = block_size;
        }
    }
    else 
    {
        data_len += pad_num;
        unsigned char* temp = new unsigned char[data_len];
        if(temp == nullptr)
            throw new std::bad_alloc();

        memcpy(temp, *data, data_len - pad_num);

        delete[] *data;
        *data = temp;

        for(size_t i = 1 ; i <= pad_num; i++)
        {
            (*data)[data_len - i] = pad_num;
        }
    }

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