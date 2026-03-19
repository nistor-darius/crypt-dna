#include "../include/App.hpp"
#include "../include/utils.hpp"
#include <iostream>
#include <exception>
#include <cstring>

void crypto::App::initialize(int argc, char **argv)
{
    if (argc < 6)
    {
        printUsage(argv[0]);
        throw new std::invalid_argument("Invalid usage!\n");
    }

    
}

void crypto::App::run()
{
    unsigned char* data = new unsigned char[101];
    scanf("%s", data);
    int data_len = strlen((const char*)data);

    unsigned char* key = new unsigned char[_KEY_LENGTH];
    if(key == NULL)
        throw std::bad_alloc();
    memset(key, 0x20, _KEY_LENGTH);

    unsigned char* iv = new unsigned char[_KEY_LENGTH];
    if(iv == NULL)
        throw std::bad_alloc();
    memset(iv, 0x88, _KEY_LENGTH);
    unsigned char* ciphertext = NULL;
    int ciphertext_len;

    m_cryptEngine->encryptData(&data, data_len, iv, &key, &ciphertext, ciphertext_len);
}


void crypto::App::printUsage(char* name)
{
    std::cout << "USAGE:\n"
        << name <<"  enc -in <INPUT_FILE> -out <OUTPUT_FILE>\n"
        << name <<"  dec -in <ENCRYPTED_FILE> -out <DECRYPTED_FILE>\n";  
}
