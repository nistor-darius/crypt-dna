#include <iostream>
#include <exception>
#include <cstring>
#include "../include/App.hpp"
#include "../include/utils.hpp"

void crypto::App::initialize(int argc, char **argv)
{
    if (argc < 6)
    {
        printUsage(argv[0]);
        throw new std::invalid_argument("Invalid usage!\n");
    }

    
}

crypto::App &crypto::App::getInstance()
{
    static App instance;
    return instance;
}

void crypto::App::run()
{
    unsigned char* data = new unsigned char[101];
    scanf("%s", data);
    int data_len = strlen((const char*)data);

    const char* password = "cryptography";
    
    unsigned char* ciphertext = NULL;
    int ciphertext_len;

    m_cryptEngine->encryptData(data, data_len, password, &ciphertext, ciphertext_len);

    printHex(ciphertext, ciphertext_len);

}


void crypto::App::printUsage(char* name)
{
    std::cout << "USAGE:\n"
        << name <<"  enc -in <INPUT_FILE> -out <OUTPUT_FILE>\n"
        << name <<"  dec -in <ENCRYPTED_FILE> -out <DECRYPTED_FILE>\n";  
}
