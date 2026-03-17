#include "../include/App.hpp"
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
    size_t data_len = strlen((const char*)data);

    m_cryptEngine->encryptData(&data, data_len, NULL, NULL, NULL);
}


void crypto::App::printUsage(char* name)
{
    std::cout << "USAGE:\n"
        << name <<"  enc -in <INPUT_FILE> -out <OUTPUT_FILE>\n"
        << name <<"  dec -in <ENCRYPTED_FILE> -out <DECRYPTED_FILE>\n";  
}
