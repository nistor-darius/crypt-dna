#include "../include/App.hpp"
#include <iostream>
#include <exception>

void crypto::App::initialize(int argc, char **argv)
{
    if (argc < 6)
    {
        printUsage();
        throw new std::invalid_argument("Invalid usage!\n");
    }
}

void crypto::App::printUsage()
{
    std::cout << "USAGE:\n";
    std::cout << "crypt-dna enc -in [INPUT_FILE] -out [OUTPUT_FILE]\n";
    std::cout << "crypt-dna dec -in [ENCRYPTED_FILE] -out [DECRYPTED_FILE]\n";  
}
