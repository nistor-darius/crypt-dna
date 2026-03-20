#include <iostream>
#include <exception>
#include <cstring>
#include <string>
#include <fstream>
#include "../include/App.hpp"
#include "../include/utils.hpp"
#include "../include/cxxopts.hpp"

void crypto::App::initialize(int argc, char **argv)
{
    cxxopts::Options options("crypt-dna", 
        "crypt-dna\tLightweight pseudo-DNA encryption utilitary");

    options.add_options()
        ("d,decrypt", "Decrypt data")
        ("in,infile", "File to perform operation", cxxopts::value<std::string>())
        ("out,outfile", "Output file", cxxopts::value<std::string>()->default_value("stdout"))
        ("h,help", "Print this help page", cxxopts::value<bool>()->default_value("false"))
        ("p,password", "Specified the password used for encryption/decryption", cxxopts::value<std::string>())
        ; 
    auto result = options.parse(argc, argv);

    if(result.count("help"))
    {
        std::cout << options.help() << std::endl;
        throw new cxxopts::exceptions::exception("Invalid usage");
    }

    m_inputFile = result["infile"].as<std::string>();
    m_encyption = result["decrypt"].as<bool>();
    m_outputFile = result["outfile"].as<std::string>();
    m_password = result["password"].as<std::string>();
}

crypto::App &crypto::App::getInstance()
{
    static App instance;
    return instance;
}

void crypto::App::run()
{
    std::vector<unsigned char> read_buffer;
    readData(read_buffer);

    std::cout.write(reinterpret_cast<char*>(read_buffer.data()), read_buffer.size());

    std::cout << std::endl;
    std::vector<unsigned char> ciphertext;

    m_cryptEngine->encryptData(read_buffer, m_password, ciphertext);

    printHex(ciphertext.data(), ciphertext.size());
}

void crypto::App::readData(std::vector<unsigned char> &buffer)
{
    buffer.clear();
    std::ifstream file(m_inputFile, std::ios::binary | std::ios::ate);
    if(!file.is_open())
        throw new std::runtime_error("Unable to open the file for reading.");

    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);

    buffer.resize(size);

    if(!file.read(reinterpret_cast<char*>(buffer.data()), size)) 
    {
        throw new std::runtime_error("Couldn't read from the specified file.");
    }
}