#include <iostream>
#include <exception>
#include <cstring>
#include <string>
#include <fstream>
#include <algorithm>
#include "../include/App.hpp"
#include "../include/utils.hpp"
#include "../include/cxxopts.hpp"
#include "../include/CipherBundle.hpp"

void crypto::App::initialize(int argc, char **argv)
{
    cxxopts::Options options("crypt-dna", 
        "crypt-dna\tLightweight pseudo-DNA encryption utilitary");

    options.add_options()
        ("d,decrypt", "Decrypt data")
        ("i,infile", "File to perform operation", cxxopts::value<std::string>())
        ("o,outfile", "Output file", cxxopts::value<std::string>()->default_value("stdout"))
        ("h,help", "Print this help page", cxxopts::value<bool>()->default_value("false"))
        ("p,password", "Specifies the password used for encryption/decryption", cxxopts::value<std::string>())
        ("v,verbose", "Verbose, prints intermediary debug values")
        ;
    auto result = options.parse(argc, argv);

    if (argc < 2)
    {
        std::cout << options.help() << std::endl;
        exit(EXIT_SUCCESS);
    }

    if(result.count("help"))
    {
        std::cout << options.help() << std::endl;
        exit(EXIT_SUCCESS);
    }

    m_inputFile = result["infile"].as<std::string>();
    m_encyption = result["decrypt"].as<bool>();
    m_outputFile = result["outfile"].as<std::string>();
    m_password = result["password"].as<std::string>();
    m_verbose = result["verbose"].as<bool>();
}

crypto::App &crypto::App::getInstance()
{
    static App instance;
    return instance;
}

void crypto::App::run()
{
    std::vector<unsigned char> read_buffer;
    _readData(read_buffer);

    if(read_buffer.size() == 0)
        throw std::runtime_error("File size is 0.");

    if(m_encyption == false)
    {
        _handleEncryption(read_buffer);
    }
    else
    {
        _handleDecryption(read_buffer);
    }
}

void crypto::App::_readData(std::vector<unsigned char> &buffer)
{
    buffer.clear();
    std::ifstream file(m_inputFile, std::ios::binary | std::ios::ate);
    if(!file.is_open())
        throw std::runtime_error("Unable to open the file for reading.");

    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);

    buffer.resize(size);

    if(!file.read(reinterpret_cast<char*>(buffer.data()), size)) 
    {
        throw  std::runtime_error("Couldn't read from the specified file.");
    }
    file.close();
}

void crypto::App::_writeData(const CipherBundle &data)
{
    
    std::ofstream out(m_outputFile, std::ios::binary);

    if (!out)
        throw std::runtime_error("Couldn't open the file for writing.");

    out.write(reinterpret_cast<const char*>(data.salt.data()), data.salt.size());
    out.write(reinterpret_cast<const char*>(data.iv.data()), data.iv.size());
    out.write(reinterpret_cast<const char*>(data.ciphertext.data()), data.ciphertext.size());

    out.close();
}
void crypto::App::_writeData(const std::vector<unsigned char> &plaintext)
{
    if(m_outputFile == "stdout")
    {
        std::cout << plaintext.data() << std::endl;
        return;
    }

    std::ofstream out(m_outputFile, std::ios::binary);

    if (!out)
        throw std::runtime_error("Couldn't open the file for writing.");

    out.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());

    out.close();

}
void crypto::App::_handleEncryption(std::vector<unsigned char> &read_buffer)
{
    if (m_verbose == true)
    {
        std::cout.write(reinterpret_cast<char*>(read_buffer.data()), read_buffer.size());
        std::cout << std::endl;
    }
    CipherBundle cipherData;

    m_cryptEngine->encryptData(read_buffer, m_password, cipherData);

    if (m_verbose == true)
    {
        std::cout << "Hexadecimal representation" << std::endl;
        printHex(cipherData.ciphertext.data(), cipherData.ciphertext.size());
    }
    _writeData(cipherData);
}

void crypto::App::_handleDecryption(std::vector<unsigned char> &read_buffer)
{
    if (m_verbose == true)
    {    
        std::cout.write(reinterpret_cast<char*>(read_buffer.data()), read_buffer.size());
        std::cout << std::endl;
    }

    CipherBundle cipherData;

    cipherData.salt.resize(_SALT_LENGTH);
    cipherData.iv.resize(_IV_LENGTH);
    cipherData.ciphertext.resize(read_buffer.size() - _SALT_LENGTH - _IV_LENGTH);

    std::copy(read_buffer.begin(), 
        read_buffer.begin() + _SALT_LENGTH , 
        cipherData.salt.begin());

    std::copy(read_buffer.begin() + _SALT_LENGTH, 
        read_buffer.begin() + _SALT_LENGTH + _IV_LENGTH, 
        cipherData.iv.begin());
    
    std::copy(read_buffer.begin() + _SALT_LENGTH + _IV_LENGTH, 
        read_buffer.end(), 
        cipherData.ciphertext.begin());

    std::vector<unsigned char> plaintext;
    m_cryptEngine->decryptData(plaintext, m_password, cipherData);

    if(m_verbose == true)
    {
        std::cout << "Hexadecimal representation" << std::endl;
        printHex(plaintext.data(), plaintext.size());
    }

    _writeData(plaintext);
}
