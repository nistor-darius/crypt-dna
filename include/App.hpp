#pragma once
#include <memory>
#include <vector>
#include "../include/CryptoEngine.hpp"

namespace crypto {
    /*
    *   Singleton class that orchestrates the whole application logic.
    */
    class App
    {
    public:
        App(App const&) = delete;
        void operator=(App const&) = delete;
        static App& getInstance();

        void initialize(int argc, char** argv);

        void run();
    private:
        App() : m_cryptEngine(std::make_unique<CryptoEngine>()) {}

        void _readData(std::vector<unsigned char>& data);
        void _readData(std::vector<unsigned char> &buffer, const std::string& file);
        void _writeData(const CipherBundle& data);
        void _writeData(const std::vector<unsigned char>& plaintext);


        void _handleEncryption(std::vector<unsigned char>& read_buffer);
        void _handleDecryption(std::vector<unsigned char>& read_buffer);

        void _handleShowDNA(std::vector<unsigned char>& read_buffer);

        // members
        std::unique_ptr<CryptoEngine> m_cryptEngine;
        std::vector<unsigned char> inputData;

        std::string m_inputFile;
        std::string m_outputFile;
        std::string m_password;
        std::string m_keyFile;
        bool m_encyption;
        bool m_verbose;
        bool m_showDna;
    };
}