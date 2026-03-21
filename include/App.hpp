#pragma once
#include <memory>
#include <vector>
#include "../include/CryptoEngine.hpp"

namespace crypto {
    /*
    Singleton class that orchestrates the whole application logic.
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

        void readData(std::vector<unsigned char>& data);
        void writeData(const CipherBundle& data);
        void writeData(const std::vector<unsigned char>& plaintext);

        // members
        std::unique_ptr<CryptoEngine> m_cryptEngine;
        std::vector<unsigned char> inputData;

        std::string m_inputFile;
        std::string m_outputFile;
        std::string m_password;
        bool m_encyption;
        bool m_verbose;
    };
}