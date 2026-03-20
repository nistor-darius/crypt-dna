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
        void printUsage(char* name);
        // members
        std::unique_ptr<CryptoEngine> m_cryptEngine;
        std::vector<unsigned char> inputData;

        unsigned char* m_salt;

    };
}