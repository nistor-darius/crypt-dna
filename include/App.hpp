#pragma once


/*
* Singleton class that orchestrates the whole program
* inspiration: StackOverflow
*/

namespace crypto {
    class App
    {
    public:
        App(App const&) = delete;
        void operator=(App const&) = delete;
        static App& getInstance()
        {
            static App instance;
            return instance;
        }

        void initialize(int argc, char** argv);

    private:
        App() {}
        void printUsage();
        // members
        
        

    };
}