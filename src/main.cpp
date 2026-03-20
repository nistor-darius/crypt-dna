/*
*   DNA-Encryption tool
*   Authors: Moraru Andra and Nistor Darius
*   version 0.0.2
*/
#include <iostream>
#include <memory>
#include "../include/App.hpp"

int main(int argc, char** argv)
{
    try
    {
        crypto::App::getInstance().initialize(argc, argv);
        crypto::App::getInstance().run();
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return 1;
    }
    catch(...)
    {
        return 1;
    }
    
    return 0;
}