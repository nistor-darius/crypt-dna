/*
*   DNA-Encryption tool
*   Authors: Moraru Andra and Nistor Darius
*   version 0.0.1
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
    catch(const std::invalid_argument&)
    {
        return 1;
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return 1;
    }
    catch(...)
    {
        std::cerr << "An unknown error occurred." << std::endl;
        return 1;
    }
    
    return 0;
}