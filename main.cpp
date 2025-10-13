#include "debugger.hpp"
#include "GUI.h"
#include "Logger.hpp"
#include "Observer.hpp"
#include "EventPublisher.hpp"
#include <thread>


int main(int argc, char** argv, char** envp)
{
    GUI gui;
    Logger logger;
    Debugger debugger;
    debugger.attach(&gui);
    debugger.attach(&logger);
    

    
 
    gui.setCommandCallback([&debugger](const std::string& cmd) {
        debugger.sendCommand(cmd);
        });


    std::thread debugThread(&Debugger::run, &debugger);
    gui.run();
    debugThread.join();
    return 0;
}