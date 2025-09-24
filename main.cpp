#include "debugger.hpp"
#include "GUI.h"
#include <thread>


int main(int argc, char** argv, char** envp)
{
    GUI gui;
    Debugger debugger;

 
    gui.setCommandCallback([&debugger](const std::string& cmd) {
        debugger.sendCommand(cmd);
        });

    debugger.setEventCallback([&gui](const DebugEvent& ev) {
        gui.pushEvent(ev);
        });
    std::thread debugThread(&Debugger::run, &debugger);
    gui.run();
    debugThread.join();
    return 0;
}