#include <vector>
#include <iostream>
#include <udis86.h>
#include <unordered_map>
#include <Windows.h>
#include <string>
#include "disas.hpp"
#include <sstream>

static const size_t lineSize = 16;
class Debugger
{
private:
    enum class BreakState 
    {
        disable,enable
    };
    enum class BreakType 
    {
        software, hardware
    };
    
    enum class Commands
    {
        run, trace, setBP, delBP, disas, reg, chgMem, getMem, setReg
    };

    struct BreakPoint 
    {

        BreakState state;
        BreakType type;
        DWORD saveByte;

    };

    std::unordered_map<DWORD, BreakPoint> breakMap;
    HANDLE hProcess;
    bool active = false;
    bool isRun = false;
    bool isTrace = false;
    Disassembler disas;



    bool createDebugProc(const std::string& prog);
    void debugRun();
    size_t disasDebugProc(PVOID addr, size_t instCount=5);
    void setBreakPoint(DWORD addr, BreakType type);
    void deleteBreakPoint(DWORD addr);
    void printRegisters(const CONTEXT& context);
    void changeRegisters(CONTEXT* context, const std::string& reg, DWORD value);
    void printMemory(PVOID addr, size_t size);
    std::vector<BYTE> getDumpMemory(PVOID addr, size_t size);
    void changeMemory(PVOID addr, DWORD value, size_t size);
    size_t eventException(DWORD pid, DWORD tid, LPEXCEPTION_DEBUG_INFO exceptionDebugInfo);
    size_t breakpointEvent(DWORD tid, ULONG_PTR exceptionAddr);


    std::unordered_map<std::string, Debugger::Commands> commands =
    {
        {"run", Commands::run},
        {"bp", Commands::setBP},
        {"del", Commands::delBP},
        {"g", Commands::trace},
        {"dump", Commands::getMem},
        {"edit", Commands::chgMem},
        {"reg", Commands::reg},
        {"disas", Commands::disas},
        {"set", Commands::setReg}

    };  
    std::unordered_map<std::string, size_t> dataSize =
    {
        {"db", 1},
        {"dw", 2},
        {"dd", 4},
    };

    void commandLine(const std::string& command, CONTEXT& cont);
    void handleTraceCommand();
    void handleBpCommand(std::istringstream& stream);
    void handleDelCommand(std::istringstream& stream);
    void handleDumpCommand(std::istringstream& stream);
    void handleDisasCommand(std::istringstream& stream);
    void handleEditCommand(std::istringstream& stream);
    void handleRegCommand(std::istringstream& stream, CONTEXT& context);

public:
    void run(const std::string& prog);

};