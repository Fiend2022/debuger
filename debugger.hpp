#pragma once 

#include <vector>
#include <iostream>
#include <udis86.h>
#include <unordered_map>
#include <Windows.h>
#include <string>
#include "disas.hpp"
#include <sstream>
#include <functional>
#include <map>
#include "msg.hpp"
#include "pe.hpp"
#include <mutex>
#include <condition_variable>
#include <queue>
static const size_t lineSize = 16;



class Debugger
{
private:

    //enum class Commands
    //{
    //    run, trace, setBP, delBP, disas, reg, chgMem, getMem, modules, threads, syms
    //};
    //std::unordered_map<std::string, Debugger::Commands> commands =
    //{
    //    {"run", Commands::run},
    //    {"bp", Commands::setBP},
    //    {"del", Commands::delBP},
    //    {"g", Commands::trace},
    //    {"dump", Commands::getMem},
    //    {"edit", Commands::chgMem},
    //    {"reg", Commands::reg},
    //    {"disas", Commands::disas},
    //    {"modules", Commands::modules},
    //    {"threads", Commands::threads},
    //    {"symbols", Commands::syms}

    //};





    std::queue<std::string> commandQueue;
    std::mutex cmdMutex;
    std::condition_variable cmdCV;
    DWORD_PTR entryAddr;
    struct CommandInfo
    {
        std::string name;
        std::string usage;
        std::function<void(Debugger&, std::istringstream&)> handler;
    };

    std::vector<CommandInfo> commands;

    enum class BreakState
    {
        disable, enable
    };

    enum class BreakType {
        software,
        hardware_write,
        hardware_access
    };

    struct HwBreakpoint {
        bool active = false;
        DWORD_PTR address = 0;
        int size = 0; // 1, 2, 4, 8
    };

    HwBreakpoint hwBps[4];



    bool addHardwareBreakpoint(DWORD_PTR addr, const std::string& typeStr, int size);
    int getHardwareBreakpointIndexFromDr6(DWORD dr6);

    struct BreakPoint
    {
        BreakState state;
        BreakType type;
        BYTE saveByte; 
        bool temp = false;
    };




    struct ExportedSymbol
    {
        std::string name;
        DWORD_PTR address;
    };

    struct Module
    {
        DWORD_PTR baseAddress;
        size_t size;
        std::vector<ExportedSymbol> symbols;

    };

    struct ActiveThread
    {
        DWORD threadId;
        HANDLE hThread;
        bool isRunning;
    };

    PeHeader* prog;
    std::vector<ExportedSymbol> fullExport;
    std::unordered_map<DWORD_PTR, BreakPoint> breakMap; 
    HANDLE hProcess;
    bool active = false;
    bool isRun = false;
    bool isTrace = false;
    Disassembler disas;
    std::unordered_map<std::string, Module> modules;
    std::unordered_map<DWORD, ActiveThread> threads;
    DWORD mainThreadId;
    DWORD_PTR exeBaseAddress;
    CONTEXT* cont;
    std::string resolveSymbol(DWORD_PTR addr);
    DWORD currentThread;
    bool createDebugProc(const std::string& prog);
    void debugRun();




    size_t disasDebugProc(DWORD_PTR addr, size_t instCount = 5);
    std::vector<DisasmLine> disasSection(IMAGE_SECTION_HEADER* sec);

    std::pair<std::vector<DisasmLine>, std::vector<DisasmLine>> getSections();
    std::vector<DisasmLine> getDataSection(IMAGE_SECTION_HEADER* sec);
    void parseCode(std::vector<DisasmLine>* code);

    void setBreakPoint(DWORD_PTR addr, BreakType type);
    void deleteBreakPoint(DWORD_PTR addr);

    void printRegisters(const CONTEXT& context);

    // Используем DWORD_PTR для значений регистров
    void changeRegisters(CONTEXT* context, const std::string& reg, DWORD_PTR value);

    // Используем DWORD_PTR для адресов памяти
    void printMemory(DWORD_PTR addr, size_t size);
    std::vector<BYTE> getDumpMemory(DWORD_PTR addr, size_t size);
    void changeMemory(DWORD_PTR addr, void* value, size_t size);

    size_t eventException(DWORD pid, DWORD tid, LPEXCEPTION_DEBUG_INFO exceptionDebugInfo);
    size_t breakpointEvent(DWORD tid, DWORD_PTR exceptionAddr, DebugEvent* de);
    std::string waitForCommand();


    std::unordered_map<std::string, size_t> dataSize =
    {
        {"db", sizeof(BYTE)},
        {"dw", sizeof(WORD)},
        {"dd", sizeof(DWORD)},
        #ifdef _WIN64
        {"dq", 8} // Добавляем 64-битный размер данных только для 64-битной сборки
        #endif
        
    };

    void commandLine(const std::string& command, CONTEXT& cont);
    void handleTraceCommand();
    void handleBpCommand(std::istringstream& stream);
    void handleDelCommand(std::istringstream& stream);
    void handleDumpCommand(std::istringstream& stream);
    void handleDisasCommand(std::istringstream& stream);
    void handleEditCommand(std::istringstream& stream);
    void handleRegCommand(std::istringstream& stream, CONTEXT& context);
    void handleModulesCommand();
    void handleThreadsCommand();
    void handleSymbolsCommand();


    void handleLoadDLL(DWORD pid, DWORD tid, LOAD_DLL_DEBUG_INFO* info);
    void handleUnloadDLL(DWORD pid, DWORD tid, DWORD_PTR addr);
    void handleCreateThread(DWORD pid, DWORD tid, CREATE_THREAD_DEBUG_INFO* info);
    void handleExitThread(DWORD pid, DWORD tid, DWORD exitCode);
    void handleCreateProcess(DWORD pid, DWORD tid, CREATE_PROCESS_DEBUG_INFO* info);
    void handleLoadExe(DWORD_PTR baseAddr, const std::string& name, DWORD_PTR entryPoint);

    bool parseSymbols(const std::string& arg, std::string& dll, std::string& symbol);
    DWORD_PTR getArgAddr(const std::string& arg);

    std::vector<ExportedSymbol> loadSyms(const std::vector<std::pair<std::string, DWORD_PTR>>&);



    struct CommandArgs
    {
        std::string addressArg;
        DWORD_PTR address;
        int count = 10;
        std::string type = "d";
        std::string value = "d";
        bool helpRequested = false;
        bool valid = true;
    };


    void initComands();
    CommandArgs parseArgs(std::istringstream& stream);
    bool isRegisterString(const std::string& str);
    DWORD_PTR getRegisterValue(const std::string& regName);
    void pushEvent(const DebugEvent& ev);
    std::function<void(const DebugEvent&)> eventCallback;

public:
    void run();
    void setEventCallback(std::function<void(const DebugEvent&)> cb)
    {
        eventCallback = cb;
    }
    void sendCommand(const std::string& cmd);
};