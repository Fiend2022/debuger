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
#include "Logger.hpp"
#include "EventPublisher.hpp"
#include "DebugAPI.hpp"
#include "pluginManager.hpp"

static const size_t lineSize = 16;


 
class Debugger : public EventPublisher
{
private:
    friend struct DebugAPI;
    PluginManager plugManager;

    std::queue<std::string> commandQueue;
    std::mutex cmdMutex;
    std::condition_variable cmdCV;
    DWORD_PTR entryAddr;
    struct CommandInfo
    {
        std::string name;
        std::string usage;
        std::function<std::string(Debugger&, std::istringstream&)> handler;
        DebugEvent::Type type;
    };

    std::vector<CommandInfo> commands;

    enum class BreakState
    {
        disable, enable
    };


    struct HwBreakpoint {
        bool active = false;
        DWORD_PTR address = 0;
        int size = 0; // 1, 2, 4, 8
    };

    HwBreakpoint hwBps[4];



    bool addHardwareBreakpoint(DWORD_PTR addr, const std::string& typeStr, int size);
    bool delHardwareBreakpoint(DWORD_PTR addr);
    int getHardwareBreakpointIndexFromDr6(DWORD dr6);

    struct BreakPoint
    {
        BreakState state;
        BYTE saveByte; 
        bool temp = false;
        DWORD_PTR address = 0;
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
    bool isStep = false;
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




    size_t disasDebugProc(DWORD_PTR addr, std::ostream& stream, size_t instCount = 5);
    std::vector<DisasmLine> disasSection(IMAGE_SECTION_HEADER* sec);

    std::pair<std::vector<DisasmLine>, std::vector<DataSection>> getSections();
    std::vector<DataLine> getDataSection(IMAGE_SECTION_HEADER* sec);
    void parseCode(std::vector<DisasmLine>* code);

    bool setBreakPoint(DWORD_PTR addr, bool temp);
    void deleteBreakPoint(DWORD_PTR addr);
    void disableBreakPoint(DWORD_PTR addr);

    void printRegisters(const CONTEXT& context, std::ostream& output);

    // Используем DWORD_PTR для значений регистров
    // void changeRegisters(CONTEXT* context, const std::string& reg, DWORD_PTR value);

    // Используем DWORD_PTR для адресов памяти
    void printMemory(DWORD_PTR addr, std::ostream& stream, size_t size);
    std::vector<BYTE> getDumpMemory(DWORD_PTR addr, size_t size);
    void changeMemory(DWORD_PTR addr, void* value, size_t size);

    size_t eventException(DWORD pid, DWORD tid, LPEXCEPTION_DEBUG_INFO exceptionDebugInfo);
    size_t breakpointEvent(DWORD tid, DWORD_PTR exceptionAddr, DebugEvent* de);
    std::string waitForCommand();
    DWORD_PTR getRetAddr();

    std::unordered_map<std::string, size_t> dataSize =
    {
        {"db", sizeof(BYTE)},
        {"dw", sizeof(WORD)},
        {"dd", sizeof(DWORD)},
        #ifdef _WIN64
        {"dq", 8} // Добавляем 64-битный размер данных только для 64-битной сборки
        #endif
        
    };

    void commandLine(const std::string& command);
    //void handleStepCommand();
    void handleBpCommand(std::istringstream& stream);
    void handleDelCommand(std::istringstream& stream);
    //void handleDumpCommand(std::istringstream& stream);
    //void handleDisasCommand(std::istringstream& stream);
    //void handleEditCommand(std::istringstream& stream);
    void handleRegCommand(std::istringstream& stream, std::ostream& output, CONTEXT& context);
    void handleModulesCommand(std::ostream& ss);
    void handleThreadsCommand(std::ostream& ss);
    void handleSymbolsCommand();
    void handleStepOver();
    void handleStepOut();

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

    void rangeStep();
    bool isTracing = false;
    DWORD_PTR startTrace = 5;
    DWORD_PTR endTrace = 0;
    void startTraceRange();

    size_t traceRangeEvent(DWORD tid, DWORD_PTR exceptionAddr, DebugEvent* de);
    void userRun();


    enum DebugState
    {
        RUN, STOP, STEP, TRACING, TRACE_RUN
    };
    DebugState state = STOP;



    std::vector<StackLine> getStack(const int numEntries);

    DWORD_PTR getIP()
    {
#if defined(_WIN64)
        return cont->Rip;
#else
        return cont->Eip;
#endif
    }

    void setIP(DWORD_PTR addr)
    {
#if defined(_WIN64)
        cont->Rip = addr;
#else
        cont->Eip = addr;
#endif
    }

    bool regEdit(const std::string& reg, CONTEXT& context, DWORD_PTR value);
public:
    Debugger() = default;
    void run();
    void sendCommand(const std::string& cmd);
};