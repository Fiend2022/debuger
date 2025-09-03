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
        disable, enable
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
        BYTE saveByte; // Точка останова - один байт
    };

    std::unordered_map<DWORD_PTR, BreakPoint> breakMap; // Используем DWORD_PTR
    HANDLE hProcess;
    bool active = false;
    bool isRun = false;
    bool isTrace = false;
    Disassembler disas;

    bool createDebugProc(const std::string& prog);
    void debugRun();

    // Используем DWORD_PTR для адресов
    size_t disasDebugProc(DWORD_PTR addr, size_t instCount = 5);
    void setBreakPoint(DWORD_PTR addr, BreakType type);
    void deleteBreakPoint(DWORD_PTR addr);

    void printRegisters(const CONTEXT& context);

    // Используем DWORD_PTR для значений регистров
    void changeRegisters(CONTEXT* context, const std::string& reg, DWORD_PTR value);

    // Используем DWORD_PTR для адресов памяти
    void printMemory(DWORD_PTR addr, size_t size);
    std::vector<BYTE> getDumpMemory(DWORD_PTR addr, size_t size);
    void changeMemory(DWORD_PTR addr, size_t value, size_t size);

    size_t eventException(DWORD pid, DWORD tid, LPEXCEPTION_DEBUG_INFO exceptionDebugInfo);
    size_t breakpointEvent(DWORD tid, DWORD_PTR exceptionAddr); // Используем DWORD_PTR

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

public:
    void run(const std::string& prog);
};