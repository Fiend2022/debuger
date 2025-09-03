#include "debugger.hpp"
#include <iostream>
#include <filesystem>
#include <vector>
#include <iomanip>
#include <stdexcept>
#include <sstream>
#include <functional>
#include  <winnt.h>

namespace fs = std::filesystem;

bool Debugger::createDebugProc(const std::string& prog)
{
    if (!fs::exists(prog)) 
    {
        std::cerr << "Executable file not found: " << prog << std::endl;
        return false;
    }

    STARTUPINFOA startupInfo;
    PROCESS_INFORMATION procInfo;
    bool ret;

    RtlZeroMemory(&startupInfo, sizeof(startupInfo));
    RtlZeroMemory(&procInfo, sizeof(procInfo));
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_SHOWNORMAL;

    ret = CreateProcessA(prog.c_str(),
        NULL,
        NULL,
        NULL,
        TRUE,
        DEBUG_ONLY_THIS_PROCESS,
        NULL,
        NULL,
        &startupInfo,
        &procInfo);
    
    if (ret)
    {
        hProcess = procInfo.hProcess;
        CloseHandle(procInfo.hThread);
        active = true;
        isRun = true;
    }
    else
        std::cerr << "Failed to create process: " << GetLastError() << std::endl;
    return ret;
    
}


void Debugger::run(const std::string& prog)
{
    if (createDebugProc(prog))
        debugRun();
    else
        std::cerr << "Failed to create process: " << GetLastError() << std::endl;
}

size_t Debugger::disasDebugProc(DWORD_PTR addr, size_t instCount)
{
    size_t size = 15 * instCount;
    std::vector<BYTE> buf(size);
    size_t offset = 0;

    if (!ReadProcessMemory(hProcess, (LPCVOID)addr, buf.data(), size, NULL))
    {
        std::cerr << "Failed to read memory: " << GetLastError() << std::endl;
        return 0;
    }

    for (size_t i = 0; i < instCount; ++i) 
    {
        std::string asmBuf(128, '\0');
        std::string hexBuf(128, '\0'); 
        size_t len = this->disas.DisasInst(buf.data() + offset, size - offset, (size_t)addr + offset, asmBuf, hexBuf);
        if (!len) {
            break;
        }
        std::cout << std::hex << (DWORD_PTR)addr + offset << ": " << hexBuf << " " << asmBuf << std::endl;
        offset += len;
    }

    return offset;
}

void Debugger::setBreakPoint(DWORD_PTR addr, BreakType type)
{
    auto it = breakMap.find(addr);
    if (it == breakMap.end())
    {
        BYTE saveByte;
        ReadProcessMemory(hProcess, (PVOID)addr, &saveByte, 1, NULL);
        WriteProcessMemory(hProcess, (PVOID)addr, "\xCC", 1, NULL);
        breakMap[addr] = { BreakState::enable, BreakType::software, saveByte };
    }
}

void Debugger::deleteBreakPoint(DWORD_PTR addr)
{
    auto it = breakMap.find(addr);
    if (it != breakMap.end())
    {
        breakMap[addr].state = BreakState::disable;
        WriteProcessMemory(hProcess, (PVOID)addr, &breakMap[addr].saveByte, 1, NULL);
        breakMap.erase(it);
    }
    else 
    {
        std::cerr << "No breakpoint found at 0x" << std::hex << addr << std::endl;
    }

}

void Debugger::printRegisters(const CONTEXT& context)
{
    std::cout << std::hex << std::setfill('0');

#ifdef _WIN64
    // 64-битные регистры
    std::cout
        << "rax = " << std::setw(8) << context.Rax << " "
        << "rbx = " << std::setw(8) << context.Rbx << " "
        << "rcx = " << std::setw(8) << context.Rcx << " "
        << "rdx = " << std::setw(8) << context.Rdx << "\n"
        << "rsi = " << std::setw(8) << context.Rsi << " "
        << "rdi = " << std::setw(8) << context.Rdi << " "
        << "rbp = " << std::setw(8) << context.Rbp << " "
        << "rsp = " << std::setw(8) << context.Rsp << "\n"
        << "rip = " << std::setw(8) << context.Rip << " "
        << "rflags = " << std::setw(8) << context.EFlags << "\n";
#else
    // 32-битные регистры
    std::cout
        << "eax = " << std::setw(8) << context.Eax << " "
        << "ebx = " << std::setw(8) << context.Ebx << " "
        << "ecx = " << std::setw(8) << context.Ecx << " "
        << "edx = " << std::setw(8) << context.Edx << "\n"
        << "esi = " << std::setw(8) << context.Esi << " "
        << "edi = " << std::setw(8) << context.Edi << " "
        << "ebp = " << std::setw(8) << context.Ebp << " "
        << "esp = " << std::setw(8) << context.Esp << "\n"
        << "eip = " << std::setw(8) << context.Eip << " "
        << "eflags = " << std::setw(8) << context.EFlags << "\n";
#endif
}



std::vector<BYTE> Debugger::getDumpMemory(DWORD_PTR addr, size_t size=128)
{
    std::vector<BYTE> buffer(size, 0);
    if (!ReadProcessMemory(hProcess, (PVOID)addr, buffer.data(), size, NULL)) {
        DWORD error = GetLastError();
        std::string errorMsg = "FAILED READ MEMORY: Error code " + std::to_string(error);
        throw std::runtime_error(errorMsg);
    }
    return buffer;
}

void Debugger::printMemory(DWORD_PTR addr, size_t size=128)
{
    try 
    {
        auto buff = getDumpMemory(addr, size);
        for (size_t i = 0; i < buff.size(); i += lineSize)
        {
            std::cout << std::hex << std::setw(8) << std::setfill('0')
                << static_cast<uintptr_t>(addr) << ": ";
            for (size_t j = 0; j < lineSize; ++j) 
            {
                if (i + j < size) 
                    std::cout << std::hex << std::setw(2) << std::setfill('0')
                        << static_cast<int>(buff[i + j]) << " ";
                
                else
                    std::cout << "   "; 
                
            }
            std::cout << "| ";

            for (size_t j = 0; j < lineSize; ++j) {
                if (i + j < size) {
                    char c = static_cast<char>(buff[i + j]);
                    if (c >= ' ' && c <= '~')
                        std::cout << c;
         
                    else
                        std::cout << "."; 
                }
                else {
                    std::cout << " "; 
                }
            }

            std::cout << std::endl;
            addr = (static_cast<uintptr_t>(addr) + lineSize);
        }

    }
    catch (const std::exception& e) 
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void Debugger::changeMemory(DWORD_PTR addr, size_t value, size_t size = 4)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, (PVOID)addr, &mbi, sizeof(mbi)) == 0) 
    {
        DWORD error = GetLastError();
        std::string errorMsg = "FAILED WRITE MEMORY: Error code " + std::to_string(error);
        throw std::runtime_error(errorMsg);
    }

    //if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY
    //    || mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_WRITECOPY)

        if (!WriteProcessMemory(hProcess, (PVOID)addr, &value, size, nullptr)) 
        {
            DWORD error = GetLastError();
            std::string errorMsg = "FAILED WRITE MEMORY: Error code " + std::to_string(error);
            throw std::runtime_error(errorMsg);
        }
    

    //else
    //{
    //    std::string errorMsg = "FAILED WRITE MEMORY: Writng to addres" 
    //        + std::to_string(reinterpret_cast<uintptr_t>(addr)) + " is not permitted.";
    //    throw std::runtime_error(errorMsg);
    //}


}


void Debugger::debugRun()
{
    
    while (active) 
    {
        DEBUG_EVENT debugEvent;
        DWORD continueFlag = DBG_CONTINUE;
        LPTHREAD_START_ROUTINE entryPoint;
        if (!WaitForDebugEvent(&debugEvent, INFINITE))
            break;

        switch (debugEvent.dwDebugEventCode)
        {
        case CREATE_THREAD_DEBUG_EVENT:
            std::cout << "Thread created: " << debugEvent.dwThreadId << std::endl;
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            std::cout << "Thread exited: " << debugEvent.dwThreadId << std::endl;
            break;
        case CREATE_PROCESS_DEBUG_EVENT:
            std::cout << "Process created: " << debugEvent.dwProcessId << std::endl;
            entryPoint = debugEvent.u.CreateProcessInfo.lpStartAddress;
            disasDebugProc(reinterpret_cast<DWORD_PTR>(entryPoint));
            setBreakPoint((DWORD)entryPoint, BreakType::software);
            std::cout << "Entry point address: 0x" << std::hex << entryPoint << std::endl;
            


            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            std::cout << "Process exited: " << debugEvent.dwProcessId << std::endl;
            active = false;
            break;
        case LOAD_DLL_DEBUG_EVENT:
            std::cout << "DLL loaded: " << debugEvent.u.LoadDll.lpBaseOfDll << std::endl;
            break;
        case UNLOAD_DLL_DEBUG_EVENT:
            std::cout << "DLL unloaded: " << debugEvent.u.UnloadDll.lpBaseOfDll << std::endl;
            break;
        case OUTPUT_DEBUG_STRING_EVENT:
            std::cout << "Debug string: " << debugEvent.u.DebugString.lpDebugStringData << std::endl;
            break;

        case EXCEPTION_DEBUG_EVENT:

            continueFlag = eventException(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.Exception);
            break;

        default:
            printf("Unexpected debug event: %d\n", debugEvent.dwDebugEventCode);
        }

        if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueFlag)) {
            printf("Error continuing debug event\n");
        }
        else
        {
            auto it = std::find_if(breakMap.begin(), breakMap.end(), [](const auto& pair) {
                return pair.second.state == BreakState::disable;
                });
            if (it != breakMap.end())
            {
                WriteProcessMemory(hProcess, (PVOID)it->first, "\xCC", 1, NULL);
                it->second.state = BreakState::enable;
            }
        }
    }

    CloseHandle(hProcess);

    return;
}



size_t Debugger::breakpointEvent(DWORD tid, DWORD_PTR exceptionAddr)
{
    CONTEXT context;
    HANDLE thread;


    auto it = breakMap.find(exceptionAddr);

    if (it == breakMap.end() && !isTrace && !isRun)
        return DBG_EXCEPTION_NOT_HANDLED;

    if (it != breakMap.end())
    {
        WriteProcessMemory(hProcess, (PVOID)exceptionAddr, &it->second.saveByte, 1, NULL);
        it->second.state = BreakState::disable;
    }
    disasDebugProc(exceptionAddr, 1);

    thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
    if (thread != INVALID_HANDLE_VALUE) {
        context.ContextFlags = CONTEXT_ALL;
        GetThreadContext(thread, &context);
        if (it != breakMap.end()) 
            #ifdef _WIN64
                context.Rip = exceptionAddr;
            #else
                context.Eip = exceptionAddr;
            #endif

        
    }
    isTrace = false;
    isRun = false;
    while (!isRun && !isTrace)
    {
        std::string cmd;
        std::getline(std::cin, cmd);        
        commandLine(cmd, context);
    }
    if (isTrace)
        context.EFlags |= 0x100;
    else
        context.EFlags &= ~0x100;

    SetThreadContext(thread, &context);
    CloseHandle(thread);

    return DBG_CONTINUE;
}

size_t Debugger::eventException(DWORD pid, DWORD tid, LPEXCEPTION_DEBUG_INFO exceptionDebugInfo)
{
    DWORD continueFlag = (DWORD)DBG_EXCEPTION_NOT_HANDLED;

    switch (exceptionDebugInfo->ExceptionRecord.ExceptionCode) 
    {

        case EXCEPTION_BREAKPOINT:
            continueFlag = breakpointEvent(tid, (ULONG_PTR)exceptionDebugInfo->ExceptionRecord.ExceptionAddress);
            break;

        
        case EXCEPTION_SINGLE_STEP:
            continueFlag = breakpointEvent(tid, (ULONG_PTR)exceptionDebugInfo->ExceptionRecord.ExceptionAddress);
            break;
    }
    return continueFlag;
}


void Debugger::commandLine(const std::string& command, CONTEXT& cont)
{
   
    std::istringstream iss(command);
    std::string cmd;
    iss >> cmd;

    auto it = commands.find(cmd);
    if (it == commands.end()) {
        std::cerr << "Unknown command: " << cmd << "\n";
        return;
    }

    switch (commands[cmd])
    {
        case Commands::run:
            isRun = true;
            break;
        case Commands::trace:
            handleTraceCommand();
            break;
        case Commands::setBP:
            handleBpCommand(iss);
            break;
        case Commands::delBP:
            handleDelCommand(iss);
            break;
        case Commands::disas:
            handleDisasCommand(iss);
            break;
        case Commands::getMem:
            handleDumpCommand(iss);
            break;
        case Commands::reg:
            handleRegCommand(iss, cont);
            break;
        case Commands::chgMem:
            handleEditCommand(iss);
            break;
        default:
            std::cout << "Unknow commands" << std::endl;
            break;


    }

}

void Debugger::handleTraceCommand()
{
    isTrace = true;
}


DWORD getAddr(std::istringstream& stream)
{
    DWORD addr;
    stream >> std::hex >> addr;

    //if (!(stream >> std::hex >> addr))
    //{
    //    std::cerr << "Invalid address format. Expected hexadecimal value.\n";
    //    return 0;
    //}

    if (addr > 0x7FFFFFFF)
    {
        std::cerr << "Address out of range: 0x" << std::hex << addr << "\n";
        return 0;
    }
    return addr;
}

void Debugger::handleBpCommand(std::istringstream& stream)
{
    DWORD addr = getAddr(stream);

    setBreakPoint(addr, BreakType::software);

}


void Debugger::handleDelCommand(std::istringstream& stream)
{
    DWORD addr = getAddr(stream);
    deleteBreakPoint(addr);
}
 
void Debugger::handleDumpCommand(std::istringstream& stream)
{
    DWORD addr = getAddr(stream);
    printMemory(addr);
}


void Debugger::handleDisasCommand(std::istringstream& stream)
{
    DWORD_PTR addr = getAddr(stream);
    disasDebugProc(addr);
}

void  Debugger::handleEditCommand(std::istringstream& stream)
{
    DWORD addr = getAddr(stream);
    size_t size, value;
    std::string strSize;
    stream >> strSize;
    

    auto it = dataSize.find(strSize);
    if (it != dataSize.end())
    {
        if (!(stream >> std::hex >> value)) 
        {
            std::cerr << "Invalid value format. Expected hexadecimal value.\n";
            return;
        }
        changeMemory(addr, value, dataSize[strSize]);
    }
    else
    {
        std::cerr << "Invalid size type. Expected db, dw, or dd.\n";
        return;
    }



}







void Debugger::handleRegCommand(std::istringstream& stream, CONTEXT& context)
{
    std::string regName;
    DWORD_PTR value;  // Используем DWORD_PTR вместо DWORD

    // Если аргументов нет, выводим все регистры
    if (stream.peek() == EOF) {
        printRegisters(context);
        return;
    }

    // Читаем имя регистра и значение
    stream >> regName;
    if (!(stream >> std::hex >> value)) {
        std::cerr << "Invalid value format. Expected hexadecimal value.\n";
        return;
    }

    // Определяем маппинг регистров в зависимости от разрядности
#ifdef _WIN64
    // 64-битные регистры и их части
    static const std::unordered_map<std::string, std::function<void(CONTEXT&, DWORD_PTR)>> regMap = {
        // Полные 64-битные регистры
        {"rax", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rax = val; }},
        {"rbx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rbx = val; }},
        {"rcx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rcx = val; }},
        {"rdx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rdx = val; }},
        {"rdi", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rdi = val; }},
        {"rsi", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rsi = val; }},
        {"rbp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rbp = val; }},
        {"rsp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rsp = val; }},
        {"rip", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rip = val; }},
        {"rflags", [](CONTEXT& ctx, DWORD_PTR val) { ctx.EFlags = static_cast<DWORD>(val); }},

        // Дополнительные 64-битные регистры
        {"r8",  [](CONTEXT& ctx, DWORD_PTR val) { ctx.R8 = val; }},
        {"r9",  [](CONTEXT& ctx, DWORD_PTR val) { ctx.R9 = val; }},
        {"r10", [](CONTEXT& ctx, DWORD_PTR val) { ctx.R10 = val; }},
        {"r11", [](CONTEXT& ctx, DWORD_PTR val) { ctx.R11 = val; }},
        {"r12", [](CONTEXT& ctx, DWORD_PTR val) { ctx.R12 = val; }},
        {"r13", [](CONTEXT& ctx, DWORD_PTR val) { ctx.R13 = val; }},
        {"r14", [](CONTEXT& ctx, DWORD_PTR val) { ctx.R14 = val; }},
        {"r15", [](CONTEXT& ctx, DWORD_PTR val) { ctx.R15 = val; }},

        // Младшие 32 бита (например, eax = младшие 32 бита rax)
        {"eax", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rax = (ctx.Rax & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},
        {"ebx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rbx = (ctx.Rbx & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},
        {"ecx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rcx = (ctx.Rcx & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},
        {"edx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rdx = (ctx.Rdx & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},
        {"edi", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rdi = (ctx.Rdi & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},
        {"esi", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rsi = (ctx.Rsi & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},
        {"ebp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rbp = (ctx.Rbp & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},
        {"esp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rsp = (ctx.Rsp & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},
        {"eip", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rip = (ctx.Rip & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},

        // Младшие 16 бит (например, ax = младшие 16 бит rax)
        {"ax", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rax = (ctx.Rax & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},
        {"bx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rbx = (ctx.Rbx & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},
        {"cx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rcx = (ctx.Rcx & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},
        {"dx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rdx = (ctx.Rdx & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},
        {"di", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rdi = (ctx.Rdi & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},
        {"si", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rsi = (ctx.Rsi & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},
        {"bp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rbp = (ctx.Rbp & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},
        {"sp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rsp = (ctx.Rsp & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},
        {"ip", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rip = (ctx.Rip & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},

        // Младшие 8 бит (например, al = младшие 8 бит rax)
        {"al", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rax = (ctx.Rax & 0xFFFFFFFFFFFFFF00ULL) | (val & 0xFF); }},
        {"ah", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rax = (ctx.Rax & 0xFFFFFFFFFFFF00FFULL) | ((val & 0xFF) << 8); }},
        {"bl", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rbx = (ctx.Rbx & 0xFFFFFFFFFFFFFF00ULL) | (val & 0xFF); }},
        {"bh", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rbx = (ctx.Rbx & 0xFFFFFFFFFFFF00FFULL) | ((val & 0xFF) << 8); }},
        {"cl", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rcx = (ctx.Rcx & 0xFFFFFFFFFFFFFF00ULL) | (val & 0xFF); }},
        {"ch", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rcx = (ctx.Rcx & 0xFFFFFFFFFFFF00FFULL) | ((val & 0xFF) << 8); }},
        {"dl", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rdx = (ctx.Rdx & 0xFFFFFFFFFFFFFF00ULL) | (val & 0xFF); }},
        {"dh", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rdx = (ctx.Rdx & 0xFFFFFFFFFFFF00FFULL) | ((val & 0xFF) << 8); }},
    };
#else
    // 32-битные регистры и их части
    static const std::unordered_map<std::string, std::function<void(CONTEXT&, DWORD_PTR)>> regMap = {
        {"eax", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Eax = static_cast<DWORD>(val); }},
        {"ebx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ebx = static_cast<DWORD>(val); }},
        {"ecx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ecx = static_cast<DWORD>(val); }},
        {"edx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Edx = static_cast<DWORD>(val); }},
        {"edi", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Edi = static_cast<DWORD>(val); }},
        {"esi", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Esi = static_cast<DWORD>(val); }},
        {"ebp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ebp = static_cast<DWORD>(val); }},
        {"esp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Esp = static_cast<DWORD>(val); }},
        {"eip", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Eip = static_cast<DWORD>(val); }},
        {"eflags", [](CONTEXT& ctx, DWORD_PTR val) { ctx.EFlags = static_cast<DWORD>(val); }},

        // Подрегистры: 16 бит
        {"ax", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Eax = (ctx.Eax & 0xFFFF0000) | (val & 0xFFFF); }},
        {"bx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ebx = (ctx.Ebx & 0xFFFF0000) | (val & 0xFFFF); }},
        {"cx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ecx = (ctx.Ecx & 0xFFFF0000) | (val & 0xFFFF); }},
        {"dx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Edx = (ctx.Edx & 0xFFFF0000) | (val & 0xFFFF); }},
        {"di", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Edi = (ctx.Edi & 0xFFFF0000) | (val & 0xFFFF); }},
        {"si", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Esi = (ctx.Esi & 0xFFFF0000) | (val & 0xFFFF); }},
        {"bp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ebp = (ctx.Ebp & 0xFFFF0000) | (val & 0xFFFF); }},
        {"sp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Esp = (ctx.Esp & 0xFFFF0000) | (val & 0xFFFF); }},
        {"ip", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Eip = (ctx.Eip & 0xFFFF0000) | (val & 0xFFFF); }},

        // Подрегистры: 8 бит
        {"al", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Eax = (ctx.Eax & 0xFFFFFF00) | (val & 0xFF); }},
        {"ah", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Eax = (ctx.Eax & 0xFFFF00FF) | ((val & 0xFF) << 8); }},
        {"bl", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ebx = (ctx.Ebx & 0xFFFFFF00) | (val & 0xFF); }},
        {"bh", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ebx = (ctx.Ebx & 0xFFFF00FF) | ((val & 0xFF) << 8); }},
        {"cl", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ecx = (ctx.Ecx & 0xFFFFFF00) | (val & 0xFF); }},
        {"ch", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ecx = (ctx.Ecx & 0xFFFF00FF) | ((val & 0xFF) << 8); }},
        {"dl", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Edx = (ctx.Edx & 0xFFFFFF00) | (val & 0xFF); }},
        {"dh", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Edx = (ctx.Edx & 0xFFFF00FF) | ((val & 0xFF) << 8); }},
    };
#endif

    // Поиск и изменение регистра
    auto it = regMap.find(regName);
    if (it != regMap.end()) {
        it->second(context, value);
        std::cout << "Register " << regName << " updated to 0x" << std::hex << value << std::endl;
    }
    else {
        std::cerr << "Unknown register: " << regName << "\n";
    }
}