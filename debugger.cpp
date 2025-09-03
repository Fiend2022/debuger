#include "debugger.hpp"
#include <iostream>
#include <filesystem>
#include <vector>
#include <iomanip>
#include <stdexcept>
#include <sstream>
#include <functional>

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

size_t Debugger::disasDebugProc(PVOID addr, size_t instCount)
{
    size_t size = 15 * instCount;
    std::vector<BYTE> buf(size);
    size_t offset = 0;

    if (!ReadProcessMemory(hProcess, addr, buf.data(), size, NULL)) 
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
        std::cout << std::hex << (size_t)addr + offset << ": " << hexBuf << " " << asmBuf << std::endl;
        offset += len;
    }

    return offset;
}

void Debugger::setBreakPoint(DWORD addr, BreakType type)
{
    auto it = breakMap.find(addr);
    if (it == breakMap.end())
    {
        DWORD saveByte;
        ReadProcessMemory(hProcess, (PVOID)addr, &saveByte, 1, NULL);
        WriteProcessMemory(hProcess, (PVOID)addr, "\xCC", 1, NULL);
        breakMap[addr] = { BreakState::enable, BreakType::software, saveByte };
    }
}

void Debugger::deleteBreakPoint(DWORD addr)
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
    std::cout << "eax = " << std::hex << std::setw(8) << std::setfill('0') << context.Eax << "  "
        << "ebx = " << std::hex << std::setw(8) << std::setfill('0') << context.Ebx << "  "
        << "ecx = " << std::hex << std::setw(8) << std::setfill('0') << context.Ecx << "  "
        << "edx = " << std::hex << std::setw(8) << std::setfill('0') << context.Edx << "\n";

    std::cout << "edi = " << std::hex << std::setw(8) << std::setfill('0') << context.Edi << "  "
        << "esi = " << std::hex << std::setw(8) << std::setfill('0') << context.Esi << "  "
        << "ebp = " << std::hex << std::setw(8) << std::setfill('0') << context.Ebp << "  "
        << "esp = " << std::hex << std::setw(8) << std::setfill('0') << context.Esp << "\n";

    std::cout << "eflags = " << std::hex << std::setw(8) << std::setfill('0') << context.EFlags << "\n";
}

void Debugger::changeRegisters(CONTEXT* context, const std::string& reg, DWORD value)
{
    static const std::unordered_map<std::string, DWORD CONTEXT::*> regMap = {
        {"eax", &CONTEXT::Eax},
        {"ebx", &CONTEXT::Ebx},
        {"ecx", &CONTEXT::Ecx},
        {"edx", &CONTEXT::Edx},
        {"edi", &CONTEXT::Edi},
        {"esi", &CONTEXT::Esi},
        {"ebp", &CONTEXT::Ebp},
        {"esp", &CONTEXT::Esp},
        {"eflags", &CONTEXT::EFlags},
    };

    auto it = regMap.find(reg);
    if (it != regMap.end()) 
        context->*(it->second) = value;

}

std::vector<BYTE> Debugger::getDumpMemory(PVOID addr, size_t size=128)
{
    std::vector<BYTE> buffer(size, 0);
    if (!ReadProcessMemory(hProcess, addr, buffer.data(), size, NULL)) {
        DWORD error = GetLastError();
        std::string errorMsg = "FAILED READ MEMORY: Error code " + std::to_string(error);
        throw std::runtime_error(errorMsg);
    }
    return buffer;
}

void Debugger::printMemory(PVOID addr, size_t size=128)
{
    try 
    {
        auto buff = getDumpMemory(addr, size);
        for (size_t i = 0; i < buff.size(); i += lineSize)
        {
            std::cout << std::hex << std::setw(8) << std::setfill('0')
                << reinterpret_cast<uintptr_t>(addr) << ": ";
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
            addr = reinterpret_cast<PVOID>(reinterpret_cast<uintptr_t>(addr) + lineSize);
        }

    }
    catch (const std::exception& e) 
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void Debugger::changeMemory(PVOID addr, DWORD value, size_t size = 4)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == 0) 
    {
        DWORD error = GetLastError();
        std::string errorMsg = "FAILED WRITE MEMORY: Error code " + std::to_string(error);
        throw std::runtime_error(errorMsg);
    }

    //if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY
    //    || mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_WRITECOPY)

        if (!WriteProcessMemory(hProcess, addr, &value, size, nullptr)) 
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
            disasDebugProc((PVOID)entryPoint);
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



size_t Debugger::breakpointEvent(DWORD tid, ULONG_PTR exceptionAddr)
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
    disasDebugProc((PVOID)exceptionAddr, 1);

    thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
    if (thread != INVALID_HANDLE_VALUE) {
        context.ContextFlags = CONTEXT_ALL;
        GetThreadContext(thread, &context);
        if (it != breakMap.end()) 
            context.Eip = exceptionAddr;

        
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
    printMemory((PVOID)addr);
}


void Debugger::handleDisasCommand(std::istringstream& stream)
{
    DWORD addr = getAddr(stream);
    disasDebugProc((PVOID)addr);
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
        changeMemory((PVOID)addr, value, dataSize[strSize]);
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
    DWORD value;

    // ���� ���������� ���, ������� ��� ��������
    if (stream.peek() == EOF) {
        printRegisters(context);
        return;
    }

    // ������ ��� �������� � ��������
    stream >> regName;
    if (!(stream >> std::hex >> value)) {
        std::cerr << "Invalid value format. Expected hexadecimal value.\n";
        return;
    }

    // ������� ��������� � ������������
    static const std::unordered_map<std::string, std::function<void(CONTEXT&, DWORD)>> regMap = {
        {"eax", [](CONTEXT& ctx, DWORD val) { ctx.Eax = val; }},
        {"ebx", [](CONTEXT& ctx, DWORD val) { ctx.Ebx = val; }},
        {"ecx", [](CONTEXT& ctx, DWORD val) { ctx.Ecx = val; }},
        {"edx", [](CONTEXT& ctx, DWORD val) { ctx.Edx = val; }},
        {"edi", [](CONTEXT& ctx, DWORD val) { ctx.Edi = val; }},
        {"esi", [](CONTEXT& ctx, DWORD val) { ctx.Esi = val; }},
        {"ebp", [](CONTEXT& ctx, DWORD val) { ctx.Ebp = val; }},
        {"esp", [](CONTEXT& ctx, DWORD val) { ctx.Esp = val; }},
        {"eflags", [](CONTEXT& ctx, DWORD val) { ctx.EFlags = val; }},

        // �����������
        {"ax", [](CONTEXT& ctx, DWORD val) { ctx.Eax = (ctx.Eax & 0xFFFF0000) | (val & 0xFFFF); }},
        {"bx", [](CONTEXT& ctx, DWORD val) { ctx.Ebx = (ctx.Ebx & 0xFFFF0000) | (val & 0xFFFF); }},
        {"cx", [](CONTEXT& ctx, DWORD val) { ctx.Ecx = (ctx.Ecx & 0xFFFF0000) | (val & 0xFFFF); }},
        {"dx", [](CONTEXT& ctx, DWORD val) { ctx.Edx = (ctx.Edx & 0xFFFF0000) | (val & 0xFFFF); }},

        {"al", [](CONTEXT& ctx, DWORD val) { ctx.Eax = (ctx.Eax & 0xFFFFFF00) | (val & 0xFF); }},
        {"ah", [](CONTEXT& ctx, DWORD val) { ctx.Eax = (ctx.Eax & 0xFFFF00FF) | ((val & 0xFF) << 8); }},
        {"bl", [](CONTEXT& ctx, DWORD val) { ctx.Ebx = (ctx.Ebx & 0xFFFFFF00) | (val & 0xFF); }},
        {"bh", [](CONTEXT& ctx, DWORD val) { ctx.Ebx = (ctx.Ebx & 0xFFFF00FF) | ((val & 0xFF) << 8); }},
        {"cl", [](CONTEXT& ctx, DWORD val) { ctx.Ecx = (ctx.Ecx & 0xFFFFFF00) | (val & 0xFF); }},
        {"ch", [](CONTEXT& ctx, DWORD val) { ctx.Ecx = (ctx.Ecx & 0xFFFF00FF) | ((val & 0xFF) << 8); }},
        {"dl", [](CONTEXT& ctx, DWORD val) { ctx.Edx = (ctx.Edx & 0xFFFFFF00) | (val & 0xFF); }},
        {"dh", [](CONTEXT& ctx, DWORD val) { ctx.Edx = (ctx.Edx & 0xFFFF00FF) | ((val & 0xFF) << 8); }},
    };

    // ����� � ��������� ��������
    auto it = regMap.find(regName);
    if (it != regMap.end()) {
        it->second(context, value);
        std::cout << "Register " << regName << " updated to 0x" << std::hex << value << std::endl;
    }
    else {
        std::cerr << "Unknown register: " << regName << "\n";
    }
}