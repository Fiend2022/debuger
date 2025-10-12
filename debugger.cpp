#include "debugger.hpp"
#include <iostream>
#include <filesystem>
#include <vector>
#include <iomanip>
#include <stdexcept>
#include <sstream>
#include <functional>
#include <winnt.h>
#include <Windows.h>
#include <psapi.h>
#include <unordered_set>

namespace fs = std::filesystem;

template<typename T>
std::string to_hex(T value)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(sizeof(T) * 2) << value;
    return ss.str();
}

void setDr7Bit(DWORD_PTR& dr7, int index, int rw, int len)
{
    int enableShift = index * 2;      // Lx: 0,2,4,6
    int rwShift = 16 + index * 4;     // RWx
    int lenShift = 18 + index * 4;    // lenx

    dr7 |= (1 << enableShift);           // Lx = 1
    dr7 &= ~(3 << rwShift);              // обнуляем RWx
    dr7 &= ~(3 << lenShift);             // обнуляем lenx
    dr7 |= (rw << rwShift);              // ставим RWx
    dr7 |= (len << lenShift);            // ставим lenx
}



bool Debugger::addHardwareBreakpoint(DWORD_PTR addr, const std::string& typeStr, int size)
{

    int idx = -1;
    for (int i = 0; i < 4; ++i)
    {
        if (!hwBps[i].active)
        {
            idx = i;
            break;
        }
    }
    if (idx == -1)
    {
        //logger.warning("No free hardware breakpoint register (DR0-DR3)");
        return false;
    }

    int rw = 0, len = 0;
    if (typeStr == "write")
        rw = 1;
    else if (typeStr == "access")
        rw = 3;
    
    else
    {
        //logger.warning("Invalid type. Use 'write' or 'access'");
        return false;
    }

    switch (size) {
    case 1: len = 0; break;
    case 2: len = 1; break;
    case 4: len = 3; break;
#ifdef _WIN64
    case 8: len = 2; break;
#else
    //default: logger.warning("Invalid size"); return false;
#endif
    }

    // Устанавливаем адрес
    switch (idx)
    {
    case 0: cont->Dr0 = addr; break;
    case 1: cont->Dr1 = addr; break;
    case 2: cont->Dr2 = addr; break;
    case 3: cont->Dr3 = addr; break;
    }

    setDr7Bit(cont->Dr7, idx, rw, len);

    cont->Dr7 &= ~(1 << 13);



    hwBps[idx] = { true, addr, size };
    std::stringstream ss;
    ss << "HWBP set at DR" << idx << " (0x" << std::hex << addr
        << ") type=" << typeStr << ", size=" << size;
    //logger.info(ss.str());
    return true;
}

int Debugger::getHardwareBreakpointIndexFromDr6(DWORD dr6)
{
    for (int i = 0; i < 4; ++i)
        if (dr6 & (1 << i)) return i;
    return -1;
}


bool Debugger::createDebugProc(const std::string& prog)
{
    if (!fs::exists(prog)) 
    {
        //logger.error(std::string("Executable file not found: ")  + prog);
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
        state = DebugState::RUN;
    }
    else
        //logger.error(std::string("Failed to create process: ") + std::to_string(GetLastError()));
    return ret;
    
}


void Debugger::run()
{
    bool ready = false;
    std::string prog;
    while(!ready)
        if (!commandQueue.empty())
        {
            prog = waitForCommand();
            ready = true;
        }
    //logger.init(prog);
    if (createDebugProc(prog))
    {
        DebugEvent de;
        debugRun();
        de.type = DebugEvent::ProcessExit;
        notify(de);
    }
    //logger.close();
}

size_t Debugger::disasDebugProc(DWORD_PTR addr, std::ostream& stream, size_t instCount)
{
    size_t size = 15 * instCount;
    std::vector<BYTE> buf(size);
    size_t offset = 0;

    if (!ReadProcessMemory(hProcess, (LPCVOID)addr, buf.data(), size, NULL))
    {
        std::stringstream ss;
        ss << "Failed to read memory: " << GetLastError() << " on address: " << addr;
        //logger.error(ss.str());
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
        stream << std::hex << (DWORD_PTR)addr + offset << ": " << hexBuf << " " << asmBuf << std::endl;
        offset += len;
    }

    return offset;
}

void Debugger::setBreakPoint(DWORD_PTR addr, bool temp = false)
{
    auto it = breakMap.find(addr);
    if (it == breakMap.end())
    {
        BYTE saveByte;
        ReadProcessMemory(hProcess, (PVOID)addr, &saveByte, 1, NULL);
        WriteProcessMemory(hProcess, (PVOID)addr, "\xCC", 1, NULL);
        breakMap[addr] = { BreakState::enable, saveByte, temp, addr };
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
        std::stringstream ss;
        ss << "No breakpoint found at 0x" << std::hex << addr;
        //logger.warning(ss.str());
    }

}

void Debugger::printRegisters(const CONTEXT& context, std::ostream& output)
{
    output << std::hex << std::setfill('0');

#ifdef _WIN64
    // 64-битные регистры
    output
        << "rax = " << std::setw(16) << context.Rax << " "
        << "rbx = " << std::setw(16) << context.Rbx << " "
        << "rcx = " << std::setw(16) << context.Rcx << " "
        << "rdx = " << std::setw(16) << context.Rdx << "\n"
        << "rsi = " << std::setw(16) << context.Rsi << " "
        << "rdi = " << std::setw(16) << context.Rdi << " "
        << "rbp = " << std::setw(16) << context.Rbp << " "
        << "rsp = " << std::setw(16) << context.Rsp << "\n"
        << "rip = " << std::setw(16) << context.Rip << " "
        << "rflags = " << std::setw(16) << context.EFlags << "\n";
#else
    // 32-битные регистры
    output
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

void Debugger::printMemory(DWORD_PTR addr, std::ostream& stream, size_t size=128)
{
    try 
    {
        auto buff = getDumpMemory(addr, size);
        for (size_t i = 0; i < buff.size(); i += lineSize)
        {
            stream << std::hex << std::setw(8) << std::setfill('0')
                << static_cast<uintptr_t>(addr) << ": ";
            for (size_t j = 0; j < lineSize; ++j) 
            {
                if (i + j < size) 
                    stream << std::hex << std::setw(2) << std::setfill('0')
                        << static_cast<int>(buff[i + j]) << " ";
                
                else
                    stream << "   ";
                
            }
            stream << "| ";

            for (size_t j = 0; j < lineSize; ++j)
            {
                if (i + j < size)
                {
                    char c = static_cast<char>(buff[i + j]);
                    if (c >= ' ' && c <= '~')
                        stream << c;
         
                    else
                        stream << "."; 
                }
                else 
                    stream << " ";
            }

            stream << std::endl;
            addr = (static_cast<uintptr_t>(addr) + lineSize);
        }

    }
    catch (const std::exception& e) 
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void Debugger::changeMemory(DWORD_PTR addr, void* value, size_t size)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, (PVOID)addr, &mbi, sizeof(mbi)) == 0) 
    {
        DWORD error = GetLastError();
        std::string errorMsg = "FAILED WRITE MEMORY: Error code " + std::to_string(error);
        throw std::runtime_error(errorMsg);
    }

    bool isWritable = false;
    switch (mbi.Protect)
    {
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
            isWritable = true;
            break;
        default:
            isWritable = false;
    }

    if (!isWritable)
        throw std::runtime_error("Cannot write to address 0x" + to_hex(addr) +
            ": protection = 0x" + to_hex(mbi.Protect));


    if (!WriteProcessMemory(hProcess, (PVOID)addr, value, size, nullptr)) 
    {
        DWORD error = GetLastError();
        std::string errorMsg = "FAILED WRITE MEMORY: Error code " + std::to_string(error);
        throw std::runtime_error(errorMsg);
    }
}


void Debugger::debugRun()
{
    
    while (active) 
    {
        DEBUG_EVENT debugEvent;
        DWORD continueFlag = DBG_CONTINUE;
        static LPTHREAD_START_ROUTINE entryPoint;
        if (!WaitForDebugEvent(&debugEvent, INFINITE))
            break;
        static std::vector<DisasmLine> sourceCode;
        static std::vector<DataSection> sections;
       

        switch (debugEvent.dwDebugEventCode)
        {
            case CREATE_THREAD_DEBUG_EVENT:
                handleCreateThread(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.CreateThread);
                break;
            case EXIT_THREAD_DEBUG_EVENT:
                handleExitThread(debugEvent.dwProcessId, debugEvent.dwThreadId, debugEvent.u.ExitProcess.dwExitCode);
                break;

            case CREATE_PROCESS_DEBUG_EVENT:
            {
                DebugEvent de;
                std::stringstream ss;
                ss << "Process created: " << std::hex << debugEvent.dwProcessId;
                std::cout << ss.str() << std::endl;

                de.message = ss.str();

                mainThreadId = debugEvent.dwThreadId;
                handleCreateThread(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.CreateThread);
            
                exeBaseAddress = (DWORD_PTR)debugEvent.u.CreateProcessInfo.lpBaseOfImage;
                handleLoadExe(exeBaseAddress, "main.exe", (DWORD_PTR)debugEvent.u.CreateProcessInfo.lpStartAddress);
            
                entryPoint = debugEvent.u.CreateProcessInfo.lpStartAddress;
                DWORD_PTR entryAddr = reinterpret_cast<DWORD_PTR>(entryPoint);
                disasDebugProc(entryAddr, std::cout);


                initComands();

                std::tie(sourceCode, sections) = getSections();

                setBreakPoint(entryAddr);

                auto it = std::find_if(sourceCode.begin(), sourceCode.end(),
                    [entryAddr](const DisasmLine& line)
                    { return line.address == entryAddr; }
                );
                it->hasBreakpoint = true;
                de.address = (DWORD_PTR)entryPoint;
                de.disasmCode = sourceCode;
                de.data = sections;
                de.type = DebugEvent::CreateProc;

                CONTEXT context;
                context.ContextFlags = CONTEXT_ALL;
                HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, debugEvent.dwThreadId);
                GetThreadContext(thread, &context);
                cont = &context;

                de.stackData = getStack(64);
                de.prog = prog->getName();
                notify(de);
                CloseHandle(thread);
                break;
            }

            case EXIT_PROCESS_DEBUG_EVENT:
            {
                std::stringstream ss;
                ss << "Process exited: " << debugEvent.dwProcessId << std::endl;
                DebugEvent de;
                de.message = ss.str();
                de.type = DebugEvent::ProcessExit;
                notify(de);
                active = false;
                break;
            }

            case LOAD_DLL_DEBUG_EVENT:
            {
                handleLoadDLL(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.LoadDll);
                //parseCode(&sourceCode);

                //de.address = (DWORD_PTR)entryPoint;
                //de.disasmCode = sourceCode;
                //de.type = DebugEvent::ModuleLoad;
                
                break;
            }

            case UNLOAD_DLL_DEBUG_EVENT:
                handleUnloadDLL(debugEvent.dwProcessId, debugEvent.dwThreadId, reinterpret_cast<DWORD_PTR>(debugEvent.u.UnloadDll.lpBaseOfDll));

                break;

            case OUTPUT_DEBUG_STRING_EVENT:
            {
                DebugEvent de;
                de.message = std::string(std::string("Debug string: ") + std::string(debugEvent.u.DebugString.lpDebugStringData));
                de.type = DebugEvent::DbgStr;
                notify(de);
                break;
            }

            case EXCEPTION_DEBUG_EVENT:

                continueFlag = eventException(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.Exception);
                break;

            default:
            {
                DebugEvent de;
                de.message = std::string("Unexpected debug event:" + std::to_string(debugEvent.dwDebugEventCode));
                break;
            }
        }

        if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueFlag))
        {
            std::stringstream ss;
            ss << "Error continuing debug event" << std::endl;
            DebugEvent de;
            de.message = ss.str();
        }

        else
        {
            auto it = std::find_if(breakMap.begin(), breakMap.end(), [](const auto& pair)
                {
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

size_t Debugger::breakpointEvent(DWORD tid, DWORD_PTR exceptionAddr, DebugEvent* de)
{
    CONTEXT context;
    HANDLE thread;
    auto it = breakMap.find(exceptionAddr);

    if (it == breakMap.end() && state != RUN && state != STEP)
        return DBG_EXCEPTION_NOT_HANDLED;
    
    

    thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);


    if (thread == INVALID_HANDLE_VALUE) return DBG_EXCEPTION_NOT_HANDLED;

    context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(thread, &context);

    if (it != breakMap.end())
    {

        WriteProcessMemory(hProcess, (PVOID)exceptionAddr, &it->second.saveByte, 1, NULL);
        it->second.state = BreakState::disable;

    }
    else if (it == breakMap.end() && state == DebugState::RUN)
    {
        context.EFlags |= 0x100;
        SetThreadContext(thread, &context);
        CloseHandle(thread);
        return DBG_CONTINUE;
    }
    std::stringstream ss;
    disasDebugProc(exceptionAddr, ss, 1);
    de->message = ss.str();
    if (it != breakMap.end())
    {
        if (it->second.temp)
            deleteBreakPoint(it->first);
    }

    this->cont = &context;
    setIP(exceptionAddr);
    de->context = *cont;
    de->address = exceptionAddr;
    de->stackData = getStack(64);
    notify(*de);

    userRun();


    if (state != RUN)
        context.EFlags |= 0x100;
    else
        context.EFlags &= ~0x100;



    SetThreadContext(thread, &context);
    CloseHandle(thread);


    return DBG_CONTINUE;
}

void Debugger::userRun()
{
    state = STOP;

    while (state == STOP)
    {
        if (!commandQueue.empty())
        {
            std::string cmd = waitForCommand();
            if (!cmd.empty())
            {
                commandLine(cmd);

            }
        }
    }
}

std::string Debugger::waitForCommand()
{
    std::unique_lock<std::mutex> lock(cmdMutex);
    cmdCV.wait(lock, [this] { return !commandQueue.empty(); });
    std::string cmd = commandQueue.front();
    commandQueue.pop();
    return cmd;
}

size_t Debugger::eventException(DWORD pid, DWORD tid, LPEXCEPTION_DEBUG_INFO exc)
{
    DebugEvent de;
    CONTEXT ctx;
    HANDLE thread;

    thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);


    if (thread == INVALID_HANDLE_VALUE) return DBG_EXCEPTION_NOT_HANDLED;
    ctx.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(thread, &ctx)) return DBG_EXCEPTION_NOT_HANDLED;
    cont = &ctx;
    if (getIP() >= startTrace && getIP() <= endTrace && (state != TRACING && state != TRACE_RUN))
        state = TRACING;
    
    switch (exc->ExceptionRecord.ExceptionCode)
    {
        case EXCEPTION_BREAKPOINT:
            if (state == TRACING || state == TRACE_RUN)
            {
                disableBreakPoint((DWORD_PTR)exc->ExceptionRecord.ExceptionAddress);
                setIP((DWORD_PTR)exc->ExceptionRecord.ExceptionAddress);
                auto ret = traceRangeEvent(tid, (DWORD_PTR)exc->ExceptionRecord.ExceptionAddress, &de);
                SetThreadContext(thread, &ctx);
                CloseHandle(thread);
                return ret;
            }
            de.type = DebugEvent::BreakpointEvent;
            return breakpointEvent(tid, (DWORD_PTR)exc->ExceptionRecord.ExceptionAddress, &de);

        case EXCEPTION_SINGLE_STEP:
        {

            if (state == TRACING || state == TRACE_RUN)
            {
                disableBreakPoint((DWORD_PTR)exc->ExceptionRecord.ExceptionAddress);
                setIP((DWORD_PTR)exc->ExceptionRecord.ExceptionAddress);
                auto ret = traceRangeEvent(tid, (DWORD_PTR)exc->ExceptionRecord.ExceptionAddress, &de);
                SetThreadContext(thread, &ctx);
                CloseHandle(thread);
                return ret;
            }
            int drIndex = getHardwareBreakpointIndexFromDr6(ctx.Dr6);
            if (drIndex != -1 && hwBps[drIndex].active)
            {
                DWORD_PTR addr = 0;
                switch (drIndex)
                {
                case 0: addr = ctx.Dr0; break;
                case 1: addr = ctx.Dr1; break;
                case 2: addr = ctx.Dr2; break;
                case 3: addr = ctx.Dr3; break;
                }
                std::stringstream ss;
                ss << "[HWBP] Triggered at 0x" << std::hex << addr << " (DR" << drIndex << ")";

                std::cout << ss.str() << std::endl;
                state = STEP;
                DWORD_PTR currIp = getIP();
            


                de.type = DebugEvent::HardwareBreak;
                de.address = (DWORD_PTR)exc->ExceptionRecord.ExceptionAddress;
                de.message = ss.str();
                notify(de);
                size_t contFlag = breakpointEvent(tid, currIp, &de);
                return contFlag;
            }
        }
        de.type = DebugEvent::Step;
        de.address = (DWORD_PTR)exc->ExceptionRecord.ExceptionAddress;

        return breakpointEvent(tid, (DWORD_PTR)exc->ExceptionRecord.ExceptionAddress, &de);

    default:
        return DBG_EXCEPTION_NOT_HANDLED;
    }
    return DBG_EXCEPTION_NOT_HANDLED;
}


void Debugger::commandLine(const std::string& command)
{
   
    std::istringstream iss(command);
    std::string cmd;
    iss >> cmd;

    auto it = std::find_if(commands.begin(), commands.end(), [cmd](CommandInfo elem) {return elem.name == cmd; });
   
    if (it != commands.end())
    {
        std::string output = it->handler(*this, iss);
        auto type = it->type;
        DebugEvent de;

        de.address = getIP();
        de.context = *cont;
        de.type = type;
        de.message = output;
        de.stackData = getStack(64);
        std::tie(de.disasmCode, de.data) = getSections();
        notify(de);
    }
    


}



DWORD_PTR getAddr(std::istringstream& stream)
{
    std::string addrStr;
    stream >> addrStr;

    if (addrStr.empty())
        return 0;
    

    // Обрабатываем префикс 0x, если он есть
    if (addrStr.size() > 2 && addrStr[0] == '0' && (addrStr[1] == 'x' || addrStr[1] == 'X')) {
        addrStr = addrStr.substr(2);
    }

    try {
        size_t pos;
        uint64_t addr = std::stoull(addrStr, &pos, 16);

        if (pos != addrStr.size()) {
            std::cerr << "Invalid address format: " << addrStr << "\n";
            return 0;
        }

        return static_cast<DWORD_PTR>(addr);
    }
    catch (...) {
        //std::cerr << "Invalid address format: " << addrStr << "\n";
        return 0;
    }
}


std::vector<Debugger::ExportedSymbol> Debugger::loadSyms(const std::vector<std::pair<std::string, DWORD_PTR>>& expSyms)
{
    std::vector<ExportedSymbol> syms;
    for (auto& sym : expSyms)
    {
        syms.push_back({ sym.first, sym.second });
        fullExport.push_back({ sym.first, sym.second });
    }
    return syms;
}

void Debugger::handleBpCommand(std::istringstream& stream)
{
    std::string arg;
    stream >> arg;
    DWORD_PTR addr = getArgAddr(arg);
    setBreakPoint(addr);
}

void Debugger::handleDelCommand(std::istringstream& stream)
{
    std::string arg;
    stream >> arg;
    DWORD_PTR addr = getArgAddr(arg);
    deleteBreakPoint(addr);
}
 
//void Debugger::handleDumpCommand(std::istringstream& stream)
//{
//    std::string arg;
//    stream >> arg;
//    DWORD_PTR addr = getArgAddr(arg);
//    printMemory(addr);
//}




void Debugger::handleRegCommand(std::istringstream& input, std::ostream& output, CONTEXT& context)
{
    std::string regName;
    DWORD_PTR value;  

    if (input.peek() == EOF) {
        printRegisters(context, output);
        return;
    }

    // Читаем имя регистра и значение
    input >> regName;
    if (!(input >> std::hex >> value)) {
        output << "Invalid value format. Expected hexadecimal value.\n";
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
    if (it != regMap.end())
    {
        it->second(context, value);
        output << "Register " << regName << " updated to 0x" << std::hex << value << std::endl;
    }
    else
    {
        output << "Unknown register: " << regName << "\n";
    }
}

void Debugger::handleExitThread(DWORD pid, DWORD tid, DWORD exitCode)
{
    auto it = threads.find(tid);
    if (it != threads.end())
    {
        CloseHandle(it->second.hThread);
        std::stringstream ss;
        ss << "[-] Thread exited: TID=" << std::dec << tid
            << ", ExitCode=" << exitCode;
        std::cout<< ss.str() << std::endl;
        threads.erase(it);
        DebugEvent ev;
        ev.message = ss.str();
        ev.type = DebugEvent::ExitThread;
        notify(ev);
    }
}

void Debugger::handleUnloadDLL(DWORD pid, DWORD tid, DWORD_PTR addr)
{
    auto it = modules.begin();
    while (it != modules.end())
    {
        if (it->second.baseAddress == addr)
            break;
        it++;
    }
    if (it != modules.end())
    {

        std::stringstream ss;
        ss << "[-] DLL unloaded: " << it->first
            << " @ 0x" << std::hex << addr << std::endl;
        modules.erase(it);
        DebugEvent ev;
        ev.message = ss.str();
        ev.type = DebugEvent::ModuleUnload;
        notify(ev);
       
    }
    else
    {
        std::stringstream ss;
        ss << "[-] Unknown module unloaded @ 0x" << std::hex << addr << std::endl;
        DebugEvent ev;
        ev.message = ss.str();
        ev.type = DebugEvent::DbgWarning;
        notify(ev);
    }
}


void Debugger::handleCreateThread(DWORD pid, DWORD tid, CREATE_THREAD_DEBUG_INFO* info)
{
    DWORD_PTR addres = (DWORD_PTR)info->lpStartAddress;
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    threads[tid] = { tid, hThread, true };

    std::stringstream ss;
    ss << "[+] Thread created: TID=" << std::dec << tid
        << " @ 0x" << std::hex << (DWORD_PTR)info->lpStartAddress << std::endl;
    DebugEvent ev;
    ev.message = ss.str();
    ev.type = DebugEvent::CreateThread;
    notify(ev);
}
void Debugger::handleLoadDLL(DWORD pid, DWORD tid, LOAD_DLL_DEBUG_INFO* info)
{
    char moduleName[MAX_PATH] = { 0 };
    DWORD_PTR baseAddr = (DWORD_PTR)info->lpBaseOfDll;

    HANDLE hFile = info->hFile;
    if (hFile != INVALID_HANDLE_VALUE && hFile != NULL)
    {
        DWORD len = GetFinalPathNameByHandleA(hFile, moduleName, MAX_PATH, FILE_NAME_NORMALIZED);
        if (len > 0 && len < MAX_PATH)
        {
            char* nameStart = strstr(moduleName, "\\");
            if (nameStart)
            {
                char* lastSlash = strrchr(nameStart, '\\');
                if (lastSlash)
                    strcpy_s(moduleName, lastSlash + 1);
            }
        }
    }

    if (!moduleName[0])
        sprintf_s(moduleName, "module_%p.dll", baseAddr);

    PeHeader lib(baseAddr, hProcess);
    std::vector<ExportedSymbol> syms = loadSyms(lib.getExportedSymbols());
    MODULEINFO modInfo = { 0 };
    size_t size;

    if (GetModuleInformation(hProcess, (HMODULE)baseAddr, &modInfo, sizeof(modInfo)))
        size = modInfo.SizeOfImage;
    else
        size = 0x1000;


    modules[std::string(moduleName)] = {
        baseAddr,
        size,
        syms
    };
    std::stringstream ss;
    ss << "[+] DLL loaded: " << moduleName << " @ 0x" << std::hex << baseAddr;
    DebugEvent ev;
    ev.message = ss.str();
    ev.type = DebugEvent::ModuleLoad;
    notify(ev);
    std::cout << ss.str() << std::endl;
}


void Debugger::handleModulesCommand(std::ostream& ss)
{
    ss << "\nLoaded modules ("<< std::dec << modules.size() << "):" << std::endl;
    ss << std::setw(18) << "Address" << " | " << std::setw(12) << "Size" << " | Name" << std::endl;
    ss << std::string(50, '-') << std::endl;

    for (const auto& [name, mod] : modules)
    {
       ss << "0x" << std::hex << std::setw(16) << std::setfill('0') << mod.baseAddress
            << " | " << std::dec << std::setw(10) << mod.size
            << " | " << name << std::endl;
    }
    ss << std::endl;
}



void Debugger::handleThreadsCommand(std::ostream& ss)
{
    ss << "\nActive threads (" << threads.size() << "):" << std::endl;
    ss << std::setw(8) << "TID" << " | " << std::setw(16) << "Handle" << " | Status" << std::endl;
    ss << std::string(40, '-') << std::endl;

    for (const auto& [tid, thread] : threads)
    {
       ss << std::dec << std::setw(8) << tid
            << " | 0x" << std::hex << std::setw(14) << std::setfill('0')
            << reinterpret_cast<uintptr_t>(thread.hThread)
            << " | " << (thread.isRunning ? "Running" : "Stopped") << std::endl;
    }
   ss << std::endl;
}

void Debugger::handleLoadExe(DWORD_PTR baseAddr, const std::string& name, DWORD_PTR entryPoint)
{
    std::stringstream ss;
    try {
        PeHeader pe(baseAddr, hProcess);
        prog = new PeHeader(pe);
        ss << "EXE Base: 0x" << std::hex << baseAddr << std::endl;;
        std::cout << ss.str()  << std::endl;
        if (pe.hasExports())
        {
            std::vector<ExportedSymbol> syms = loadSyms(pe.getExportedSymbols());
            modules[name] = { baseAddr, 0x1000, syms };
            ss << "Found " << syms.size() << " exports in EXE" << std::endl;;
        }
    }
    catch (const std::exception& e)
    {
        ss << "Failed to read EXE headers: " << e.what();
        DebugEvent ev;
        ev.message = ss.str();
        ev.type = DebugEvent::DbgError;
        notify(ev);
        return;
    }

    ss << "[+] EXE loaded: " << name << " @ 0x" << std::hex << baseAddr
        << ", Entry: 0x" << entryPoint << std::endl;;
    std::cout << ss.str() << std::endl;
    DebugEvent ev;
    ev.message = ss.str();
    ev.type = DebugEvent::ModuleLoad;
    notify(ev);
}


void Debugger::handleSymbolsCommand()
{
    for (auto& [name, mod] : modules)
    {
        std::cout << "\n" << name << ":\n";
        std::cout << std::string(60, '-') << std::endl;

        for (const auto& [symbol, addr] : mod.symbols)
            std::cout << "  " << std::setw(40) << std::left << symbol
                << " = 0x" << std::hex << addr << std::endl;
    }
}



bool Debugger::parseSymbols(const std::string& arg, std::string& dll, std::string& symbol)
{
    auto pos = arg.find('!');
    if (pos != std::string::npos)
    {
        dll = arg.substr(0, pos);
        symbol = arg.substr(pos+1);
    }
    else
    {
        symbol = arg;
        return false;
    }

}

DWORD_PTR Debugger::getArgAddr(const std::string& arg)
{
    try
    {
        auto stream = std::istringstream(arg);
        DWORD_PTR addr = getAddr(stream);
        
        if (addr != 0)
            return addr;

    }
    catch (...){}
    if (isRegisterString(arg))
    {
        std::string regName = arg.substr(1);
        return (DWORD_PTR)getRegisterValue(regName);
    }
    std::string dll, symbol;
    if (parseSymbols(arg, dll, symbol))
    {
        for (auto& func : modules[dll + ".dll"].symbols)
            if (func.name == symbol)
                return func.address;
    }
    else
    {
        for (auto& func : fullExport)
            if (func.name == symbol)
                return func.address;
    }
    return 0;
}


Debugger::CommandArgs Debugger::parseArgs(std::istringstream& stream)
{
    CommandArgs args;
    if (!(stream >> args.addressArg))
    {
        args.valid = false;
        return args;
    }

    if (args.addressArg == "-h" || args.addressArg == "--help")
    {
        args.helpRequested = true;
        return args;
    }

    args.address = getArgAddr(args.addressArg);
    if (!args.address)
    {
        args.valid = false;
        return args;
    }

    std::string token;
    while (stream >> token)
    {
        if (token == "-n" || token == "--number")
            if (!(stream >> args.count) || args.count <= 0)
                args.valid = false;
            
        

        if (token == "-t" || token == "--type")
            if (!(stream >> args.type))
                args.valid = false;
            
        
        if (token == "-v" || token == "--value")
            if (!(stream >> args.value))
                args.valid = false;
            

    }
    return args;
}

void Debugger::initComands()
{
    commands =
    {
        {"disas",
         "disas <addr> [-n <count>]",
        [](Debugger& dbg, std::istringstream& stream) -> std::string
            {
                CommandArgs args = dbg.parseArgs(stream);
                if (!args.valid) return std::string("disas <addr> [-n <count>]");

                if (args.helpRequested)
                {
                    std::cout << "Use: disas <addr> [-n <count>]" << std::endl;
                    return std::string("disas <addr> [-n <count>]");
                }

                DWORD_PTR addr = dbg.getArgAddr(args.addressArg);
                if (!addr)
                {
                    std::cerr << "Invalid address: " << args.addressArg << "\n";
                    return std::string("disas <addr> [-n <count>]");
                }

                std::stringstream ss;
                dbg.disasDebugProc(addr, ss, args.count);
                return ss.str();
            },
             DebugEvent::Type::DisasmCode
        },

        {
            "bp",
            "bp <address>",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
            {
                std::vector<std::string> types = { "hw", "hww", "hwr"};
                CommandArgs args = dbg.parseArgs(stream);
                if (!args.valid) return std::string("Use: bp <address>");
                if (args.helpRequested)
                {
                    std::cout << "Use: bp <address>" << std::endl;
                    return std::string("Use: bp <address>");
                }
                dbg.setBreakPoint(args.address);
                return std::string("");
            },
             DebugEvent::Type::BreakpointSetup
        },

        {
            "dump",
            "dump <addr|symbol|reg> [-n <count>] [-t <byte|word|dword]",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
                {
                    std::vector<std::string> types = { "byte", "word", "dword"};
                    CommandArgs args = dbg.parseArgs(stream);
                    if (!args.valid) return  std::string("Use : dump <addr|symbol|reg> [-n <count>] [-t <byte|word|dword]");

                    if (args.helpRequested)
                        return std::string("Use : dump <addr|symbol|reg> [-n <count>] [-t <byte|word|dword]");
                    

                    std::stringstream ss;
                    dbg.printMemory(args.address, ss, args.count);
                    return ss.str();
                },
            DebugEvent::Type::Dump

        },

        {
            "edit",
            "edit <addr|symbol|reg> [-t <byte|word|dword|string>] -v <value>",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
                {
                    std::vector<std::string> types = { "byte", "word", "dword", "string"};
                    CommandArgs args = dbg.parseArgs(stream);
                    if (!args.valid) return std::string("Use: edit <addr|symbol|reg> [-t <byte|word|dword|string>] -v <value>");

                    if (args.helpRequested)
                    {
                       return  std::string("Use: edit <addr|symbol|reg> [-t <byte|word|dword|string>] -v <value>");
                    }

                    std::vector<BYTE> data(args.value.begin(), args.value.end());

                    auto it = dbg.dataSize.find(args.type);
                    if (it != dbg.dataSize.end())
                    {
                        uint64_t hexNum;
                        std::istringstream(args.value) >> std::hex >> hexNum;
                        dbg.changeMemory(args.address, &hexNum, dbg.dataSize[args.type]);
                    }
                    
                    else if (args.type == "str" && it == dbg.dataSize.end())
                    {
                        data.push_back('\0');
                        dbg.changeMemory(args.address, data.data(), data.size());
                    }
                    else
                    {
                        std::stringstream ss;
                        ss << "Error: incorrect data type\n"
                            << "Use: edit <addr|symbol|reg> [-t <byte|word|dword|string>] -v <value>\n" << std::endl;
                        return ss.str();
                    }

                    return " ";

                },
                 DebugEvent::Type::Nope
        },

        { 
            "del",
            "del <address|symbol|reg>",    
            [](Debugger& dbg, std::istringstream& stream) -> std::string
                {
                    CommandArgs args = dbg.parseArgs(stream);
                    if (!args.valid) return std::string("Use: del <address|symbol|reg>");

                    if (args.helpRequested)
                    
                        return std::string("Use: del <address|symbol|reg>");
                        
                    

                    dbg.deleteBreakPoint(args.address);
                    return std::string("");

                },
            DebugEvent::Type::Nope
        },

        {
            "reg",
            "reg <reg> <value>",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
                {
                    std::stringstream ss;
                    dbg.handleRegCommand(stream, ss, *dbg.cont);
                    return ss.str();
                },
                 DebugEvent::Type::Reg

        },

        {
            "run",
            "run",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
                {
                    dbg.state = DebugState::RUN;
                    return std::string("");
                },
                 DebugEvent::Type::Run

        },

        {
            "g",
                "g",
                [](Debugger& dbg, std::istringstream& stream) -> std::string
                {
                    dbg.state = DebugState::STEP;
                    return std::string("");
                },
                 DebugEvent::Type::Step
        },

        {
            "modules",
            "modules",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
                {
                    std::stringstream ss;
                    dbg.handleModulesCommand(ss);
                    return ss.str();
                },
                 DebugEvent::Type::ModList

        },

        {
            "threads",
            "threads",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
                {
                    std::stringstream ss;
                    dbg.handleThreadsCommand(ss);
                    return ss.str();
                },
                 DebugEvent::Type::ThreadList

        },

        {
            "symbols",
            "symbols",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
            {
                    dbg.handleSymbolsCommand();
                    return std::string("");
            },
             DebugEvent::Type::Nope
        },

        {
            "bplist",
            "bplist",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
                {
                    std::stringstream ss;
                    size_t n = 0;
                    for (auto& [addr, bp] : dbg.breakMap)
                    {
                        if (!bp.temp)
                        {
                            ss << n << ") " << ": ";
                            dbg.disasDebugProc(addr, ss, 1);
                            n++;
                        }
                    }
                    return ss.str();
                },
                 DebugEvent::Type::BreakList

        },

        {
            "hwbp",
            "",
            [](Debugger& dbg, std::istringstream& stream)-> std::string
            {
                std::string addrStr, t, typeStr;
                int size = 1;

                stream >> addrStr >> t >> typeStr;
                if (t != "-t") {
                    return "Usage: hwbp <addr> -t <write|access|exec> [-n <size>]\n";

                }

                if (stream >> t >> size) {
                    if (t != "-n") {
                        return "Expected -n\n";

                    }
                }

                DWORD_PTR addr = dbg.getArgAddr(addrStr);
                if (!addr) return "";
                dbg.addHardwareBreakpoint(addr, typeStr, size);
                return "";
            },
            DebugEvent::Type::BreakpointSetup
        },
        {
            "hwbplist",
            "hwbplist",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
            {
                std::stringstream ss;
                for (size_t i = 0; i < 4; i++)
                    ss << "address: " << dbg.hwBps[i].address << "bytes:" << dbg.hwBps[i].size;
                return ss.str();
            },
            DebugEvent::Type::HwBreakList
        },
        {
            "load",
            "load <programm",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
            {
                std::string prog;
                stream >> prog;

                dbg.createDebugProc(prog);
                return "";
            },
            DebugEvent::Type::CreateProc
        },
        {
            "stop",
            "stop",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
            {
                    dbg.active = false;
                    return "";
            },
            DebugEvent::Type::ProcessExit
        },
        {
            "n",
            "n",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
            {
                dbg.handleStepOut();
                return "";
            },
            DebugEvent::Type::StepOut
        },
        {
            "p",
            "p",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
            {
                dbg.handleStepOver();
                return "";
            },
            DebugEvent::Type::StepOver
        },
        {
            "trace",
            "trace <start> <end>",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
            {
                    std::string startStr, endStr;
                    if (!(stream >> startStr >> endStr))
    
                        return "Usage: trace <start> <end>";
                    
                    DWORD_PTR start = dbg.getArgAddr(startStr);
                    DWORD_PTR end = dbg.getArgAddr(endStr);
                    if (!start || !end)            
                        return "Usage: trace <start> <end>";
                    
                    if (start > end)
                    {
                        return "Error: start > end!\nUsage: trace <start> <end>";
                    }
                    dbg.startTrace = start;
                    dbg.endTrace = end;
                    //dbg.logger.startTrace(start, end);
                    if (dbg.getIP() >= start && dbg.getIP() <= end)
                    {
                        dbg.state = dbg.DebugState::TRACING;
                    }
                    else
                    {
                        dbg.setBreakPoint(start, true);
                        dbg.setBreakPoint(end, true);
                    }
                    return "";
            },
            DebugEvent::Type::SetupTrace
        }

    };
}




bool Debugger::isRegisterString(const std::string& str)
{
    if (str.empty() || str[0] != '$') return false;

    std::string regName = str.substr(1);  

    static const std::unordered_set<std::string> registers =
    {
        // x86
        "eip", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags",
        // x64
        "rip", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rflags",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    };

    return registers.find(regName) != registers.end();
}


DWORD_PTR Debugger::getRegisterValue(const std::string& regName)
{

#ifdef _WIN64
    if (regName == "rax") return cont->Rax;
    if (regName == "rbx") return cont->Rbx;
    if (regName == "rcx") return cont->Rcx;
    if (regName == "rdx") return cont->Rdx;
    if (regName == "rsi") return cont->Rsi;
    if (regName == "rdi") return cont->Rdi;
    if (regName == "rbp") return cont->Rbp;
    if (regName == "rsp") return cont->Rsp;
    if (regName == "rip") return cont->Rip;
    if (regName == "r8")  return cont->R8;
    if (regName == "r9")  return cont->R9;
    if (regName == "r10") return cont->R10;
    if (regName == "r11") return cont->R11;
    if (regName == "r12") return cont->R12;
    if (regName == "r13") return cont->R13;
    if (regName == "r14") return cont->R14;
    if (regName == "r15") return cont->R15;
#else
    if (regName == "eax") return cont->Eax;
    if (regName == "ebx") return cont->Ebx;
    if (regName == "ecx") return cont->Ecx;
    if (regName == "edx") return cont->Edx;
    if (regName == "esi") return cont->Esi;
    if (regName == "edi") return cont->Edi;
    if (regName == "ebp") return cont->Ebp;
    if (regName == "esp") return cont->Esp;
    if (regName == "eip") return cont->Eip;
#endif

}

std::vector<DisasmLine> Debugger::disasSection(IMAGE_SECTION_HEADER* sec)
{
    DWORD_PTR addr = sec->VirtualAddress + exeBaseAddress;
    std::vector<DisasmLine> text;
    while (addr  - exeBaseAddress < sec->VirtualAddress + sec->Misc.VirtualSize)
    {   
        std::vector<uint8_t> buf(16);
        std::string asmBuf(128, '\0');
        std::string hexBuf(128, '\0');
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProcess, (LPCVOID)addr, buf.data(), 16, &bytesRead) || bytesRead == 0)
        {
            break;
        }
        size_t len = disas.DisasInst(buf.data(), bytesRead, addr, asmBuf, hexBuf);
        text.push_back({ addr, hexBuf, asmBuf });
        addr += len;
    }
    return text;
}

std::pair<std::vector<DisasmLine>, std::vector<DataSection>> Debugger::getSections()
{
    std::vector<DisasmLine> codeSections;
    std::vector<DataSection> dataSections;

    auto secs = prog->getSections();
    for (auto sec : secs)
    {
        if ((sec.Characteristics & IMAGE_SCN_CNT_CODE) && (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE))
        {
            auto disasCode = disasSection(&sec);
            std::copy(disasCode.begin(), disasCode.end(), std::back_inserter(codeSections));
        }
        else if ((sec.Characteristics & (IMAGE_SCN_CNT_INITIALIZED_DATA |
            IMAGE_SCN_CNT_UNINITIALIZED_DATA)) &&
           !(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE))
        {
            auto dataSec = getDataSection(&sec);
            dataSections.push_back({ std::string((const char*)sec.Name), dataSec });
        }
    }
    return { codeSections, dataSections };
}
std::vector<DataLine> Debugger::getDataSection(IMAGE_SECTION_HEADER* sec)
{
    DWORD_PTR addr = sec->VirtualAddress + exeBaseAddress;
    std::vector<DataLine> text;

    while (addr < sec->VirtualAddress + exeBaseAddress + sec->Misc.VirtualSize)
    {
        std::vector<BYTE> buf(16);
        SIZE_T bytesRead;

        if (!ReadProcessMemory(hProcess, (LPCVOID)addr, buf.data(), 16, &bytesRead)
            || bytesRead == 0)
            break;
        



        std::string ascii;
        for (SIZE_T i = 0; i < bytesRead; ++i)
        {
            char c = buf[i];
            ascii += (c >= 32 && c < 127) ? c : '.';
        }

        DataLine tmp = { addr, buf, ascii };
        text.push_back(tmp);
        addr += 16;
    }
    return text;
}

std::string Debugger::resolveSymbol(DWORD_PTR addr)
{
    for (const auto& mod : modules)
        for (const auto& exp : mod.second.symbols)
            if (exp.address == addr)
                return mod.first + "!" + exp.name;
    return "";
}

void Debugger::parseCode(std::vector<DisasmLine>* code)
{
    for (auto it = code->begin(); it != code->end(); it++)
    {
        if((it->instruction.find("call") != std::string::npos)
            || (it->instruction.find("jmp") != std::string::npos))
        {
            auto pos = it->instruction.find("0x");
            if (pos != std::string::npos)
            {
                std::string hexPart = it->instruction.substr(pos);
                DWORD_PTR targetAddr = std::stoull(hexPart, nullptr, 16);
                std::string symbol = resolveSymbol(targetAddr);
                if (!symbol.empty())
                {
                    std::string newInst = it->instruction.substr(0, pos) + symbol;
                    it->instruction = newInst;
                }
            }
        }
    }
}

void Debugger::sendCommand(const std::string& cmd)
{
    std::lock_guard<std::mutex> lock(cmdMutex);
    commandQueue.push(cmd);
    cmdCV.notify_one();
}

void Debugger::handleStepOut()
{
    DWORD_PTR retAddr = getRetAddr();
    setBreakPoint(retAddr, true);
    state = RUN;
}

void Debugger::handleStepOver()
{

    DWORD_PTR curIP = getIP();
    DWORD_PTR retAddr = curIP;
    std::vector<uint8_t> buf(16);
    std::string asmBuf(128, '\0');
    std::string hexBuf(128, '\0');
    SIZE_T bytesRead;
    if (ReadProcessMemory(hProcess, (LPCVOID)retAddr, buf.data(), 16, &bytesRead) || bytesRead == 0)
    {
        size_t len = disas.DisasInst(buf.data(), bytesRead, retAddr, asmBuf, hexBuf);
        if (asmBuf.find("call") != std::string::npos)
        {
            setBreakPoint(curIP + len, true);
            state = RUN;
        }
        else
            state = STEP;
    }

}

DWORD_PTR Debugger::getRetAddr() {


#if defined(_WIN64)
    DWORD_PTR stackPointer = cont->Rsp;
#else
    DWORD_PTR stackPointer = cont->Esp;
#endif

    DWORD_PTR retAddr;
    SIZE_T bytesRead;

    if (ReadProcessMemory(hProcess, (LPCVOID)stackPointer, &retAddr, sizeof(retAddr), &bytesRead) &&
        bytesRead == sizeof(retAddr)) {
        return retAddr;
    }
    return 0;
}

void Debugger::rangeStep()
{
    DWORD_PTR currIP = getIP();
    if (currIP < startTrace || currIP > endTrace)
    {
        state = RUN;
        cont->EFlags &= ~0x100;
        return;
    }
    std::stringstream ss;
    disasDebugProc(currIP, ss, 1);
    //logger.trace(ss.str(), cont);   
}


void Debugger::startTraceRange()
{
    state = TRACING;
    cont->EFlags |= 0x100;
    //logger.startTrace(startTrace, endTrace);
}


size_t Debugger::traceRangeEvent(DWORD tid, DWORD_PTR exceptionAddr, DebugEvent* de)
{
        std::stringstream ss;
        size_t len = disasDebugProc(exceptionAddr, ss, 1);
        if (ss.str().find("call") != std::string::npos)
        {
            DWORD_PTR addr;
            std::string call;
            ss >> call >>  call >> call >> addr;
            if (addr < startTrace || addr > endTrace)
            {
                setBreakPoint(exceptionAddr + len, true);
                state = TRACE_RUN;
            }
        }

        rangeStep();
        return DBG_CONTINUE;
    
}

void Debugger::disableBreakPoint(DWORD_PTR addr)
{
    auto it = breakMap.find(addr);
    if (it != breakMap.end())
    {
        breakMap[addr].state = BreakState::disable;
        WriteProcessMemory(hProcess, (PVOID)addr, &breakMap[addr].saveByte, 1, NULL);
    }
}


std::vector<StackLine> Debugger::getStack(const int numEntries = 64)
{
    std::vector<StackLine> stackLines;
#if defined(_WIN64)
    DWORD_PTR esp = cont->Rsp;
#else
    DWORD_PTR esp = cont->Esp;
#endif

    stackLines.clear();

    for (int i = 0; i < numEntries; ++i)
    {
        DWORD_PTR addr = esp + i * sizeof(void*);
        DWORD_PTR value = 0;
        SIZE_T bytesRead;

        if (ReadProcessMemory(hProcess, (LPCVOID)addr, &value, sizeof(value), &bytesRead))
        {
            StackLine line;
            line.address = addr;
            line.value = value;
            line.label = "";

            if (i == 0)
                line.label = "<return address>";
            
            else if (i == 1)
                line.label = "<saved ebp>";
            

            

            stackLines.push_back(line);
        }
        else {
            // Ошибка чтения
            StackLine line;
            line.address = addr;
            line.value = 0;
            line.label = "<memory access error>";
            stackLines.push_back(line);
            break;
        }
    }

    return stackLines;
}