#include "debugger.hpp"
#include <iostream>
#include <filesystem>
#include <vector>
#include <iomanip>
#include <stdexcept>
#include <sstream>
#include <functional>
#include  <winnt.h>
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
        std::cerr << "No free hardware breakpoint register (DR0-DR3)\n";
        return false;
    }

    int rw = 0, len = 0;
    if (typeStr == "write")
        rw = 1;
    else if (typeStr == "access")
        rw = 3;
    
    else
    {
        std::cerr << "Invalid type. Use 'write' or 'access'\n";
        return false;
    }

    switch (size) {
    case 1: len = 0; break;
    case 2: len = 1; break;
    case 4: len = 3; break;
#ifdef _WIN64
    case 8: len = 2; break;
#else
    default: std::cerr << "Invalid size\n"; return false;
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
    std::cout << "HWBP set at DR" << idx << " (0x" << std::hex << addr
        << ") type=" << typeStr << ", size=" << size << "\n";

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
    if (createDebugProc(prog))
    {
        debugRun();
        DebugEvent de;
        de.type = DebugEvent::ProcessExit;
        eventCallback(de);
    }
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

void Debugger::setBreakPoint(DWORD_PTR addr, BreakType type = BreakType::software, bool temp = false)
{
    auto it = breakMap.find(addr);
    if (it == breakMap.end())
    {
        BYTE saveByte;
        ReadProcessMemory(hProcess, (PVOID)addr, &saveByte, 1, NULL);
        WriteProcessMemory(hProcess, (PVOID)addr, "\xCC", 1, NULL);
        breakMap[addr] = { BreakState::enable, BreakType::software, saveByte, temp };
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
        std::cerr << "No breakpoint found at 0x" << std::hex << addr << std::endl;

}

void Debugger::printRegisters(const CONTEXT& context)
{
    std::cout << std::hex << std::setfill('0');

#ifdef _WIN64
    // 64-битные регистры
    std::cout
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
        DebugEvent de;
        DWORD continueFlag = DBG_CONTINUE;
        static LPTHREAD_START_ROUTINE entryPoint;
        if (!WaitForDebugEvent(&debugEvent, INFINITE))
            break;
        static std::vector<DisasmLine> sourceCode, data;
       

        switch (debugEvent.dwDebugEventCode)
        {
        case CREATE_THREAD_DEBUG_EVENT:
            handleCreateThread(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.CreateThread);
            //std::cout << "Thread created: " << debugEvent.dwThreadId << std::endl;
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            handleExitThread(debugEvent.dwProcessId, debugEvent.dwThreadId, debugEvent.u.ExitProcess.dwExitCode);
            //std::cout << "Thread exited: " << debugEvent.dwThreadId << std::endl;
            break;
        case CREATE_PROCESS_DEBUG_EVENT:
        {
            std::cout << "Process created: " << std::hex << debugEvent.dwProcessId << std::endl;
            mainThreadId = debugEvent.dwThreadId;
            handleCreateThread(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.CreateThread);
            exeBaseAddress = (DWORD_PTR)debugEvent.u.CreateProcessInfo.lpBaseOfImage;
            handleLoadExe(exeBaseAddress, "main.exe", (DWORD_PTR)debugEvent.u.CreateProcessInfo.lpStartAddress);
            entryPoint = debugEvent.u.CreateProcessInfo.lpStartAddress;
            DWORD_PTR entryAddr = reinterpret_cast<DWORD_PTR>(entryPoint);
            disasDebugProc(entryAddr);
            std::cout << "Entry point address: 0x" << std::hex << entryAddr << std::endl;
            initComands();
            std::tie(sourceCode, data) = getSections();
            setBreakPoint(entryAddr, BreakType::software);
            auto it = std::find_if(sourceCode.begin(), sourceCode.end(),
                [entryAddr](const DisasmLine& line)
                { return line.address == entryAddr; }
            );
            it->hasBreakpoint = true;
            de.address = (DWORD_PTR)entryPoint;
            de.disasmCode = sourceCode;
            de.data = data;
            de.type = DebugEvent::DisasmReady;
            eventCallback(de);
            break;
        }

        case EXIT_PROCESS_DEBUG_EVENT:
            std::cout << "Process exited: " << debugEvent.dwProcessId << std::endl;
            active = false;
            break;
        case LOAD_DLL_DEBUG_EVENT:
            handleLoadDLL(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.LoadDll);
            parseCode(&sourceCode);
            de.address = (DWORD_PTR)entryPoint;
            de.disasmCode = sourceCode;
            de.type = DebugEvent::ModuleLoad;
            eventCallback(de);
            break;

        case UNLOAD_DLL_DEBUG_EVENT:
            handleUnloadDLL(debugEvent.dwProcessId, debugEvent.dwThreadId, reinterpret_cast<DWORD_PTR>(debugEvent.u.UnloadDll.lpBaseOfDll));
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

        if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueFlag))
            printf("Error continuing debug event\n");

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
    de->address = exceptionAddr;
    auto it = breakMap.find(exceptionAddr);

    if (it == breakMap.end() && !isTrace && !isRun)
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
    else if (it == breakMap.end() && isTrace == false)
    {
        context.EFlags |= 0x100;
        SetThreadContext(thread, &context);
        CloseHandle(thread);
        return DBG_CONTINUE;
    }
    disasDebugProc(exceptionAddr, 1);
    if (it != breakMap.end())
    {
        if (it->second.temp)
            deleteBreakPoint(it->first);
    }
#ifdef _WIN64
    context.Rip = exceptionAddr;
#else
    context.Eip = exceptionAddr;
#endif
    isRun = false;
    isTrace = false;

    //de->type = DebugEvent::BreakpointEvent;
    de->context = context;
    de->address = exceptionAddr;
    eventCallback(*de);

    while (!isRun && !isTrace)
    {
        if (!commandQueue.empty())
        {
            std::string cmd = waitForCommand();
            if (!cmd.empty())
            {
                commandLine(cmd, context);

            }
        }
    }



    if (isTrace)
        context.EFlags |= 0x100;
    else
        context.EFlags &= ~0x100;



    SetThreadContext(thread, &context);
    CloseHandle(thread);


    return DBG_CONTINUE;
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
    switch (exc->ExceptionRecord.ExceptionCode)
    {
        case EXCEPTION_BREAKPOINT:
            de.type = DebugEvent::BreakpointEvent;
            return breakpointEvent(tid, (DWORD_PTR)exc->ExceptionRecord.ExceptionAddress, &de);

        case EXCEPTION_SINGLE_STEP:
        {
            CONTEXT ctx;
            HANDLE thread;

            thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);


            if (thread == INVALID_HANDLE_VALUE) return DBG_EXCEPTION_NOT_HANDLED;
            ctx.ContextFlags = CONTEXT_ALL;
            if (!GetThreadContext(thread, &ctx)) break;

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
                std::cout << "[HWBP] Triggered at 0x" << std::hex << addr << " (DR" << drIndex << ")\n";
                isTrace = true;
            #if defined(_WIN64)
                DWORD_PTR currIp = ctx.Rip;
            #else
                DWORD_PTR currIp = ctx.Eip;
            #endif

                SetThreadContext(thread, &ctx);
                CloseHandle(thread);
                de.type = DebugEvent::HardwareBreak;
                size_t contFlag = breakpointEvent(tid, currIp, &de);
                return contFlag;
            }
        }
        de.type = DebugEvent::Step;
        return breakpointEvent(tid, (DWORD_PTR)exc->ExceptionRecord.ExceptionAddress, &de);

    default:
        return DBG_EXCEPTION_NOT_HANDLED;
    }
    return DBG_EXCEPTION_NOT_HANDLED;
}


void Debugger::commandLine(const std::string& command, CONTEXT& cont)
{
   
    std::istringstream iss(command);
    std::string cmd;
    iss >> cmd;

    auto it = std::find_if(commands.begin(), commands.end(), [cmd](CommandInfo elem) {return elem.name == cmd; });
    this->cont = &cont;
    if (it != commands.end())
        it->handler(*this, iss);
    


}

void Debugger::handleTraceCommand()
{
    isTrace = true;
    isRun = false;
}


DWORD_PTR getAddr(std::istringstream& stream)
{
    std::string addrStr;
    stream >> addrStr;

    if (addrStr.empty()) {
        std::cerr << "Address is missing.\n";
        return 0;
    }

    // Обрабатываем префикс 0x, если он есть
    if (addrStr.size() > 2 && addrStr[0] == '0' && (addrStr[1] == 'x' || addrStr[1] == 'X')) {
        addrStr = addrStr.substr(2);
    }

    try {
        // Используем stoull для чтения 64-битного значения
        size_t pos;
        uint64_t addr = std::stoull(addrStr, &pos, 16);

        // Проверяем, что вся строка была успешно прочитана
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
    setBreakPoint(addr, BreakType::software);
}

void Debugger::handleDelCommand(std::istringstream& stream)
{
    std::string arg;
    stream >> arg;
    DWORD_PTR addr = getArgAddr(arg);
    deleteBreakPoint(addr);
}
 
void Debugger::handleDumpCommand(std::istringstream& stream)
{
    std::string arg;
    stream >> arg;
    DWORD_PTR addr = getArgAddr(arg);
    printMemory(addr);
}


void Debugger::handleDisasCommand(std::istringstream& stream)
{
    std::string arg;
    stream >> arg;
    DWORD_PTR addr = getArgAddr(arg);
    disasDebugProc(addr);
}

void  Debugger::handleEditCommand(std::istringstream& stream)
{
    DWORD_PTR addr = getAddr(stream);
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
        changeMemory(addr, &value, dataSize[strSize]);
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
    if (it != regMap.end())
    {
        it->second(context, value);
        std::cout << "Register " << regName << " updated to 0x" << std::hex << value << std::endl;
    }
    else
        std::cerr << "Unknown register: " << regName << "\n";
}

void Debugger::handleExitThread(DWORD pid, DWORD tid, DWORD exitCode)
{
    auto it = threads.find(tid);
    if (it != threads.end())
    {
        CloseHandle(it->second.hThread);
        std::cout << "[-] Thread exited: TID=" << std::dec << tid
            << ", ExitCode=" << exitCode << std::endl;
        threads.erase(it);
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
        std::cout << "[-] DLL unloaded: " << it->first
            << " @ 0x" << std::hex << addr << std::endl;
        modules.erase(it);
    }
    else
        std::cout << "[-] Unknown module unloaded @ 0x" << std::hex << addr << std::endl;
}


void Debugger::handleCreateThread(DWORD pid, DWORD tid, CREATE_THREAD_DEBUG_INFO* info)
{
    DWORD_PTR addres = (DWORD_PTR)info->lpStartAddress;
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    threads[tid] = { tid, hThread, true };

    std::cout << "[+] Thread created: TID=" << std::dec << tid
        << " @ 0x" << std::hex << (DWORD_PTR)info->lpStartAddress << std::endl;

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

    std::cout << "[+] DLL loaded: " << moduleName
        << " @ 0x" << std::hex << baseAddr << std::endl;
}


void Debugger::handleModulesCommand()
{
    std::cout << "\nLoaded modules ("<< std::dec << modules.size() << "):" << std::endl;
    std::cout << std::setw(18) << "Address" << " | " << std::setw(12) << "Size" << " | Name" << std::endl;
    std::cout << std::string(50, '-') << std::endl;

    for (const auto& [name, mod] : modules)
    {
        std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << mod.baseAddress
            << " | " << std::dec << std::setw(10) << mod.size
            << " | " << name << std::endl;
    }
    std::cout << std::endl;
}



void Debugger::handleThreadsCommand()
{
    std::cout << "\nActive threads (" << threads.size() << "):" << std::endl;
    std::cout << std::setw(8) << "TID" << " | " << std::setw(16) << "Handle" << " | Status" << std::endl;
    std::cout << std::string(40, '-') << std::endl;

    for (const auto& [tid, thread] : threads)
    {
        std::cout << std::dec << std::setw(8) << tid
            << " | 0x" << std::hex << std::setw(14) << std::setfill('0')
            << reinterpret_cast<uintptr_t>(thread.hThread)
            << " | " << (thread.isRunning ? "Running" : "Stopped") << std::endl;
    }
    std::cout << std::endl;
}

void Debugger::handleLoadExe(DWORD_PTR baseAddr, const std::string& name, DWORD_PTR entryPoint)
{
    try {
        PeHeader pe(baseAddr, hProcess);
        prog = new PeHeader(pe);
        std::cout << "EXE Base: 0x" << std::hex << baseAddr << std::endl;

        if (pe.hasExports())
        {
            std::vector<ExportedSymbol> syms = loadSyms(pe.getExportedSymbols());
            modules[name] = { baseAddr, 0x1000, syms };
            std::cout << "Found " << syms.size() << " exports in EXE" << std::endl;
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Failed to read EXE headers: " << e.what() << std::endl;
    }

    std::cout << "[+] EXE loaded: " << name << " @ 0x" << std::hex << baseAddr
        << ", Entry: 0x" << entryPoint << std::endl;
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
        std::cerr << "Invalid address: " << args.addressArg << "\n";
        args.valid = false;
        return args;
    }



    std::string token;
    while (stream >> token)
    {
        if (token == "-n" || token == "--number")
            if (!(stream >> args.count) || args.count <= 0)
            {
                std::cerr << "Invalid count\n";
                args.valid = false;
            }
        

        if (token == "-t" || token == "--type")
            if (!(stream >> args.type))
            {
                std::cerr << "Expected type after " << token <<"\n";
                args.valid = false;
            }
        
        if (token == "-v" || token == "--value")
            if (!(stream >> args.value))
            {
                std::cerr << "Expected value\n";
                args.valid = false;
            }

    }
    return args;
}

void Debugger::initComands()
{
    commands =
    {
        {"disas",
         "disas <addr> [-n <count>]",
        [](Debugger& dbg, std::istringstream& stream)
            {
                CommandArgs args = dbg.parseArgs(stream);
                if (!args.valid) return;

                if (args.helpRequested)
                {
                    std::cout << "Use: disas <addr> [-n <count>]" << std::endl;
                    return;
                }

                DWORD_PTR addr = dbg.getArgAddr(args.addressArg);
                if (!addr)
                {
                    std::cerr << "Invalid address: " << args.addressArg << "\n";
                    return;
                }

                dbg.disasDebugProc(addr, args.count);
            }
        },

        {
            "bp",
            "bp <addres> [-t hw|hww|hwr]",
            [](Debugger& dbg, std::istringstream& stream)
            {
                std::vector<std::string> types = { "hw", "hww", "hwr"};
                CommandArgs args = dbg.parseArgs(stream);
                if (!args.valid) return;

                if (args.helpRequested)
                {
                    std::cout << "Use: bp <addres> [-t hw|hww|hwr]" << std::endl;
                    return;
                }
                if (args.type == "d")
                    dbg.setBreakPoint(args.address);
            }
        },

        {
            "dump",
            "dump <addr|symbol|reg> [-n <count>] [-t <byte|word|dword]",
            [](Debugger& dbg, std::istringstream& stream)
                {
                    std::vector<std::string> types = { "byte", "word", "dword"};
                    CommandArgs args = dbg.parseArgs(stream);
                    if (!args.valid) return;

                    if (args.helpRequested)
                    {
                        std::cout << "Use: dump <addr|symbol|reg> [-n <count>] [-t <byte|word|dword]" << std::endl;
                        return;
                    }

                    dbg.printMemory(args.address, args.count);

                }

        },

        {
            "edit",
            "edit <addr|symbol|reg> [-t <byte|word|dword|string|mnemonic>] -v <value>",
            [](Debugger& dbg, std::istringstream& stream)
                {
                    std::vector<std::string> types = { "byte", "word", "dword", "string"};
                    CommandArgs args = dbg.parseArgs(stream);
                    if (!args.valid) return;

                    if (args.helpRequested)
                    {
                        std::cout << "Use: edit <addr|symbol|reg> [-t <db|dw|dd|qd|str>]" << std::endl;
                        return;
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
                        std::cout << "Error: incorrect data type" << std::endl;
                        return;
                    }

                    return;

                }
        },

        { 
            "del",
            "del <address|symbol|reg>",    
            [](Debugger& dbg, std::istringstream& stream)
                {
                    CommandArgs args = dbg.parseArgs(stream);
                    if (!args.valid) return;

                    if (args.helpRequested)
                    {
                        std::cout << "Use: del <address|symbol|reg>" << std::endl;
                        return;
                    }

                    dbg.deleteBreakPoint(args.address);
                }
        },

        {
            "reg",
            "reg <reg> <value>",
            [](Debugger& dbg, std::istringstream& stream)
                {
                    std::string reg;
                    dbg.handleRegCommand(stream, *dbg.cont);
                }

        },

        {
            "run",
            "run",
            [](Debugger& dbg, std::istringstream& stream)
                {
                    dbg.isRun = true;
                    return;
                }

        },

        {
            "g",
            "g",
            [](Debugger& dbg, std::istringstream& stream)
                {
                    dbg.handleTraceCommand();
                    if (dbg.eventCallback)
                    {
                        DebugEvent de;
                        #if defined(_WIN64)
                            de.address = dbg.cont->Rip;
                        #else
                            de.address = dbg.cont->Eip;
                        #endif
                        de.context = *dbg.cont;
                        de.type = DebugEvent::Step;
                        dbg.eventCallback(de);
                    }
                    
                }
        },

        {
            "modules",
            "modules",
            [](Debugger& dbg, std::istringstream& stream)
                {
                    dbg.handleModulesCommand();
                }

        },

        {
            "threads",
            "threads",
            [](Debugger& dbg, std::istringstream& stream)
                {
                    dbg.handleThreadsCommand();
                }

        },

        {
            "symbols",
            "symbols",
            [](Debugger& dbg, std::istringstream& stream)
            {
                    dbg.handleSymbolsCommand();
            }
        },

        {
            "bplist",
            "bplist",
            [](Debugger& dbg, std::istringstream& stream)
                {
                    size_t n = 0;
                    for (auto& [addr, bp] : dbg.breakMap)
                    {   
                        if (!bp.temp)
                        {
                            std::string type = (bp.type == BreakType::software) ? "soft" : "hard";
                            std::cout << n << ") " << type << ": ";
                            dbg.disasDebugProc(addr, 1);
                            n++;
                        }
                    }
                }

        },

        {
            "hwbp",
            "",
            [](Debugger& dbg, std::istringstream& stream)
            {
                std::string addrStr, t, typeStr;
                int size = 1;

                stream >> addrStr >> t >> typeStr;
                if (t != "-t") {
                    std::cerr << "Usage: hwbp <addr> -t <write|access> [-n <size>]\n";
                    return;
                }

                if (stream >> t >> size) {
                    if (t != "-n") {
                        std::cerr << "Expected -n\n";
                        return;
                    }
                }

                DWORD_PTR addr = dbg.getArgAddr(addrStr);
                if (!addr) return;
                dbg.addHardwareBreakpoint(addr, typeStr, size);
            }
        },
        {
            "load",
            "load <programm",
            [](Debugger& dbg, std::istringstream& stream)
            {
                std::string prog;
                stream >> prog;

                dbg.createDebugProc(prog);
            }
        },
        {
            "stop",
            "stop",
            [](Debugger& dbg, std::istringstream& stream)
            {
                    dbg.active = false;
            }
        },
        {
            "n",
            "n",
            [](Debugger& dbg, std::istringstream& stream)
            {
                dbg.handleStepOut();
            }
        },
        {
            "p",
            "p",
            [](Debugger& dbg, std::istringstream& stream)
            {
                dbg.handleStepOver();
            }
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

std::pair<std::vector<DisasmLine>, std::vector<DisasmLine>> Debugger::getSections()
{
    std::vector<DisasmLine> codeSections, data;

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
            std::copy(dataSec.begin(), dataSec.end(), std::back_inserter(data));
        }
    }
    return { codeSections, data };
}
std::vector<DisasmLine> Debugger::getDataSection(IMAGE_SECTION_HEADER* sec)
{
    DWORD_PTR addr = sec->VirtualAddress + exeBaseAddress;
    std::vector<DisasmLine> text;

    while (addr < sec->VirtualAddress + exeBaseAddress + sec->Misc.VirtualSize)
    {
        std::vector<uint8_t> buf(16);
        SIZE_T bytesRead;

        if (!ReadProcessMemory(hProcess, (LPCVOID)addr, buf.data(), 16, &bytesRead)
            || bytesRead == 0)
            break;
        

        std::string hexStr;
        for (SIZE_T i = 0; i < bytesRead; ++i)
        {
            char byte[4];
            sprintf_s(byte, "%02X ", buf[i]);
            hexStr += byte;
        }
        if (!hexStr.empty()) hexStr.pop_back();

        std::string ascii;
        for (SIZE_T i = 0; i < bytesRead; ++i)
        {
            char c = buf[i];
            ascii += (c >= 32 && c < 127) ? c : '.';
        }

        DisasmLine tmp = { addr, hexStr, ascii };
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
    setBreakPoint(retAddr, BreakType::software, true);
    isRun = true;
}

void Debugger::handleStepOver()
{
#if defined(_WIN64)
    DWORD_PTR curIP = cont->Rip;
#else
    DWORD_PTR curIP = cont->Eip;
#endif
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
            setBreakPoint(curIP + len, BreakType::software, true);
            isRun = true;
        }
        else
            isTrace = true;
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