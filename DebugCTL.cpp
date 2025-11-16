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
#include "msg.hpp"


namespace fs = std::filesystem;

void Debugger::run()
{
    bool ready = false;
    std::string prog;
    while (!ready)
        if (!commandQueue.empty())
        {
            prog = waitForCommand();
            ready = true;
        }
    if (launch(prog));
    debugLoop();
}

void Debugger::debugLoop()
{
    if (!active) return;
    debugRun();
    DebugEvent de;
    de.type = DebugEvent::ProcessExit;
    notify(de);
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




void Debugger::printMemory(DWORD_PTR addr, std::ostream& stream, size_t size = 128)
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
            std::stringstream ss, disasError;
            ss << "Process created: " << std::hex << debugEvent.dwProcessId;
            std::cout << ss.str() << std::endl;

            de.message = ss.str();

            mainThreadId = debugEvent.dwThreadId;
            handleCreateThread(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.CreateThread);

            exeBaseAddress = (DWORD_PTR)debugEvent.u.CreateProcessInfo.lpBaseOfImage;
            handleLoadExe(exeBaseAddress, "main.exe", (DWORD_PTR)debugEvent.u.CreateProcessInfo.lpStartAddress);

            entryPoint = debugEvent.u.CreateProcessInfo.lpStartAddress;
            DWORD_PTR entryAddr = reinterpret_cast<DWORD_PTR>(entryPoint);
            if (!disasmDebugProc(entryAddr, disasError))
            {
                DebugEvent event;
                event.message = disasError.str();
                event.type = DebugEvent::DbgWarning;
                notify(event);
            }


            initComands();

            std::tie(sourceCode, sections) = getAllSections();

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
    //disasDebugProc(exceptionAddr, ss, 1);
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
            de.type = DebugEvent::TraceStep;
            std::stringstream ss;
            disasmDebugProc(getIP(), ss, 1);
            de.context = *cont;
            de.message = ss.str();
            notify(de);
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
            de.type = DebugEvent::TraceStep;
            std::stringstream ss;
            disasmDebugProc(getIP(), ss, 1);
            de.context = *cont;
            de.message = ss.str();
            notify(de);
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
        try {
            std::string output = it->handler(*this, iss);
            auto type = it->type;
            DebugEvent de;

            de.address = getIP();
            de.context = *cont;
            de.type = type;
            de.message = output;
            de.stackData = getStack(64);
            de.startTrace = startTrace;
            de.endTrace = endTrace;
            //std::tie(de.disasmCode, de.data) = getSections();
            notify(de);
        }
        catch (const std::exception& e)
        {
            DebugEvent de;
            de.address = getIP();
            de.type = DebugEvent::DbgError;
            de.message = e.what();
            notify(de);
        }
    }



}



DWORD_PTR Debugger::getAddr(std::istringstream& stream)
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


    if (regEdit(regName, context, value))
        output << "Register " << regName << " updated to 0x" << std::hex << value << std::endl;
    else
        output << "Unknown register: " << regName << "\n";
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
        std::cout << ss.str() << std::endl;
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
        sprintf_s(moduleName, "module_%x.dll", baseAddr);

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
    ss << "\nLoaded modules (" << std::dec << modules.size() << "):" << std::endl;
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
        std::cout << ss.str() << std::endl;
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
        symbol = arg.substr(pos + 1);
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
    catch (...) {}
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
                dbg.disasmDebugProc(addr, ss, args.count);
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
                if (!dbg.setBreakPoint(args.address))
                    throw  std::runtime_error("Failed to setup BreakPoint");
                std::stringstream ss;
                ss << args.address;
                return ss.str();
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
                    try
                    {
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
                    }
                    catch (const std::exception& e)
                    {
                        throw std::runtime_error(e.what());
                    }
                    return "";

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
                            dbg.disasmDebugProc(addr, ss, 1);
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
                if (dbg.addHardwareBreakpoint(addr, typeStr, size))
                    return "";
                else
                {
                    return "No free hardware breakpoint register (DR0-DR3)";
                }
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
            "load <plugin>",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
            {
                std::string plug;
                stream >> plug;
                auto plugFile = std::filesystem::directory_entry(plug);
                if (plugFile.exists())
                    dbg.plugManager.loadPlugin(plugFile);
                else
                    throw std::exception("This plugin file was not found!");
                return plugFile.path().filename().string();
            },
            DebugEvent::Type::LoadPlug
        },
        {
            "start",
            "start <program>",
            [](Debugger& dbg, std::istringstream& stream)-> std::string
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
                dbg.stepOut();
                return "";
            },
            DebugEvent::Type::StepOut
        },
        {
            "p",
            "p",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
            {
                dbg.stepOver();
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
                    if (dbg.getIP() >= start && dbg.getIP() <= end)
                        dbg.state = dbg.DebugState::TRACING;

                    else
                    {


                        if (!dbg.setBreakPoint(start, true))
                        {
                            std::stringstream errMsg;
                            errMsg << "Failed to setup BreakPoint on start of range: " << start;
                            throw  std::runtime_error(errMsg.str());
                        }

                        if (!dbg.setBreakPoint(end, true))
                        {
                            std::stringstream errMsg;
                            errMsg << "Failed to setup BreakPoint on end of range: " << start;
                            throw  std::runtime_error(errMsg.str());
                        }

                    }
                    return "";
            },
            DebugEvent::Type::SetupTrace
        },
        {
            "hwdel",
            "hwdel <addres>",
            [](Debugger& dbg, std::istringstream& stream) -> std::string
            {
                    CommandArgs args = dbg.parseArgs(stream);
                    if (args.helpRequested || !args.valid)
                        return  std::string("Use: hwdel <addres>");

                    if (dbg.delHardwareBreakpoint(args.address))
                        return "";
                    else
                        return  std::string("Use: hwdel <addres>");
            },
            DebugEvent::Type::Nope
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
        if ((it->instruction.find("call") != std::string::npos)
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
    disasmDebugProc(currIP, ss, 1);
}


void Debugger::startTraceRange()
{
    state = TRACING;
    cont->EFlags |= 0x100;
}


size_t Debugger::traceRangeEvent(DWORD tid, DWORD_PTR exceptionAddr, DebugEvent* de)
{
    std::stringstream ss;
    size_t len = disasmDebugProc(exceptionAddr, ss, 1);
    if (ss.str().find("call") != std::string::npos)
    {
        DWORD_PTR addr;
        std::string call;
        ss >> call >> call >> call >> addr;
        if (addr < startTrace || addr > endTrace)
        {
            setBreakPoint(exceptionAddr + len, true);
            state = TRACE_RUN;
        }
    }

    rangeStep();
    return DBG_CONTINUE;

}



