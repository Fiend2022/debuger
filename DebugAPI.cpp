#include "DebugAPI.hpp"
#include "debugger.hpp"
#include "msg.hpp"
#include "Observer.hpp"
#include <mutex>
#include <cstring>
#include <cstdlib>
#include <algorithm>

void copyCppToCDisasmLine(CDisasmLine* dst, const DisasmLine& src);
void copyCppToCDataLine(CDataLine* dst, const DataLine& src);
void copyCppToCDataSection(CDataSection* dst, const DataSection& src);
void copyCppToCStackLine(CStackLine* dst, const StackLine& src);
void copyCppToCDebugEvent(CDebugEvent* dst, const DebugEvent& src);

static Debugger* debug = nullptr;

class DebugAPI
{
private:
    friend class Debugger;

public:
    static void bind(Debugger* dbg);

    //Breakpoint functions;
    static bool dbg_setBreakPoint(DWORD_PTR addr);
    static void dbg_deleteBreakPoint(DWORD_PTR addr);
    static bool dbg_setHwBreakPoint(DWORD_PTR addr, const std::string& typeStr, int size);
    static bool dbg_deleteHwBreakPoint(DWORD_PTR addr);
    static std::unordered_map<DWORD_PTR, Debugger::BreakPoint>& dbg_getBpList();
    static Debugger::HwBreakpoint* dbg_getHwBpList();

    //Trace functions
    static void dbg_step();
    static void dbg_stepOver();
    static void dbg_stepOut();
    static void dbg_run();
    static void dbg_stop();

    //Registers functions
    static bool dbg_changeRegister(const std::string& reg, DWORD_PTR value);
    static CONTEXT* dbg_getContext();
    static std::string dbg_getRegs();

    // Modules and Threads functions
    static std::unordered_map<std::string, Debugger::Module>* dbg_getModules();
    static std::unordered_map<DWORD, Debugger::ActiveThread>* dbg_getThreads();

    // Memmory functions
    static std::vector<BYTE> dbg_dump(DWORD_PTR addr, size_t size);
    static bool dbg_memoryEdit(DWORD_PTR addr, void* value, size_t size);

    // Event publishing functions
    static void dbg_notify(const DebugEvent& de);
    
    // Launch functions
    static bool dbg_launch(const std::string& prog);
    static void dbg_loop();
};





static std::vector<CDebugObserver*> observers;
static std::mutex obsMutex;


void notifyAllCObservers(const DebugEvent& ev)
{
    CDebugEvent cEvent = {};
    initCDebugEvent(&cEvent);

    copyCppToCDebugEvent(&cEvent, ev);
    std::lock_guard<std::mutex> lock(obsMutex);

    for (auto& sub : observers)
        sub->update(&cEvent);

    freeCDebugEvent(&cEvent);

}

void DebugAPI::bind(Debugger* dbg)
{
    debug = dbg;
}
bool DebugAPI::dbg_setBreakPoint(DWORD_PTR addr)
{
    if (!debug) return false;
    return debug->setBreakPoint(addr, false);
}

void DebugAPI::dbg_deleteBreakPoint(DWORD_PTR addr)
{
    if (debug)
        return debug->deleteBreakPoint(addr);
}

bool DebugAPI::dbg_changeRegister(const std::string& reg, DWORD_PTR value)
{
    if (debug)
        return debug->regEdit(reg, *debug->cont, value);
}

CONTEXT* DebugAPI::dbg_getContext()
{
    if (debug)
        return debug->cont;
}

//std::string DebugAPI::dbg_getRegs()
//{
//    std::stringstream ss;
//    if (debug)
//    {
//        debug->printRegisters(*debug->cont, ss);
//        return ss.str();
//    }
//}

std::vector<BYTE> DebugAPI::dbg_dump(DWORD_PTR addr, size_t size)
{
    if (debug)
    {
        try {
            return debug->getDumpMemory(addr, size);
        }
        catch (...)
        {
            std::vector<BYTE> errBuf = { 0 };
            return errBuf;
        }
    }
}

bool DebugAPI::dbg_memoryEdit(DWORD_PTR addr, void* newValue, size_t size)
{
    if (debug)
    {
        try
        {
            debug->changeMemory(addr, newValue, size);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }
}

std::unordered_map<std::string, Debugger::Module>* DebugAPI::dbg_getModules()
{
    if (debug)
        return &debug->modules;
    else
        return nullptr;

}

std::unordered_map<DWORD, Debugger::ActiveThread>* DebugAPI::dbg_getThreads()
{
    if (debug)
        return &debug->threads;
    else
        return nullptr;
}

std::unordered_map<DWORD_PTR, Debugger::BreakPoint>& DebugAPI::dbg_getBpList() {
    if (!debug) {
        static std::unordered_map<DWORD_PTR, Debugger::BreakPoint> empty;
        return empty;
    }
    return debug->breakMap; // возвращаем ссылку!
}

bool DebugAPI::dbg_setHwBreakPoint(DWORD_PTR addr, const std::string& typeStr, int size)
{
    if (debug)
        return debug->addHardwareBreakpoint(addr, typeStr, size);
    return false;
}

bool DebugAPI::dbg_deleteHwBreakPoint(DWORD_PTR addr)
{
    if (debug)
        return debug->delHardwareBreakpoint(addr);

}

void DebugAPI::dbg_notify(const DebugEvent& de)
{
    if (debug)
        debug->notify(de);
}

Debugger::HwBreakpoint* DebugAPI::dbg_getHwBpList()
{
    if (debug)
        return debug->hwBps;
    else
        return nullptr;
}

void DebugAPI::dbg_step()
{
    if (debug)
    {
        debug->state = Debugger::STEP;
        debug->cont->EFlags |= 0x100;
    }
}
void DebugAPI::dbg_stepOver()
{
    if (debug) debug->stepOver();
}

void DebugAPI::dbg_stepOut()
{
    if (debug) debug->stepOut();
}


void DebugAPI::dbg_run()
{
    if (debug) debug->state = Debugger::RUN;
}

void DebugAPI::dbg_stop()
{
    if (debug)
    {
        debug->state = Debugger::STOP;
        debug->active = false;
    }
}

void DebugAPI::dbg_loop()
{
    debug->debugLoop();
}

bool API__setBP(DWORD_PTR addr)
{
    return DebugAPI::dbg_setBreakPoint(addr);
}

void API__delBP(DWORD_PTR addr)
{
    return DebugAPI::dbg_deleteBreakPoint(addr);
}

void* API__BpList()
{
    return &DebugAPI::dbg_getBpList();
}

bool API__setHwBP(DWORD_PTR addr, const char* type, size_t size)
{
    return DebugAPI::dbg_setHwBreakPoint(addr, type, size);
}

bool API__delHwBP(DWORD_PTR addr)
{
    return DebugAPI::dbg_deleteHwBreakPoint(addr);
}

void* API__HwBpList()
{
    return (void*)DebugAPI::dbg_getHwBpList();
}

void API__step()
{
    DebugAPI::dbg_step();
}

void API__stepOver()
{
    DebugAPI::dbg_stepOver();
}

void API__stepOut()
{
    DebugAPI::dbg_stepOut();
}

void API__run()
{
    DebugAPI::dbg_run();
}

void API__stop()
{
    DebugAPI::dbg_stop();
}

CONTEXT* API__getContext()
{
    return DebugAPI::dbg_getContext();
}

bool API__chgReg(const char* regName, DWORD_PTR addr)
{
    return DebugAPI::dbg_changeRegister(regName, addr);
}

size_t API__memDump(DWORD_PTR addr, void* output, size_t size)
{
    auto dump = DebugAPI::dbg_dump(addr, size);
    if (dump.size() < size) size = (int)dump.size();
    memcpy(output, dump.data(), size);
    return size;
}

bool API__memEdit(DWORD_PTR addr, void* input, size_t size)
{
    return DebugAPI::dbg_memoryEdit(addr, input, size);
}

void* API__getModules()
{
    return (void*)DebugAPI::dbg_getModules();
}

void* API__getThreads()
{
    return (void*)DebugAPI::dbg_getThreads();
}

void API__notify(const CDebugEvent* de)
{
    DebugAPI::dbg_notify(*de);
}

bool DebugAPI::dbg_launch(const std::string& prog)
{
    return debug->launch(prog);
}

bool API__launch(const char* prog)
{
    return DebugAPI::dbg_launch(prog);
}




void API__attach(CDebugObserver* obs)
{
    auto it = std::find(observers.begin(), observers.end(), obs);
    if (it == observers.end())
        observers.push_back(obs);
}
void API__detach(CDebugObserver* obs)
{
    auto it = std::find(observers.begin(), observers.end(), obs);
    if (it != observers.end())
        std::erase(observers, obs);
}

void API__loop()
{
    DebugAPI::dbg_loop();
}

static DebugCAPI gCAPI =
{
    API__setBP, API__delBP, API__BpList,
    API__setHwBP, API__delHwBP, API__HwBpList,
    API__step, API__stepOver, API__stepOut, API__run, API__stop,
    API__getContext, API__chgReg,
    API__memDump, API__memEdit,
    API__getModules, API__getThreads,
    API__notify, API__attach, API__detach,
    API__launch, API__loop
};

extern "C" const DebugCAPI* get_debug_api()
{
    return &gCAPI;
}

void InitDebugAPI(Debugger* dbg)
{
    if (!debug)
        DebugAPI::bind(dbg);
}




// === Вспомогательная функция ===
static char* strDup(const std::string& s)
{
    if (s.empty()) return nullptr;
    char* dup = new char[s.length() + 1];
    strcpy_s(dup, s.length() + 1, s.c_str());
    return dup;
}

// === Копирование C++ → C ===
void copyCppToCDisasmLine(CDisasmLine* dst, const DisasmLine& src) {
    dst->address = src.address;
    dst->bytes = strDup(src.bytes);
    dst->instruction = strDup(src.instruction);
    dst->hasBreakpoint = src.hasBreakpoint;
}

void copyCppToCDataLine(CDataLine* dst, const DataLine& src) {
    dst->address = src.address;
    dst->bytesSize = src.bytes.size();
    if (!src.bytes.empty()) {
        dst->bytes = new BYTE[src.bytes.size()];
        memcpy(dst->bytes, src.bytes.data(), src.bytes.size());
    }
    else {
        dst->bytes = nullptr;
    }
    dst->ascii = strDup(src.ascii);
}

void copyCppToCDataSection(CDataSection* dst, const DataSection& src) {
    dst->secName = strDup(src.secName);
    dst->dataCount = src.data.size();
    if (!src.data.empty()) {
        dst->data = new CDataLine[src.data.size()];
        for (size_t i = 0; i < src.data.size(); ++i) {
            copyCppToCDataLine(&dst->data[i], src.data[i]);
        }
    }
    else {
        dst->data = nullptr;
    }
}

void copyCppToCStackLine(CStackLine* dst, const StackLine& src) {
    dst->address = src.address;
    dst->value = src.value;
    dst->label = strDup(src.label);
}

void copyCppToCDebugEvent(CDebugEvent* dst, const DebugEvent& src) {
    dst->type = static_cast<CDebugEventType>(src.type);
    dst->address = src.address;
    dst->message = strDup(src.message);
    dst->context = src.context;
    dst->startTrace = src.startTrace;
    dst->endTrace = src.endTrace;
    dst->prog = strDup(src.prog);

    // disasmCode
    dst->disasmCodeCount = src.disasmCode.size();
    if (!src.disasmCode.empty()) {
        dst->disasmCode = new CDisasmLine[src.disasmCode.size()];
        for (size_t i = 0; i < src.disasmCode.size(); ++i) {
            copyCppToCDisasmLine(&dst->disasmCode[i], src.disasmCode[i]);
        }
    }
    else {
        dst->disasmCode = nullptr;
    }

    // data
    dst->dataCount = src.data.size();
    if (!src.data.empty()) {
        dst->data = new CDataSection[src.data.size()];
        for (size_t i = 0; i < src.data.size(); ++i) {
            copyCppToCDataSection(&dst->data[i], src.data[i]);
        }
    }
    else {
        dst->data = nullptr;
    }

    // stackData
    dst->stackDataCount = src.stackData.size();
    if (!src.stackData.empty()) {
        dst->stackData = new CStackLine[src.stackData.size()];
        for (size_t i = 0; i < src.stackData.size(); ++i) {
            copyCppToCStackLine(&dst->stackData[i], src.stackData[i]);
        }
    }
    else {
        dst->stackData = nullptr;
    }
}