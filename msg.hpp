#pragma once
#include <string>
#include <vector>
#include <Windows.h>

// === Объявления структур (без конструкторов/деструкторов) ===
struct CDisasmLine
{
    DWORD_PTR address;
    char* bytes;
    char* instruction;
    bool hasBreakpoint;
};

struct CDataLine
{
    DWORD_PTR address;
    BYTE* bytes;
    size_t bytesSize;
    char* ascii;
};

struct CDataSection
{
    char* secName;
    CDataLine* data;
    size_t dataCount;
};

struct CStackLine
{
    DWORD_PTR address;
    DWORD_PTR value;
    char* label;
};

typedef enum
{
    CAPI__StartDebbug, CAPI__BreakpointEvent, CAPI__BreakpointSetup, CAPI__HardBreakpointSetup, CAPI__ModuleLoad, CAPI__ProcessExit, CAPI__CreateThread, CAPI__ExitThread, CAPI__ModuleUnload, CAPI__DbgStr,
    Dump, CAPI__Reg, CAPI__ModList, CAPI__ThreadList, CAPI__BreakList, CAPI__HwBreakList, CAPI__CreateProc, CAPI__DisasmCode, CAPI__HardwareBreak,
    InputError, CAPI__Step, CAPI__Run, CAPI__DbgError, CAPI__DbgWarning, CAPI__StepOver, CAPI__StepOut, CAPI__Nope, CAPI__SetupTrace, CAPI__TraceStep, CAPI__LoadPlug
} CDebugEventType;

struct CDebugEvent
{
    CDebugEventType type;
    DWORD_PTR address;
    char* message;
    CDisasmLine* disasmCode;
    size_t disasmCodeCount;
    CDataSection* data;
    size_t dataCount;
    CStackLine* stackData;
    size_t stackDataCount;
    CONTEXT context;
    DWORD_PTR startTrace;
    DWORD_PTR endTrace;
    char* prog;
};

// === Функции инициализации ===
void initCDisasmLine(struct CDisasmLine* line);
void initCDataLine(struct CDataLine* line);
void initCDataSection(struct CDataSection* section);
void initCStackLine(struct CStackLine* line);
void initCDebugEvent(struct CDebugEvent* event);

// === Функции освобождения ===
void freeCDisasmLine(struct CDisasmLine* line);
void freeCDataLine(struct CDataLine* line);
void freeCDataSection(struct CDataSection* section);
void freeCStackLine(struct CStackLine* line);
void freeCDebugEvent(struct CDebugEvent* event);

// === Функции копирования ===
void copyCDisasmLine(struct CDisasmLine* dst, const struct CDisasmLine* src);
void copyCDataLine(struct CDataLine* dst, const struct CDataLine* src);
void copyCDataSection(struct CDataSection* dst, const struct CDataSection* src);
void copyCStackLine(struct CStackLine* dst, const struct CStackLine* src);
void copyCDebugEvent(struct CDebugEvent* dst, const struct CDebugEvent* src);
struct DisasmLine
{
    DWORD_PTR address;
    std::string bytes;
    std::string instruction;
    bool hasBreakpoint = false;
    DisasmLine() = default;
    DisasmLine(DWORD_PTR addr, const std::string& b, const std::string& inst)
        : address(addr), bytes(b), instruction(inst)
    {

    }
    DisasmLine(const CDisasmLine& c)
        : address(c.address)
        , bytes(c.bytes ? c.bytes : "")
        , instruction(c.instruction ? c.instruction : "")
        , hasBreakpoint(c.hasBreakpoint)
    {
    }
};

struct DataLine
{
    DWORD_PTR address;
    std::vector<BYTE> bytes;
    std::string ascii;
    DataLine() = default;
    DataLine(DWORD_PTR addr, const std::vector<BYTE>& b, const std::string& asc)
        : address(addr), bytes(b), ascii(asc)
    {

    }
    // Конструктор из CDataLine
    DataLine(const CDataLine& c)
        : address(c.address)
        , bytes(c.bytes ? c.bytes : nullptr, c.bytes + (c.bytes ? c.bytesSize : 0))
        , ascii(c.ascii ? c.ascii : "")
    {
    }
};

struct DataSection
{
    std::string secName;
    std::vector<DataLine> data;
    DataSection() = default;
    DataSection(const std::string& sec, const std::vector<DataLine>& d)
        : secName(sec), data(d)
    {

    }
    // Конструктор из CDataSection
    DataSection(const CDataSection& c)
        : secName(c.secName ? c.secName : "")
        , data()
    {
        if (c.data && c.dataCount > 0) {
            data.reserve(c.dataCount);
            for (size_t i = 0; i < c.dataCount; ++i) {
                data.emplace_back(c.data[i]);
            }
        }
    }
};

struct StackLine {
    DWORD_PTR address;
    DWORD_PTR value;
    std::string label;
    StackLine() = default;
    // Конструктор из CStackLine
    StackLine(const CStackLine& c)
        : address(c.address)
        , value(c.value)
        , label(c.label ? c.label : "")
    {
    }
};

struct DebugEvent
{
    enum Type {
        StartDebbug, BreakpointEvent, BreakpointSetup, HardBreakpointSetup, ModuleLoad, ProcessExit, CreateThread, ExitThread, ModuleUnload, DbgStr,
        Dump, Reg, ModList, ThreadList, BreakList, HwBreakList, CreateProc, DisasmCode, HardwareBreak,
        InputError, Step, Run, DbgError, DbgWarning, StepOver, StepOut, Nope, SetupTrace, TraceStep, LoadPlug
    } type;

    DWORD_PTR address = 0;
    std::string message;
    std::vector<DisasmLine> disasmCode;
    std::vector<DataSection> data;
    std::vector<StackLine> stackData;
    CONTEXT context;

    DWORD_PTR startTrace = 0;
    DWORD_PTR endTrace = 0;
    std::string prog;
    DebugEvent() = default;
    // Конструктор из CDebugEvent
    DebugEvent(const CDebugEvent& c)
        : type(static_cast<Type>(c.type))
        , address(c.address)
        , message(c.message ? c.message : "")
        , disasmCode()
        , data()
        , stackData()
        , context(c.context)
        , startTrace(c.startTrace)
        , endTrace(c.endTrace)
        , prog(c.prog ? c.prog : "")
    {
        // disasmCode
        if (c.disasmCode && c.disasmCodeCount > 0) {
            disasmCode.reserve(c.disasmCodeCount);
            for (size_t i = 0; i < c.disasmCodeCount; ++i) {
                disasmCode.emplace_back(c.disasmCode[i]);
            }
        }

        // data
        if (c.data && c.dataCount > 0) {
            data.reserve(c.dataCount);
            for (size_t i = 0; i < c.dataCount; ++i) {
                data.emplace_back(c.data[i]);
            }
        }

        // stackData
        if (c.stackData && c.stackDataCount > 0) {
            stackData.reserve(c.stackDataCount);
            for (size_t i = 0; i < c.stackDataCount; ++i) {
                stackData.emplace_back(c.stackData[i]);
            }
        }
    }
};




