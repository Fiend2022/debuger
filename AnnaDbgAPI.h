#pragma once
#include <string>
#include <vector>
#include <Windows.h>
#include <sstream>


#ifdef __cplusplus
extern "C" {
#endif

// =============== C-структуры (оставляем как есть) ===============
struct CDisasmLine
{
    DWORD_PTR address;
    char* bytes;
    char* instruction;
    bool hasBreakpoint = false;
};

struct CDataLine
{
    DWORD_PTR address;
    BYTE* bytes;
    size_t bytes_size;   // ← вы уже добавили
    char* ascii;
};

struct CDataSection
{
    char* secName;
    CDataLine* data;
    size_t data_count;   // ← вы уже добавили
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
    DWORD_PTR address = 0;
    char* message;
    CDisasmLine* disasmCode;
    size_t disasmCode_count;  // ← вы уже добавили
    CDataSection* data;
    size_t data_count;        // ← вы уже добавили
    CStackLine* stackData;
    size_t stackData_count;   // ← вы уже добавили
    CONTEXT context;

    DWORD_PTR startTrace = 0;
    DWORD_PTR endTrace = 0;
    char* prog;
};


typedef struct DebugCAPI DebugCAPI;

typedef bool (*dbg_set_bp_fn)(DWORD_PTR addr);
typedef void (*dbg_del_bp_fn)(DWORD_PTR addr);
typedef void* (*dbg_get_bp_list_fn)(void);

typedef bool (*dbg_set_hw_bp_fn)(DWORD_PTR addr, const char* type, size_t size);
typedef bool (*dbg_del_hw_bp_fn)(DWORD_PTR addr);
typedef void* (*dbg_get_hw_bp_list_fn)(void);

typedef void (*dbg_step_fn)(void);
typedef void (*dbg_step_over_fn)(void);
typedef void (*dbg_step_out_fn)(void);
typedef void (*dbg_run_fn)(void);
typedef void (*dbg_stop_fn)(void);

typedef CONTEXT* (*dbg_get_context_fn)(void);
typedef bool (*dbg_change_reg_fn)(const char* reg, DWORD_PTR value);

typedef size_t (*dbg_mem_dump_fn)(DWORD_PTR addr, void* output, size_t size);
typedef bool (*dbg_mem_edit_fn)(DWORD_PTR addr, void* input, size_t size);

typedef void* (*dbg_get_modules_fn)(void);
typedef void* (*dbg_get_threads_fn)(void);
typedef void (*dbg_notify)(const CDebugEvent* de);

struct DebugCAPI {
    dbg_set_bp_fn setBP;
    dbg_del_bp_fn delBP;
    dbg_get_bp_list_fn getBpList;

    dbg_set_hw_bp_fn setHwBP;
    dbg_del_hw_bp_fn delHwBP;
    dbg_get_hw_bp_list_fn getHwBpList;

    dbg_step_fn step;
    dbg_step_over_fn stepOver;
    dbg_step_out_fn stepOut;
    dbg_run_fn run;
    dbg_stop_fn stop;

    dbg_get_context_fn getCont;
    dbg_change_reg_fn chgReg;

    dbg_mem_dump_fn memDump;
    dbg_mem_edit_fn memEdit;

    dbg_get_modules_fn getMods;
    dbg_get_threads_fn getThreads;
	dbg_notify notify;
};

typedef bool (*plugin_init_fn)(const DebugCAPI* host_api);
typedef void (*plugin_shutdown_fn)(void);

typedef struct PluginAPI {
    plugin_init_fn init;
    plugin_shutdown_fn shutdown;
} PluginAPI;

// Экспортируется ПЛАГИНОМ
__declspec(dllexport) PluginAPI get_plugin_api(void);

// Экспортируется ЯДРОМ (debugger_core.dll)
const DebugCAPI* get_debug_api(void);



#ifdef __cplusplus
}
#endif



// =============== C++-структуры с конструкторами из C ===============

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
        , bytes(c.bytes ? c.bytes : nullptr, c.bytes + (c.bytes ? c.bytes_size : 0))
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
        if (c.data && c.data_count > 0) {
            data.reserve(c.data_count);
            for (size_t i = 0; i < c.data_count; ++i) {
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
        if (c.disasmCode && c.disasmCode_count > 0) {
            disasmCode.reserve(c.disasmCode_count);
            for (size_t i = 0; i < c.disasmCode_count; ++i) {
                disasmCode.emplace_back(c.disasmCode[i]);
            }
        }

        // data
        if (c.data && c.data_count > 0) {
            data.reserve(c.data_count);
            for (size_t i = 0; i < c.data_count; ++i) {
                data.emplace_back(c.data[i]);
            }
        }

        // stackData
        if (c.stackData && c.stackData_count > 0) {
            stackData.reserve(c.stackData_count);
            for (size_t i = 0; i < c.stackData_count; ++i) {
                stackData.emplace_back(c.stackData[i]);
            }
        }
    }
};
