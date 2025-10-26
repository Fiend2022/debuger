#pragma once
#include <string>
#include <vector>
#include <Windows.h>
#include <sstream>

struct DisasmLine
{
    DWORD_PTR address;
    std::string bytes;
    std::string instruction;
    bool hasBreakpoint = false;
};

struct DataLine
{
    DWORD_PTR address;
    std::vector<BYTE> bytes;
    std::string ascii;
};

struct DataSection
{
    std::string secName;
    std::vector<DataLine> data;
};

struct StackLine {
    DWORD_PTR address;  // адрес в памяти
    DWORD_PTR value;    // значение по этому адресу
    std::string label;  // метка: "ret to kernel32!CreateFileA" или "[ebp-4]"
};

struct DebugEvent
{
    enum Type {StartDebbug, BreakpointEvent, BreakpointSetup, HardBreakpointSetup, ModuleLoad, ProcessExit, CreateThread, ExitThread, ModuleUnload, DbgStr,
        Dump, Reg, ModList, ThreadList, BreakList, HwBreakList, CreateProc, DisasmCode, HardwareBreak,
        InputError, Step, Run, DbgError, DbgWarning, StepOver, StepOut, Nope, SetupTrace, TraceStep, LoadPlug} type;
    DWORD_PTR address = 0;
    std::string message;
    std::vector<DisasmLine> disasmCode;
    std::vector<DataSection> data;
    std::vector<StackLine> stackData;
    CONTEXT context;

    DWORD_PTR startTrace = 0;
    DWORD_PTR endTrace = 0;
    std::string prog;
};
