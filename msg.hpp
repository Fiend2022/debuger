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

struct DebugEvent
{
    enum Type {BreakpointEvent, BreakpointSetup, ModuleLoad, ProcessExit,
        DisasmProg, DisasmCode, HardwareBreak, Step, Run, Error, StepOver} type;
    DWORD_PTR address = 0;
    std::string message;
    std::vector<DisasmLine> disasmCode;
    std::vector<DisasmLine> data;
    CONTEXT context;

};
