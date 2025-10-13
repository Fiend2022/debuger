#include "debug_api.hpp"


Debugger* DebugApi::debug = nullptr;

bool DebugApi::dbg_setBreakPoint(DWORD_PTR addr)
{
    if (!debug) return false;
    return debug->setBreakPoint(addr, false); 
}

void DebugApi::dbg_deleteBreakPoint(DWORD_PTR addr)
{
    if (debug)
        return debug->deleteBreakPoint(addr);
}

