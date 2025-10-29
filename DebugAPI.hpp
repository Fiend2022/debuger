#pragma once
#include <Windows.h>
#include "msg.hpp"

class Debugger;
void InitDebugAPI(Debugger* dbg);

struct DebugCAPI
{
    bool (*setBP)(DWORD_PTR addr);
    void (*delBP)(DWORD_PTR addr);
    void* (*getBpList)();

    bool (*setHwBP)(DWORD_PTR addr, const char* type, size_t size);
    bool (*delHwBP)(DWORD_PTR addr);
    void* (*getHwBpList)();

    void (*step)();
    void (*stepOver)();
    void (*stepOut)();
    void (*run)();
    void (*stop)();

    CONTEXT* (*getCont)();
    bool (*chgReg)(const char* reg, DWORD_PTR value);
    //DWORD_PTR (*getReg)(const char* name);

    size_t(*memDump)(DWORD_PTR addr, void* output, size_t size);
    bool (*memEdit)(DWORD_PTR addr, void* input, size_t size);

    void* (*getMods)();
    void* (*getThreads)();

    void (*sendMessage)(const CDebugEvent* de);



};


#ifdef __cplusplus
    extern "C" {
#endif
    __declspec(dllexport) const DebugCAPI* get_debug_api();
#ifdef __cplusplus
}
#endif