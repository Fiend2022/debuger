#pragma once
#include <Windows.h>
#include "msg.hpp"

class Debugger;
class DebugObserver;

extern "C" __declspec(dllexport) void initDebugAPI(Debugger* dbg);
extern "C" __declspec(dllexport) void* createDebugger();
extern "C" __declspec(dllexport) void destroyDebugger(void* dbg);

struct CDebugObserver
{
    void* userData;
    void (*update)(const CDebugEvent* de);
    char* plugName;
};

void notifyAllCObservers(const DebugEvent& ev);

struct CExportedSymbol
{
    char* name;
    DWORD_PTR address;
};

struct CModule
{
    DWORD_PTR baseAddress;
    size_t sizeOfSymbols;
    CExportedSymbol* symbols;
    char* name;

};

struct CActiveThread
{
    DWORD threadId;
    HANDLE hThread;
    bool isRunning;
};

struct CBreakPoint
{
    bool enable;
    BYTE saveByte;
    bool temp;
    DWORD_PTR address;
};
struct CHwBreakpoint {
    bool enable;
    DWORD_PTR address;
    int size; // 1, 2, 4, 8
};


struct PlugCmd
{
    char* name;
    char* help;
    const char* (*handler)(const char* args);
    CDebugEventType type;
};

struct DebugCAPI
{
    bool (*setBP)(DWORD_PTR addr);
    void (*delBP)(DWORD_PTR addr);
    CBreakPoint* (*getBpList)(size_t* count);


    bool (*setHwBP)(DWORD_PTR addr, const char* type, size_t size);
    bool (*delHwBP)(DWORD_PTR addr);
    CHwBreakpoint* (*getHwBpList)(size_t* count);

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

    CModule* (*getMods)(size_t* count);
    CActiveThread* (*getThreads)(size_t* count);

    void (*sendCommand)(const char* cmd);
    void (*attachObserver)(CDebugObserver* obs);
    void (*detachObserver)(CDebugObserver* obs);

    bool (*launchProg)(const char* prog);
    void (*dbgLoop)();

    void (*freeBreakList)(CBreakPoint*);
    void (*freeHwBreakList)(CHwBreakpoint*);
    void (*freeMods)(CModule*, size_t);
    void (*freeThreads)(CActiveThread*);

    void (*addNewCommand)(PlugCmd* cmd);
};


#ifdef __cplusplus
extern "C" {
#endif
    __declspec(dllexport) const DebugCAPI* get_debug_api();
#ifdef __cplusplus
}
#endif