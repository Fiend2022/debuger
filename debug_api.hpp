#pragma once
#include "debugger.hpp"


class DebugApi
{
private:
	static Debugger* debug;
	friend class Debugger;
public:
	static void bind(Debugger* dbg) { debug = dbg; }

	//Breakpoint functions;
	static bool dbg_setBreakPoint(DWORD_PTR addr);
	static void dbg_deleteBreakPoint(DWORD_PTR addr);
	static void dbg_setHwBreakPoint(DWORD_PTR addr, const std::string& typeStr, int size);
	static void dbg_deleteHwBreakPoint(DWORD_PTR addr);
	static void dbg_getBpList();
	static void dbg_getHwBpList();
	
	//Trace functions
	static void dbg_step();
	static void dbg_stepOver();
	static void dbg_stepOut();
	static void dbg_run();
	static void dbg_stop();

	//Registers functions
	static void dbg_changeRegister(const std::string& reg, DWORD_PTR value);
	static void dbg_getContext();
	static DWORD_PTR dbg_getReg(const std::string& reg);

	// Modules and Threads functions
	static void dbg_getModules();
	static void dbg_getThreads();

	// Memmory functions
	static void dbg_dump(DWORD_PTR addr, std::ostream& stream, size_t size);
	static void dbg_memoryEdit(DWORD_PTR addr, void* value, size_t size);
};