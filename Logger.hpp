#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include <Windows.h>
#include "Observer.hpp"

class Logger : public Observer
{
private:
	enum Level {DEBUG, INFO, TRACE, WARNING, ERR};
	void write(const Level lvl, const std::string& msg);
	std::string getCurTime();
	std::string getCurTimestamp();
	std::string progName;

	std::ofstream logFile;
	std::ofstream traceFile;

	std::string logDirName = "G:\\debuger\\logs";
	std::tm getCurTM();

public:
	void init(const std::string& progName);
	void close();
	void debug(const std::string& msg);
	void info(const std::string& msg);
	void warning(const std::string& msg);
	void error(const std::string& msg);
	bool startTrace(DWORD_PTR start, DWORD_PTR end);
	void endTrace();
	void trace(const std::string& instruction, const CONTEXT* ctx);
	void update(const DebugEvent& de) override;

};