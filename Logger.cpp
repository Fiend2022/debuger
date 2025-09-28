#include "Logger.hpp"
#include <iomanip>
#include <sstream>
#include <filesystem>


void Logger::init(const std::string& prog)
{
	std::stringstream ss;
	if (!(std::filesystem::exists(logDirName) && std::filesystem::is_directory(logDirName)))
		std::filesystem::create_directory(logDirName);
	
	progName = std::filesystem::path(prog).filename().string();
	ss << logDirName << "/log_" << getCurTimestamp() << "_" << progName << ".log";
	logFile.open(ss.str());
	if (logFile.is_open())
		write(Logger::INFO, "Logging started for " + progName);
	
}
void Logger::close()
{
	if (logFile.is_open())
	{
		write(Logger::INFO, "Logging stopped");
		logFile.close();
	}
	if (traceFile.is_open())
		traceFile.close();
}

std::tm Logger::getCurTM()
{
	auto now = std::chrono::system_clock::now();
	auto time_t = std::chrono::system_clock::to_time_t(now);
	std::tm tm;
	localtime_s(&tm, &time_t);
	return tm;
}

std::string Logger::getCurTime()
{
	std::tm tm = getCurTM();
	std::ostringstream oss;
	oss << std::put_time(&tm, "%H:%M:%S");
	return oss.str();
}

std::string Logger::getCurTimestamp()
{
	std::tm tm = getCurTM();
	std::ostringstream oss;
	oss << std::put_time(&tm, "%Y-%m-%d_%H-%M-%S");
	return oss.str();
}

void Logger::write(Level level, const std::string& msg)
{
	if (!logFile.is_open()) return;

	std::string levelStr;
	switch (level)
	{
		case Level::DEBUG:   levelStr = "DEBUG";   break;
		case Level::INFO:    levelStr = "INFO";    break;
		case Level::WARNING: levelStr = "WARNING"; break;
		case Level::ERR:   levelStr = "ERROR";   break;
	}

	logFile << "[" << getCurTime() << "] [" << levelStr << "] " << msg << "\n";
	logFile.flush();
}

void Logger::debug(const std::string& msg) { write(Level::DEBUG, msg); }
void Logger::info(const std::string& msg) { write(Level::INFO, msg); }
void Logger::warning(const std::string& msg) { write(Level::WARNING, msg); }
void Logger::error(const std::string& msg) { write(Level::ERR, msg); }