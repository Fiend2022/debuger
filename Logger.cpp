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

bool Logger::startTrace(DWORD_PTR start, DWORD_PTR end)
{
	std::stringstream ss;
	if (!(std::filesystem::exists(logDirName) && std::filesystem::is_directory(logDirName)))
		std::filesystem::create_directory(logDirName);
	ss << logDirName << "/trace_" << start << "-" << end << getCurTimestamp() << "_" << progName << ".log";
	traceFile.open(ss.str());
	if (traceFile.is_open())
	{
		traceFile << "# Instruction Trace\n";
		traceFile << "# Range: 0x" << std::hex << start << " - 0x" << end << "\n";
		traceFile << "# Time       EIP         Bytes              Mnemonic               Registers\n";
		traceFile << "#----------------------------------------------------------------------------------------\n";
		traceFile.flush();
	}
	else
		return false;
	return true;

}

void Logger::endTrace()
{
	if (traceFile.is_open())
		traceFile.close();
}

void Logger::trace(const std::string& instruction, const CONTEXT* ctx)
{
	if (!traceFile.is_open()) return;

	auto now = std::chrono::system_clock::now();
	auto time_t = std::chrono::system_clock::to_time_t(now);
	std::tm tm;
	localtime_s(&tm, &time_t);
	char timeBuf[16];
	strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", &tm);
	std::string eip, bytes, mnem;
	std::stringstream ss (instruction);
	ss >> eip >> bytes >> mnem;

#ifdef _WIN64
#define REG_FMT "%016llX"
#else
#define REG_FMT "%08X"
#endif

	// Первая строка: время, EIP, байты, мнемоника
	traceFile
		<< "[" << timeBuf << "] "
		<< "0x" << std::setfill('0') << std::setw(8) << std::hex << eip << ": "
		<< std::left << std::setw(16) << bytes << " "
		<< mnem << " ; ";

	// Регистры: первая пара — сразу после инструкции
	traceFile
		<< "EAX=" << REG_FMT << ctx->Eax
		<< " EBX=" << REG_FMT << ctx->Ebx;

	traceFile << "\n";  // переход на новую строку для оставшихся регистров

	// Вторая строка: оставшиеся регистры
	traceFile
		<< std::setw(55) << ""  // отступ (под временем + EIP)
		<< "ECX=" << REG_FMT << ctx->Ecx
		<< " EDX=" << REG_FMT << ctx->Edx << "\n"
		<< std::setw(55) << ""
		<< "ESI=" << REG_FMT << ctx->Esi
		<< " EDI=" << REG_FMT << ctx->Edi << "\n"
		<< std::setw(55) << ""
		<< "EBP=" << REG_FMT << ctx->Ebp
		<< " ESP=" << REG_FMT << ctx->Esp << "\n"
		<< std::setw(55) << ""
		<< "EFLAGS=" << REG_FMT << ctx->EFlags;

#undef REG_FMT

	// Разделитель
	traceFile << "\n";
	traceFile << "--------------------------------------------------------------------------------\n";
	traceFile.flush();
}