#include "Logger.hpp"
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <algorithm>

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
		traceFile << "# Time\t\tEIP\t\tBytes\t\t\t\Mnemonic\t\t\tRegisters\n";
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


void Logger::update(const DebugEvent& ev)
{
	switch (ev.type)
	{
		
	case DebugEvent::DbgWarning:
		warning(ev.message);
		break;
	case DebugEvent::DbgError:
		error(ev.message);
		break;
	case DebugEvent::BreakpointSetup:
	case DebugEvent::ModuleLoad:
	case DebugEvent::ModuleUnload:
	case DebugEvent::CreateThread:
	case DebugEvent::ExitThread:
	case DebugEvent::HardBreakpointSetup:
	case DebugEvent::Reg:
	case DebugEvent::ProcessExit:
	case DebugEvent::Run:

		info(ev.message);
		break;

	case DebugEvent::SetupTrace:
		startTrace(ev.startTrace, ev.endTrace);
		break;

	case DebugEvent::TraceStep:
		trace(ev.message, &ev.context);
		break;
	case DebugEvent::CreateProc:
		init(ev.prog);
		break;
	default:
		break;
	}
}

void Logger::trace(const std::string& instruction, const CONTEXT* ctx)
{
	if (!traceFile.is_open()) return;

	// --- Время ---
	auto now = std::chrono::system_clock::now();
	auto time_t = std::chrono::system_clock::to_time_t(now);
	std::tm tm;
	localtime_s(&tm, &time_t);

	std::ostringstream timeStream;
	timeStream << std::put_time(&tm, "%H:%M:%S");

#ifdef _WIN64
	constexpr int regWidth = 16;
	auto getRax = [](const CONTEXT* c) { return c->Rax; };
	auto getRbx = [](const CONTEXT* c) { return c->Rbx; };
	auto getRcx = [](const CONTEXT* c) { return c->Rcx; };
	auto getRdx = [](const CONTEXT* c) { return c->Rdx; };
	auto getRsi = [](const CONTEXT* c) { return c->Rsi; };
	auto getRdi = [](const CONTEXT* c) { return c->Rdi; };
	auto getRbp = [](const CONTEXT* c) { return c->Rbp; };
	auto getRsp = [](const CONTEXT* c) { return c->Rsp; };
	auto getEFlags = [](const CONTEXT* c) { return c->EFlags; };
#else
	constexpr int regWidth = 8;
	auto getRax = [](const CONTEXT* c) { return static_cast<uint64_t>(c->Eax); };
	auto getRbx = [](const CONTEXT* c) { return static_cast<uint64_t>(c->Ebx); };
	auto getRcx = [](const CONTEXT* c) { return static_cast<uint64_t>(c->Ecx); };
	auto getRdx = [](const CONTEXT* c) { return static_cast<uint64_t>(c->Edx); };
	auto getRsi = [](const CONTEXT* c) { return static_cast<uint64_t>(c->Esi); };
	auto getRdi = [](const CONTEXT* c) { return static_cast<uint64_t>(c->Edi); };
	auto getRbp = [](const CONTEXT* c) { return static_cast<uint64_t>(c->Ebp); };
	auto getRsp = [](const CONTEXT* c) { return static_cast<uint64_t>(c->Esp); };
	auto getEFlags = [](const CONTEXT* c) { return static_cast<uint64_t>(c->EFlags); };
#endif

	// Форматирование регистра как HEX строки
	auto fmtReg = [regWidth](uint64_t val) -> std::string {
		std::ostringstream oss;
		oss << std::hex << std::uppercase << std::setfill('0') << std::setw(regWidth) << val;
		return oss.str();
		};

	// --- Разбиваем instruction на части ---
	std::istringstream iss(instruction);
	std::string eip, bytes, mnem;
	iss >> eip >> bytes;
	std::getline(iss, mnem);
	mnem.erase(0, mnem.find_first_not_of(" \t"));

	// --- Первая строка: инструкция ---
	std::ostringstream ss;
	ss << "[" << timeStream.str() << "]      " << eip << "         " << bytes
		<< "              " << mnem << "               ";
	std::string firstLine = ss.str();
	traceFile << firstLine;

	// --- Регистры: RAX, RBX сразу после инструкции ---
	traceFile
		<< "RAX=" << fmtReg(getRax(ctx))
		<< " RBX=" << fmtReg(getRbx(ctx));

	traceFile << "\n";

	// --- Остальные регистры с отступом ---
	size_t indent = firstLine.length();
	if (indent > 1000) indent = 40; // защита от переполнения

	auto writeIndented = [&](const std::string& line) {
		traceFile << std::string(indent, ' ') << line << "\n";
		};

	writeIndented("RCX=" + fmtReg(getRcx(ctx)) + " RDX=" + fmtReg(getRdx(ctx)));
	writeIndented("RSI=" + fmtReg(getRsi(ctx)) + " RDI=" + fmtReg(getRdi(ctx)));
	writeIndented("RBP=" + fmtReg(getRbp(ctx)) + " RSP=" + fmtReg(getRsp(ctx)));
	writeIndented("RFLAGS=" + fmtReg(getEFlags(ctx)));

	// --- Разделитель ---
	traceFile << "\n--------------------------------------------------------------------------------\n";
	traceFile.flush();
}