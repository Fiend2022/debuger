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
#else
	constexpr int regWidth = 8;
#endif

	auto fmtReg = [](uint32_t val, int width) -> std::string {
		std::ostringstream oss;
		oss << std::hex << std::uppercase << std::setfill('0') << std::setw(width) << val;
		return oss.str();
		};

	// --- Разбиваем instruction на части ---
	std::istringstream iss(instruction);
	std::string eip, bytes, mnem;
	iss >> eip >> bytes;  // первые два токена — адрес и байты
	getline(iss, mnem);  // всё остальное — мнемоника (с пробелами)

	// Удаляем пробелы в начале мнемоники
	mnem.erase(0, mnem.find_first_not_of(" \t"));

	// --- Формируем первую строку ---
	std::stringstream ss;
	ss << "[" << timeStream.str() << "]      " << eip << "         " << bytes
		<< "              " << mnem + "               ";
	size_t firstLineLen = ss.str().length();

	// --- Записываем первую строку ---
	traceFile << ss.str();

	// --- Регистры: EAX EBX сразу после инструкции ---
	traceFile
		<< "EAX=" << fmtReg(ctx->Eax, regWidth)
		<< " EBX=" << fmtReg(ctx->Ebx, regWidth);

	traceFile << "\n";

	// --- Остальные регистры с отступом ---
	// Отступ = длина первой строки - длина части до " ; "
	size_t indent = firstLineLen + 4;
	if (indent < 0) indent = 0;

	// Форматируем регистры
	std::string regLine1 = "ECX=" + fmtReg(ctx->Ecx, regWidth) + " EDX=" + fmtReg(ctx->Edx, regWidth);
	std::string regLine2 = "ESI=" + fmtReg(ctx->Esi, regWidth) + " EDI=" + fmtReg(ctx->Edi, regWidth);
	std::string regLine3 = "EBP=" + fmtReg(ctx->Ebp, regWidth) + " ESP=" + fmtReg(ctx->Esp, regWidth);
	std::string regLine4 = "EFLAGS=" + fmtReg(ctx->EFlags, regWidth);

	// Длина самой длинной строки регистров
	//size_t maxRegLen = std::max({ regLine1.length(), regLine2.length(), regLine3.length(), regLine4.length() });

	// Выравнивание по левому краю с отступом
	traceFile
		<< std::setw(indent) << ""  // отступ
		<< regLine1 << "\n"
		<< std::setw(indent) << ""
		<< regLine2 << "\n"
		<< std::setw(indent) << ""
		<< regLine3 << "\n"
		<< std::setw(indent) << ""
		<< regLine4;

	// --- Разделитель ---
	traceFile << "\n--------------------------------------------------------------------------------\n";
	traceFile.flush();
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