#include "debugger.hpp"
#include <iostream>
#include <filesystem>
#include <vector>
#include <iomanip>
#include <stdexcept>
#include <sstream>
#include <functional>
#include <winnt.h>
#include <Windows.h>
#include <psapi.h>
#include <unordered_set>
#include "msg.hpp"

namespace fs = std::filesystem;

template<typename T>
std::string to_hex(T value)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(sizeof(T) * 2) << value;
    return ss.str();
}

void setDr7Bit(DWORD_PTR& dr7, int index, int rw, int len)
{
    int enableShift = index * 2;      // Lx: 0,2,4,6
    int rwShift = 16 + index * 4;     // RWx
    int lenShift = 18 + index * 4;    // lenx

    dr7 |= (1 << enableShift);           // Lx = 1
    dr7 &= ~ (3 << rwShift);              // обнуляем RWx
    dr7 &= ~ (3 << lenShift);             // обнуляем lenx
    dr7 |= (rw << rwShift);              // ставим RWx
    dr7 |= (len << lenShift);            // ставим lenx
}

bool Debugger::addHardwareBreakpoint(DWORD_PTR addr, const std::string& typeStr, int size)
{

    int idx = -1;
    for (int i = 0; i < 4; ++i)
    {
        if (!hwBps[i].active)
        {
            idx = i;
            break;
        }
    }
    if (idx == -1)
    {

        return false;
    }

    int rw = 0, len = 0;
    if (typeStr == "write")
        rw = 1;
    else if (typeStr == "access")
        rw = 3;

    else
    {
        //logger.warning("Invalid type. Use 'write' or 'access'");
        return false;
    }

    switch (size) {
    case 1: len = 0; break;
    case 2: len = 1; break;
    case 4: len = 3; break;
#ifdef _WIN64
    case 8: len = 2; break;
#else
        //default: logger.warning("Invalid size"); return false;
#endif
    }

    // Устанавливаем адрес
    switch (idx)
    {
    case 0: cont->Dr0 = addr; break;
    case 1: cont->Dr1 = addr; break;
    case 2: cont->Dr2 = addr; break;
    case 3: cont->Dr3 = addr; break;
    }

    setDr7Bit(cont->Dr7, idx, rw, len);

    cont->Dr7 &= ~(1 << 13);



    hwBps[idx] = { true, addr, size };
    std::stringstream ss;
    ss << "HWBP set at DR" << idx << " (0x" << std::hex << addr
        << ") type=" << typeStr << ", size=" << size;
    //logger.info(ss.str());
    return true;
}

int Debugger::getHardwareBreakpointIndexFromDr6(DWORD dr6)
{
    for (int i = 0; i < 4; ++i)
        if (dr6 & (1 << i)) return i;
    return -1;
}

bool Debugger::delHardwareBreakpoint(DWORD_PTR addr)
{
    auto it = std::find_if(std::begin(hwBps), std::end(hwBps),
        [addr](const HwBreakpoint& bp) { return bp.active && bp.address == addr; });

    if (it == std::end(hwBps))
        return false;

    int index = it - hwBps;

    if (index == 0) cont->Dr0 = 0;
    else if (index == 1) cont->Dr0 = 0;
    else if (index == 2) cont->Dr0 = 0;
    else if (index == 3) cont->Dr0 = 0;

    uint32_t mask = ~(0b1111 << (index * 2));
    mask &= ~(0b11 << (16 + index * 2));
    cont->Dr7 &= mask;
    return true;
}

bool Debugger::createDebugProc(const std::string& prog)
{
    if (!fs::exists(prog))
        return false;


    STARTUPINFOA startupInfo;
    PROCESS_INFORMATION procInfo;
    bool ret;

    RtlZeroMemory(&startupInfo, sizeof(startupInfo));
    RtlZeroMemory(&procInfo, sizeof(procInfo));
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_SHOWNORMAL;

    ret = CreateProcessA(prog.c_str(),
        NULL,
        NULL,
        NULL,
        TRUE,
        DEBUG_ONLY_THIS_PROCESS,
        NULL,
        NULL,
        &startupInfo,
        &procInfo);

    if (ret)
    {
        hProcess = procInfo.hProcess;
        CloseHandle(procInfo.hThread);
        active = true;
        state = DebugState::RUN;
    }

    return ret;

}

bool Debugger::setBreakPoint(DWORD_PTR addr, bool temp)
{
    auto it = breakMap.find(addr);
    if (it == breakMap.end())
    {
        BYTE saveByte;
        if (!ReadProcessMemory(hProcess, (PVOID)addr, &saveByte, 1, NULL))
            return false;
        if (!WriteProcessMemory(hProcess, (PVOID)addr, "\xCC", 1, NULL))
            return false;
        breakMap[addr] = { BreakState::enable, saveByte, temp, addr };
    }
    return true;
}

void Debugger::deleteBreakPoint(DWORD_PTR addr)
{
    auto it = breakMap.find(addr);
    if (it != breakMap.end())
    {
        breakMap[addr].state = BreakState::disable;
        WriteProcessMemory(hProcess, (PVOID)addr, &breakMap[addr].saveByte, 1, NULL);
        breakMap.erase(it);
    }
    else
    {
        std::stringstream ss;
        ss << "No breakpoint found at 0x" << std::hex << addr;
    }
}

std::vector<BYTE> Debugger::getDumpMemory(DWORD_PTR addr, size_t size = 128)
{
    std::vector<BYTE> buffer(size, 0);
    if (!ReadProcessMemory(hProcess, (PVOID)addr, buffer.data(), size, NULL)) {
        DWORD error = GetLastError();
        std::string errorMsg = "FAILED READ MEMORY: Error code " + std::to_string(error);
        throw std::runtime_error(errorMsg);
    }
    return buffer;
}

void Debugger::changeMemory(DWORD_PTR addr, void* value, size_t size)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, (PVOID)addr, &mbi, sizeof(mbi)) == 0)
    {
        DWORD error = GetLastError();
        std::string errorMsg = "FAILED WRITE MEMORY: Error code " + std::to_string(error);
        throw std::runtime_error(errorMsg);
    }

    bool isWritable = false;
    switch (mbi.Protect)
    {
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
        isWritable = true;
        break;
    default:
        isWritable = false;
    }

    if (!isWritable)
        throw std::runtime_error("Cannot write to address 0x" + to_hex(addr) +
            ": protection = 0x" + to_hex(mbi.Protect));


    if (!WriteProcessMemory(hProcess, (PVOID)addr, value, size, nullptr))
    {
        DWORD error = GetLastError();
        std::string errorMsg = "FAILED WRITE MEMORY: Error code " + std::to_string(error);
        throw std::runtime_error(errorMsg);
    }
}

bool Debugger::regEdit(const std::string& reg, CONTEXT& context, DWORD_PTR value)
{
#ifdef _WIN64
    // 64-битные регистры и их части
    static const std::unordered_map<std::string, std::function<void(CONTEXT&, DWORD_PTR)>> regMap = {
        // Полные 64-битные регистры
        {"rax", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rax = val; }},
        {"rbx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rbx = val; }},
        {"rcx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rcx = val; }},
        {"rdx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rdx = val; }},
        {"rdi", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rdi = val; }},
        {"rsi", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rsi = val; }},
        {"rbp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rbp = val; }},
        {"rsp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rsp = val; }},
        {"rip", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rip = val; }},
        {"rflags", [](CONTEXT& ctx, DWORD_PTR val) { ctx.EFlags = static_cast<DWORD>(val); }},

        // Дополнительные 64-битные регистры
        {"r8",  [](CONTEXT& ctx, DWORD_PTR val) { ctx.R8 = val; }},
        {"r9",  [](CONTEXT& ctx, DWORD_PTR val) { ctx.R9 = val; }},
        {"r10", [](CONTEXT& ctx, DWORD_PTR val) { ctx.R10 = val; }},
        {"r11", [](CONTEXT& ctx, DWORD_PTR val) { ctx.R11 = val; }},
        {"r12", [](CONTEXT& ctx, DWORD_PTR val) { ctx.R12 = val; }},
        {"r13", [](CONTEXT& ctx, DWORD_PTR val) { ctx.R13 = val; }},
        {"r14", [](CONTEXT& ctx, DWORD_PTR val) { ctx.R14 = val; }},
        {"r15", [](CONTEXT& ctx, DWORD_PTR val) { ctx.R15 = val; }},

        // Младшие 32 бита (например, eax = младшие 32 бита rax)
        {"eax", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rax = (ctx.Rax & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},
        {"ebx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rbx = (ctx.Rbx & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},
        {"ecx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rcx = (ctx.Rcx & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},
        {"edx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rdx = (ctx.Rdx & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},
        {"edi", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rdi = (ctx.Rdi & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},
        {"esi", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rsi = (ctx.Rsi & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},
        {"ebp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rbp = (ctx.Rbp & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},
        {"esp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rsp = (ctx.Rsp & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},
        {"eip", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rip = (ctx.Rip & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF); }},

        // Младшие 16 бит (например, ax = младшие 16 бит rax)
        {"ax", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rax = (ctx.Rax & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},
        {"bx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rbx = (ctx.Rbx & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},
        {"cx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rcx = (ctx.Rcx & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},
        {"dx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rdx = (ctx.Rdx & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},
        {"di", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rdi = (ctx.Rdi & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},
        {"si", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rsi = (ctx.Rsi & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},
        {"bp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rbp = (ctx.Rbp & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},
        {"sp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rsp = (ctx.Rsp & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},
        {"ip", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rip = (ctx.Rip & 0xFFFFFFFFFFFF0000ULL) | (val & 0xFFFF); }},

        // Младшие 8 бит (например, al = младшие 8 бит rax)
        {"al", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rax = (ctx.Rax & 0xFFFFFFFFFFFFFF00ULL) | (val & 0xFF); }},
        {"ah", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rax = (ctx.Rax & 0xFFFFFFFFFFFF00FFULL) | ((val & 0xFF) << 8); }},
        {"bl", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rbx = (ctx.Rbx & 0xFFFFFFFFFFFFFF00ULL) | (val & 0xFF); }},
        {"bh", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rbx = (ctx.Rbx & 0xFFFFFFFFFFFF00FFULL) | ((val & 0xFF) << 8); }},
        {"cl", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rcx = (ctx.Rcx & 0xFFFFFFFFFFFFFF00ULL) | (val & 0xFF); }},
        {"ch", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rcx = (ctx.Rcx & 0xFFFFFFFFFFFF00FFULL) | ((val & 0xFF) << 8); }},
        {"dl", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rdx = (ctx.Rdx & 0xFFFFFFFFFFFFFF00ULL) | (val & 0xFF); }},
        {"dh", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Rdx = (ctx.Rdx & 0xFFFFFFFFFFFF00FFULL) | ((val & 0xFF) << 8); }},
    };
#else
    // 32-битные регистры и их части
    static const std::unordered_map<std::string, std::function<void(CONTEXT&, DWORD_PTR)>> regMap = {
        {"eax", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Eax = static_cast<DWORD>(val); }},
        {"ebx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ebx = static_cast<DWORD>(val); }},
        {"ecx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ecx = static_cast<DWORD>(val); }},
        {"edx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Edx = static_cast<DWORD>(val); }},
        {"edi", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Edi = static_cast<DWORD>(val); }},
        {"esi", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Esi = static_cast<DWORD>(val); }},
        {"ebp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ebp = static_cast<DWORD>(val); }},
        {"esp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Esp = static_cast<DWORD>(val); }},
        {"eip", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Eip = static_cast<DWORD>(val); }},
        {"eflags", [](CONTEXT& ctx, DWORD_PTR val) { ctx.EFlags = static_cast<DWORD>(val); }},

        // Подрегистры: 16 бит
        {"ax", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Eax = (ctx.Eax & 0xFFFF0000) | (val & 0xFFFF); }},
        {"bx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ebx = (ctx.Ebx & 0xFFFF0000) | (val & 0xFFFF); }},
        {"cx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ecx = (ctx.Ecx & 0xFFFF0000) | (val & 0xFFFF); }},
        {"dx", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Edx = (ctx.Edx & 0xFFFF0000) | (val & 0xFFFF); }},
        {"di", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Edi = (ctx.Edi & 0xFFFF0000) | (val & 0xFFFF); }},
        {"si", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Esi = (ctx.Esi & 0xFFFF0000) | (val & 0xFFFF); }},
        {"bp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ebp = (ctx.Ebp & 0xFFFF0000) | (val & 0xFFFF); }},
        {"sp", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Esp = (ctx.Esp & 0xFFFF0000) | (val & 0xFFFF); }},
        {"ip", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Eip = (ctx.Eip & 0xFFFF0000) | (val & 0xFFFF); }},

        // Подрегистры: 8 бит
        {"al", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Eax = (ctx.Eax & 0xFFFFFF00) | (val & 0xFF); }},
        {"ah", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Eax = (ctx.Eax & 0xFFFF00FF) | ((val & 0xFF) << 8); }},
        {"bl", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ebx = (ctx.Ebx & 0xFFFFFF00) | (val & 0xFF); }},
        {"bh", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ebx = (ctx.Ebx & 0xFFFF00FF) | ((val & 0xFF) << 8); }},
        {"cl", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ecx = (ctx.Ecx & 0xFFFFFF00) | (val & 0xFF); }},
        {"ch", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Ecx = (ctx.Ecx & 0xFFFF00FF) | ((val & 0xFF) << 8); }},
        {"dl", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Edx = (ctx.Edx & 0xFFFFFF00) | (val & 0xFF); }},
        {"dh", [](CONTEXT& ctx, DWORD_PTR val) { ctx.Edx = (ctx.Edx & 0xFFFF00FF) | ((val & 0xFF) << 8); }},
    };
#endif
    auto it = regMap.find(reg);
    if (it != regMap.end())
    {
        it->second(context, value);
        return true;
    }
    else
        return false;

}


std::vector<Debugger::ExportedSymbol> Debugger::loadSyms(const std::vector<std::pair<std::string, DWORD_PTR>>& expSyms)
{
    std::vector<ExportedSymbol> syms;
    for (auto& sym : expSyms)
    {
        syms.push_back({ sym.first, sym.second });
        fullExport.push_back({ sym.first, sym.second });
    }
    return syms;
}


std::vector<DisasmLine> Debugger::disasSection(IMAGE_SECTION_HEADER* sec)
{
    DWORD_PTR addr = sec->VirtualAddress + exeBaseAddress;
    std::vector<DisasmLine> text;
    while (addr - exeBaseAddress < sec->VirtualAddress + sec->Misc.VirtualSize)
    {
        std::vector<uint8_t> buf(16);
        std::string asmBuf(128, '\0');
        std::string hexBuf(128, '\0');
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProcess, (LPCVOID)addr, buf.data(), 16, &bytesRead) || bytesRead == 0)
        {
            break;
        }
        size_t len = disas.DisasInst(buf.data(), bytesRead, addr, asmBuf, hexBuf);
        text.push_back({ addr, hexBuf, asmBuf });
        addr += len;
    }
    return text;
}

std::pair<std::vector<DisasmLine>, std::vector<DataSection>> Debugger::getAllSections()
{
    std::vector<DisasmLine> codeSections;
    std::vector<DataSection> dataSections;

    auto secs = prog->getSections();
    for (auto sec : secs)
    {
        if ((sec.Characteristics & IMAGE_SCN_CNT_CODE) && (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE))
        {
            auto disasCode = disasSection(&sec);
            std::copy(disasCode.begin(), disasCode.end(), std::back_inserter(codeSections));
        }
        else if ((sec.Characteristics & (IMAGE_SCN_CNT_INITIALIZED_DATA |
            IMAGE_SCN_CNT_UNINITIALIZED_DATA)) &&
            !(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE))
        {
            auto dataSec = getDataSection(&sec);
            dataSections.push_back({ std::string((const char*)sec.Name), dataSec });
        }
    }
    return { codeSections, dataSections };
}
std::vector<DataLine> Debugger::getDataSection(IMAGE_SECTION_HEADER* sec)
{
    DWORD_PTR addr = sec->VirtualAddress + exeBaseAddress;
    std::vector<DataLine> text;

    while (addr < sec->VirtualAddress + exeBaseAddress + sec->Misc.VirtualSize)
    {
        std::vector<BYTE> buf(16);
        SIZE_T bytesRead;

        if (!ReadProcessMemory(hProcess, (LPCVOID)addr, buf.data(), 16, &bytesRead)
            || bytesRead == 0)
            break;




        std::string ascii;
        for (SIZE_T i = 0; i < bytesRead; ++i)
        {
            char c = buf[i];
            ascii += (c >= 32 && c < 127) ? c : '.';
        }

        DataLine tmp({ addr, buf, ascii });
        text.push_back(tmp);
        addr += 16;
    }
    return text;
}

std::vector<StackLine> Debugger::getStack(const int numEntries = 64)
{
    std::vector<StackLine> stackLines;
#if defined(_WIN64)
    DWORD_PTR esp = cont->Rsp;
#else
    DWORD_PTR esp = cont->Esp;
#endif

    stackLines.clear();

    for (int i = 0; i < numEntries; ++i)
    {
        DWORD_PTR addr = esp + i * sizeof(void*);
        DWORD_PTR value = 0;
        SIZE_T bytesRead;

        if (ReadProcessMemory(hProcess, (LPCVOID)addr, &value, sizeof(value), &bytesRead))
        {
            StackLine line;
            line.address = addr;
            line.value = value;
            line.label = "";

            if (i == 0)
                line.label = "<return address>";

            else if (i == 1)
                line.label = "<saved ebp>";

            stackLines.push_back(line);
        }
        else {
            // Ошибка чтения
            StackLine line;
            line.address = addr;
            line.value = 0;
            line.label = "<memory access error>";
            stackLines.push_back(line);
            break;
        }
    }

    return stackLines;
}

void Debugger::stepOut()
{
    DWORD_PTR retAddr = getRetAddr();
    setBreakPoint(retAddr, true);
    state = RUN;
}

void Debugger::stepOver()
{

    DWORD_PTR curIP = getIP();
    DWORD_PTR retAddr = curIP;
    std::vector<uint8_t> buf(16);
    std::string asmBuf(128, '\0');
    std::string hexBuf(128, '\0');
    SIZE_T bytesRead;
    if (ReadProcessMemory(hProcess, (LPCVOID)retAddr, buf.data(), 16, &bytesRead) || bytesRead == 0)
    {
        size_t len = disas.DisasInst(buf.data(), bytesRead, retAddr, asmBuf, hexBuf);
        if (asmBuf.find("call") != std::string::npos)
        {
            setBreakPoint(curIP + len, true);
            state = RUN;
        }
        else
            state = STEP;
    }

}

DWORD_PTR Debugger::getRetAddr() {


#if defined(_WIN64)
    DWORD_PTR stackPointer = cont->Rsp;
#else
    DWORD_PTR stackPointer = cont->Esp;
#endif

    DWORD_PTR retAddr;
    SIZE_T bytesRead;

    if (ReadProcessMemory(hProcess, (LPCVOID)stackPointer, &retAddr, sizeof(retAddr), &bytesRead) &&
        bytesRead == sizeof(retAddr)) {
        return retAddr;
    }
    return 0;
}

void Debugger::disableBreakPoint(DWORD_PTR addr)
{
    auto it = breakMap.find(addr);
    if (it != breakMap.end())
    {
        breakMap[addr].state = BreakState::disable;
        WriteProcessMemory(hProcess, (PVOID)addr, &breakMap[addr].saveByte, 1, NULL);
    }
}

size_t Debugger::disasmDebugProc(DWORD_PTR addr, std::ostream& stream, size_t instCount)
{
    size_t size = 15 * instCount;
    std::vector<BYTE> buf(size);
    size_t offset = 0;

    if (!ReadProcessMemory(hProcess, (LPCVOID)addr, buf.data(), size, NULL))
    {
        stream << "Failed to read memory: " << GetLastError() << " on address: " << addr;
        return 0;
    }

    for (size_t i = 0; i < instCount; ++i)
    {
        std::string asmBuf(128, '\0');
        std::string hexBuf(128, '\0');
        size_t len = this->disas.DisasInst(buf.data() + offset, size - offset, (size_t)addr + offset, asmBuf, hexBuf);
        if (!len) {
            break;
        }
        stream << std::hex << (DWORD_PTR)addr + offset << ": " << hexBuf << " " << asmBuf << "\n";
        offset += len;
    }

    return offset;
}

bool Debugger::launch(const std::string& prog)
{
    return createDebugProc(prog);
}


