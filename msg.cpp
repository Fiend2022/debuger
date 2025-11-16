#include "msg.hpp"




// === Вспомогательные функции ===
static char* strDup(const std::string& s)
{
    if (s.empty()) return nullptr;
    char* dup = new char[s.length() + 1];
    strcpy_s(dup, s.length() + 1, s.c_str());
    return dup;
}

char* strDupC(const char* s) {
    if (!s) return nullptr;
    size_t len = strlen(s) + 1;
    char* dup = new char[len];
    strcpy_s(dup, len, s);
    return dup;
}

// === Инициализация ===
void initCDisasmLine(CDisasmLine* line)
{
    line->address = 0;
    line->bytes = nullptr;
    line->instruction = nullptr;
    line->hasBreakpoint = false;
}

void initCDataLine(CDataLine* line)
{
    line->address = 0;
    line->bytes = nullptr;
    line->bytesSize = 0;
    line->ascii = nullptr;
}

void initCDataSection(CDataSection* section) {
    section->secName = nullptr;
    section->data = nullptr;
    section->dataCount = 0;
}

void initCStackLine(CStackLine* line) {
    line->address = 0;
    line->value = 0;
    line->label = nullptr;
}

void initCDebugEvent(CDebugEvent* event) {
    event->type = CAPI__Nope;
    event->address = 0;
    event->message = nullptr;
    event->disasmCode = nullptr;
    event->disasmCodeCount = 0;
    event->data = nullptr;
    event->dataCount = 0;
    event->stackData = nullptr;
    event->stackDataCount = 0;
    ZeroMemory(&event->context, sizeof(CONTEXT));
    event->startTrace = 0;
    event->endTrace = 0;
    event->prog = nullptr;
}

// === Освобождение ===
void freeCDisasmLine(CDisasmLine* line) {
    delete[] line->bytes;
    delete[] line->instruction;
    initCDisasmLine(line); // обнуляем поля
}

void freeCDataLine(CDataLine* line) {
    delete[] line->bytes;
    delete[] line->ascii;
    initCDataLine(line);
}

void freeCDataSection(CDataSection* section) {
    if (section->data) {
        for (size_t i = 0; i < section->dataCount; ++i) {
            freeCDataLine(&section->data[i]);
        }
        delete[] section->data;
    }
    delete[] section->secName;
    initCDataSection(section);
}

void freeCStackLine(CStackLine* line) {
    delete[] line->label;
    initCStackLine(line);
}

void freeCDebugEvent(CDebugEvent* event) {
    if (event->disasmCode) {
        for (size_t i = 0; i < event->disasmCodeCount; ++i) {
            freeCDisasmLine(&event->disasmCode[i]);
        }
        delete[] event->disasmCode;
    }
    if (event->data) {
        for (size_t i = 0; i < event->dataCount; ++i) {
            freeCDataSection(&event->data[i]);
        }
        delete[] event->data;
    }
    if (event->stackData) {
        for (size_t i = 0; i < event->stackDataCount; ++i) {
            freeCStackLine(&event->stackData[i]);
        }
        delete[] event->stackData;
    }
    delete[] event->message;
    delete[] event->prog;
    initCDebugEvent(event);
}

// === Копирование ===
void copyCDisasmLine(CDisasmLine* dst, const CDisasmLine* src)
{
    freeCDisasmLine(dst);
    dst->address = src->address;
    dst->bytes = strDupC(src->bytes);
    dst->instruction = strDupC(src->instruction);
    dst->hasBreakpoint = src->hasBreakpoint;
}

void copyCDataLine(CDataLine* dst, const CDataLine* src)
{
    freeCDataLine(dst);
    dst->address = src->address;
    dst->bytesSize = src->bytesSize;
    if (src->bytes && src->bytesSize > 0) {
        dst->bytes = new BYTE[src->bytesSize];
        memcpy(dst->bytes, src->bytes, src->bytesSize);
    }
    else {
        dst->bytes = nullptr;
    }
    dst->ascii = strDupC(src->ascii);
}

void copyCDataSection(CDataSection* dst, const CDataSection* src) {
    freeCDataSection(dst);
    dst->secName = strDupC(src->secName);
    dst->dataCount = src->dataCount;
    if (src->data && src->dataCount > 0) {
        dst->data = new CDataLine[src->dataCount];
        for (size_t i = 0; i < src->dataCount; ++i) {
            copyCDataLine(&dst->data[i], &src->data[i]);
        }
    }
    else {
        dst->data = nullptr;
    }
}

void copyCStackLine(CStackLine* dst, const CStackLine* src) {
    freeCStackLine(dst);
    dst->address = src->address;
    dst->value = src->value;
    dst->label = strDupC(src->label);
}

void copyCDebugEvent(CDebugEvent* dst, const CDebugEvent* src) {
    freeCDebugEvent(dst);
    dst->type = src->type;
    dst->address = src->address;
    dst->message = strDupC(src->message);
    dst->context = src->context;
    dst->startTrace = src->startTrace;
    dst->endTrace = src->endTrace;
    dst->prog = strDupC(src->prog);

    // disasmCode
    dst->disasmCodeCount = src->disasmCodeCount;
    if (src->disasmCode && src->disasmCodeCount > 0)
    {
        dst->disasmCode = new CDisasmLine[src->disasmCodeCount];
        for (size_t i = 0; i < src->disasmCodeCount; ++i) 
            copyCDisasmLine(&dst->disasmCode[i], &src->disasmCode[i]);
        
    }
    else
        dst->disasmCode = nullptr;
    

    // data
    dst->dataCount = src->dataCount;
    if (src->data && src->dataCount > 0)
    {
        dst->data = new CDataSection[src->dataCount];
        for (size_t i = 0; i < src->dataCount; ++i)
            copyCDataSection(&dst->data[i], &src->data[i]);
        
    }
    else
        dst->data = nullptr;
    

    // stackData
    dst->stackDataCount = src->stackDataCount;
    if (src->stackData && src->stackDataCount > 0)
    {
        dst->stackData = new CStackLine[src->stackDataCount];
        for (size_t i = 0; i < src->stackDataCount; ++i) 
            copyCStackLine(&dst->stackData[i], &src->stackData[i]);
        
    }
    else
        dst->stackData = nullptr;
    
}